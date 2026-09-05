const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;

const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;
const Address = @import("Address.zig");
const socks5 = @import("socks5.zig");
const Server = @import("Server.zig");
const Local = @import("Local.zig");
const tunnel = @import("tunnel.zig");

fn runEchoServerOnce(io: Io, server: *Io.net.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);

    var r_buf: [1024]u8 = undefined;
    var w_buf: [1024]u8 = undefined;
    var reader = stream.reader(io, &r_buf);
    var writer = stream.writer(io, &w_buf);

    _ = tunnel.pump(&reader.interface, &writer.interface) catch {};
}

fn runServerOnce(io: Io, listener: *Io.net.Server, server: *const Server) !void {
    const stream = try listener.accept(io);
    server.handleClientTcp(io, stream);
}

fn runLocalOnce(io: Io, listener: *Io.net.Server, local: *const Local) !void {
    const stream = try listener.accept(io);
    local.handleClientTcp(io, stream);
}

fn runUdpEchoServerOnce(io: Io, sock: *const Io.net.Socket) !void {
    var buf: [2048]u8 = undefined;
    const msg = try sock.receive(io, &buf);
    try sock.send(io, &msg.from, msg.data);
}

fn runServerUdpOnce(io: Io, server: *const Server, udp_sock: *const Io.net.Socket, fwd_sock: *const Io.net.Socket) !void {
    try server.handleUdpOnce(io, udp_sock, fwd_sock);
}

fn runLocalUdpOnce(io: Io, local: *const Local, inbound_sock: *const Io.net.Socket, outbound_sock: *const Io.net.Socket) !void {
    try local.handleUdpOnce(io, inbound_sock, outbound_sock);
}

fn runTcpClientOnce(io: Io, local_ip: IpAddress, echo_port: u16, test_data: []const u8) !void {
    const client_stream = try local_ip.connect(io, .{ .mode = .stream });
    defer client_stream.close(io);

    var client_r_buf: [1024]u8 = undefined;
    var client_w_buf: [1024]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_r_buf);
    var client_writer = client_stream.writer(io, &client_w_buf);

    // SOCKS5 Greeting: [VER 0x05, NMETHODS 1, METHOD 0x00]
    try client_writer.interface.writeAll(&[_]u8{ 0x05, 0x01, 0x00 });
    try client_writer.interface.flush();

    var greeting_resp: [2]u8 = undefined;
    try client_reader.interface.readSliceAll(&greeting_resp);
    try std.testing.expectEqual(@as(u8, 0x05), greeting_resp[0]);
    try std.testing.expectEqual(@as(u8, 0x00), greeting_resp[1]);

    // Send SOCKS5 CONNECT request to Echo Server: [VER 0x05, CMD 0x01, RSV 0x00, ATYP 0x01, 127.0.0.1, echo_port]
    var connect_req: [10]u8 = undefined;
    connect_req[0] = 0x05;
    connect_req[1] = 0x01; // CONNECT
    connect_req[2] = 0x00; // RSV
    connect_req[3] = 0x01; // IPv4
    connect_req[4] = 127;
    connect_req[5] = 0;
    connect_req[6] = 0;
    connect_req[7] = 1;
    mem.writeInt(u16, connect_req[8..10], echo_port, .big);

    try client_writer.interface.writeAll(&connect_req);
    try client_writer.interface.flush();

    // Read SOCKS5 CONNECT reply
    var connect_resp: [10]u8 = undefined;
    try client_reader.interface.readSliceAll(&connect_resp);
    try std.testing.expectEqual(@as(u8, 0x05), connect_resp[0]);
    try std.testing.expectEqual(@as(u8, 0x00), connect_resp[1]); // Succeeded!

    // Send data and receive echo
    try client_writer.interface.writeAll(test_data);
    try client_writer.interface.flush();

    var echoed_data: [128]u8 = undefined;
    try client_reader.interface.readSliceAll(echoed_data[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, echoed_data[0..test_data.len]);
}

test "End-to-end SOCKS5 Shadowsocks tunnel with echo server" {
    const io = std.testing.io;

    const test_methods = [_]CipherMethod{
        .chacha20_ietf_poly1305,
        .aes_256_gcm,
        .aes_128_gcm,
    };

    for (test_methods) |method| {
        // OS assigned port for echo server
        var echo_server = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer echo_server.deinit(io);
        const echo_port = echo_server.socket.address.ip4.port;

        // OS assigned port for Shadowsocks server
        var ss_server_listener = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer ss_server_listener.deinit(io);
        const server_port = ss_server_listener.socket.address.ip4.port;

        // OS assigned port for Shadowsocks local
        var ss_local_listener = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer ss_local_listener.deinit(io);
        const local_ip = ss_local_listener.socket.address;

        const ss_server = Server.init(
            ss_server_listener.socket.address,
            method,
            "secret_pass_1234",
            false,
        );

        const ss_local = Local.init(
            local_ip,
            "127.0.0.1",
            server_port,
            method,
            "secret_pass_1234",
            false,
        );

        var fut_echo = try io.concurrent(runEchoServerOnce, .{ io, &echo_server });
        var fut_srv = try io.concurrent(runServerOnce, .{ io, &ss_server_listener, &ss_server });
        var fut_loc = try io.concurrent(runLocalOnce, .{ io, &ss_local_listener, &ss_local });
        var fut_cli = try io.concurrent(runTcpClientOnce, .{ io, local_ip, echo_port, "Hello Shadowsocks via OS assigned ports!" });

        try fut_cli.await(io);
        try fut_loc.await(io);
        try fut_srv.await(io);
        try fut_echo.await(io);
    }
}

test "End-to-end SOCKS5 IPv6 Shadowsocks tunnel" {
    const io = std.testing.io;
    const method = CipherMethod.chacha20_ietf_poly1305;

    const ip6_loopback = [_]u8{0} ** 15 ++ [_]u8{1};

    var echo_server = (IpAddress{ .ip6 = .{ .bytes = ip6_loopback, .port = 0 } }).listen(io, .{ .reuse_address = true }) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.NetworkDown => return error.SkipZigTest,
        else => |e| return e,
    };
    defer echo_server.deinit(io);
    const echo_port = echo_server.socket.address.ip6.port;

    var ss_server_listener = try (IpAddress{ .ip6 = .{ .bytes = ip6_loopback, .port = 0 } }).listen(io, .{ .reuse_address = true });
    defer ss_server_listener.deinit(io);
    const server_port = ss_server_listener.socket.address.ip6.port;

    var ss_local_listener = try (IpAddress{ .ip6 = .{ .bytes = ip6_loopback, .port = 0 } }).listen(io, .{ .reuse_address = true });
    defer ss_local_listener.deinit(io);
    const local_ip = ss_local_listener.socket.address;

    const ss_server = Server.init(
        ss_server_listener.socket.address,
        method,
        "ipv6_secret_123",
        false,
    );

    const ss_local = Local.init(
        local_ip,
        "::1",
        server_port,
        method,
        "ipv6_secret_123",
        false,
    );

    var fut_echo = try io.concurrent(runEchoServerOnce, .{ io, &echo_server });
    var fut_srv = try io.concurrent(runServerOnce, .{ io, &ss_server_listener, &ss_server });
    var fut_loc = try io.concurrent(runLocalOnce, .{ io, &ss_local_listener, &ss_local });
    var fut_cli = try io.concurrent(runTcpClientIp6Once, .{ io, local_ip, echo_port, ip6_loopback, "Hello IPv6 Shadowsocks!" });

    try fut_cli.await(io);
    try fut_loc.await(io);
    try fut_srv.await(io);
    try fut_echo.await(io);
}

fn runTcpClientIp6Once(io: Io, local_ip: IpAddress, echo_port: u16, ip6_loopback: [16]u8, test_data: []const u8) !void {
    const client_stream = try local_ip.connect(io, .{ .mode = .stream });
    defer client_stream.close(io);

    var client_r_buf: [1024]u8 = undefined;
    var client_w_buf: [1024]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_r_buf);
    var client_writer = client_stream.writer(io, &client_w_buf);

    try client_writer.interface.writeAll(&[_]u8{ 0x05, 0x01, 0x00 });
    try client_writer.interface.flush();

    var greeting_resp: [2]u8 = undefined;
    try client_reader.interface.readSliceAll(&greeting_resp);

    var connect_req: [22]u8 = undefined;
    connect_req[0] = 0x05;
    connect_req[1] = 0x01; // CONNECT
    connect_req[2] = 0x00; // RSV
    connect_req[3] = 0x04; // IPv6
    @memcpy(connect_req[4..20], &ip6_loopback);
    mem.writeInt(u16, connect_req[20..22], echo_port, .big);

    try client_writer.interface.writeAll(&connect_req);
    try client_writer.interface.flush();

    var connect_resp: [10]u8 = undefined;
    try client_reader.interface.readSliceAll(&connect_resp);
    try std.testing.expectEqual(@as(u8, 0x05), connect_resp[0]);
    try std.testing.expectEqual(@as(u8, 0x00), connect_resp[1]);

    try client_writer.interface.writeAll(test_data);
    try client_writer.interface.flush();

    var echoed_data: [128]u8 = undefined;
    try client_reader.interface.readSliceAll(echoed_data[0..test_data.len]);
    try std.testing.expectEqualStrings(test_data, echoed_data[0..test_data.len]);
}

test "End-to-end Shadowsocks 2022 SOCKS5 tunnel with echo server" {
    const io = std.testing.io;

    const test_cases = [_]struct {
        method: CipherMethod,
        psk_b64: []const u8,
    }{
        .{
            .method = .blake3_aes_128_gcm,
            .psk_b64 = "5mOQSa20Kt6ay2LXruBoHQ==",
        },
        .{
            .method = .blake3_aes_256_gcm,
            .psk_b64 = "t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=",
        },
        .{
            .method = .blake3_chacha20_poly1305,
            .psk_b64 = "W9r1q12Xf84qV4f2/P1g6v9lQ3K8M4bZ1j7k8m1n9q4=",
        },
    };

    for (test_cases) |tc| {
        var echo_server = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer echo_server.deinit(io);
        const echo_port = echo_server.socket.address.ip4.port;

        var ss_server_listener = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer ss_server_listener.deinit(io);
        const server_port = ss_server_listener.socket.address.ip4.port;

        var ss_local_listener = try (IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer ss_local_listener.deinit(io);
        const local_ip = ss_local_listener.socket.address;

        const ss_server = Server.init(
            ss_server_listener.socket.address,
            tc.method,
            tc.psk_b64,
            false,
        );

        const ss_local = Local.init(
            local_ip,
            "127.0.0.1",
            server_port,
            tc.method,
            tc.psk_b64,
            false,
        );

        var fut_echo = try io.concurrent(runEchoServerOnce, .{ io, &echo_server });
        var fut_srv = try io.concurrent(runServerOnce, .{ io, &ss_server_listener, &ss_server });
        var fut_loc = try io.concurrent(runLocalOnce, .{ io, &ss_local_listener, &ss_local });
        var fut_cli = try io.concurrent(runTcpClientOnce, .{ io, local_ip, echo_port, "Hello Shadowsocks 2022 Edition!" });

        try fut_cli.await(io);
        try fut_loc.await(io);
        try fut_srv.await(io);
        try fut_echo.await(io);
    }
}

test "End-to-end SOCKS5 UDP Associate Shadowsocks tunnel with UDP echo server" {
    const io = std.testing.io;

    const test_methods = [_]CipherMethod{
        .chacha20_ietf_poly1305,
        .aes_256_gcm,
        .aes_128_gcm,
        .blake3_aes_128_gcm,
        .blake3_aes_256_gcm,
        .blake3_chacha20_poly1305,
    };

    const psk_2022_128 = "5mOQSa20Kt6ay2LXruBoHQ==";
    const psk_2022_256 = "t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=";

    for (test_methods) |method| {
        // 1. Echo UDP server on OS assigned port
        const echo_sock = try (IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer echo_sock.close(io);
        const echo_port = echo_sock.address.ip4.port;

        // 2. Shadowsocks Remote Server UDP on OS assigned port
        const srv_udp_sock = try (IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer srv_udp_sock.close(io);
        const server_port = srv_udp_sock.address.ip4.port;

        var srv_forward_addr = IpAddress{ .ip4 = .unspecified(0) };
        const srv_forward_sock = try srv_forward_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer srv_forward_sock.close(io);

        // 3. Shadowsocks Local Proxy on OS assigned port
        const loc_udp_inbound = try (IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer loc_udp_inbound.close(io);
        const local_udp_port = loc_udp_inbound.address.ip4.port;

        var loc_outbound_addr = IpAddress{ .ip4 = .unspecified(0) };
        const loc_udp_outbound = try loc_outbound_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer loc_udp_outbound.close(io);

        const secret = if (method == .blake3_aes_128_gcm)
            psk_2022_128
        else if (method.is2022())
            psk_2022_256
        else
            "secret_pass_1234";

        const ss_server = Server.init(
            srv_udp_sock.address,
            method,
            secret,
            true,
        );

        const ss_local = Local.init(
            loc_udp_inbound.address,
            "127.0.0.1",
            server_port,
            method,
            secret,
            true,
        );

        var fut_echo = try io.concurrent(runUdpEchoServerOnce, .{ io, &echo_sock });
        var fut_srv = try io.concurrent(runServerUdpOnce, .{ io, &ss_server, &srv_udp_sock, &srv_forward_sock });
        var fut_loc = try io.concurrent(runLocalUdpOnce, .{ io, &ss_local, &loc_udp_inbound, &loc_udp_outbound });
        var fut_cli = try io.concurrent(runClientUdpTest, .{ io, local_udp_port, echo_port });

        try fut_cli.await(io);
        try fut_loc.await(io);
        try fut_srv.await(io);
        try fut_echo.await(io);
    }
}

fn runClientUdpTest(io: Io, local_udp_port: u16, echo_port: u16) !void {
    const local_relay_ip = IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = local_udp_port } };

    var cli_sock_addr = IpAddress{ .ip4 = .unspecified(0) };
    const cli_udp_sock = try cli_sock_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer cli_udp_sock.close(io);

    // SOCKS5 UDP datagram: [RSV 2B][FRAG 1B][ATYP 1B][ADDR 4B][PORT 2B][PAYLOAD]
    const target_addr = Address.initIp4(.{ 127, 0, 0, 1 }, echo_port);
    const udp_hdr = socks5.UdpHeader{
        .frag = 0,
        .target = target_addr,
    };
    var s5_dgram: [512]u8 = undefined;
    const hdr_len = try udp_hdr.encode(&s5_dgram);
    const ping_msg = "Ping UDP over Shadowsocks tunnel!";
    @memcpy(s5_dgram[hdr_len..][0..ping_msg.len], ping_msg);
    const total_dgram_len = hdr_len + ping_msg.len;

    try cli_udp_sock.send(io, &local_relay_ip, s5_dgram[0..total_dgram_len]);

    var recv_dgram_buf: [2048]u8 = undefined;
    const recv_msg = try cli_udp_sock.receiveTimeout(
        io,
        &recv_dgram_buf,
        .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
    );

    const resp_hdr, const resp_hdr_len = try socks5.UdpHeader.decode(recv_msg.data);
    try std.testing.expectEqual(echo_port, resp_hdr.target.port);
    try std.testing.expectEqualStrings(ping_msg, recv_msg.data[resp_hdr_len..]);
}
