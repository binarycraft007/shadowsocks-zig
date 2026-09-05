const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Io = std.Io;
const Stream = Io.net.Stream;
const Socket = Io.net.Socket;
const ServerSocket = Io.net.Server;
const IpAddress = Io.net.IpAddress;

const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;
const max_key_len = crypto.max_key_len;
const max_salt_len = crypto.max_salt_len;
const max_chunk_payload_len = crypto.max_chunk_payload_len;
const Address = @import("Address.zig");
const socks5 = @import("socks5.zig");
const tunnel = @import("tunnel.zig");
const tunnel2022 = @import("tunnel2022.zig");
const udp2022 = @import("udp2022.zig");
const Local = @This();

pub const stream_buffer_len: usize = 16384;

local_address: IpAddress,
server_host: []const u8,
server_port: u16,
method: CipherMethod,
master_key: [max_key_len]u8,
enable_udp: bool = false,

pub fn init(
    local_address: IpAddress,
    server_host: []const u8,
    server_port: u16,
    method: CipherMethod,
    password_or_key: []const u8,
    enable_udp: bool,
) Local {
    var l: Local = .{
        .local_address = local_address,
        .server_host = server_host,
        .server_port = server_port,
        .method = method,
        .master_key = undefined,
        .enable_udp = enable_udp,
    };
    const klen = method.keyLength();
    crypto.parseOrDeriveKey(method, password_or_key, l.master_key[0..klen]) catch |err| {
        std.log.err("Failed to parse/derive master key for method {s}: {any}", .{ method.toString(), err });
        crypto.deriveKeyFromPassword(password_or_key, l.master_key[0..klen]);
    };
    return l;
}

/// Start the local SOCKS5 proxy and run until canceled or error.
pub fn listenAndServe(self: *const Local, io: Io) !void {
    if (self.enable_udp) {
        var tcp_task = try io.concurrent(runTcpServerTask, .{ io, self });
        defer tcp_task.cancel(io) catch {};

        var udp_task = try io.concurrent(runUdpRelayTask, .{ io, self });
        defer udp_task.cancel(io) catch {};

        _ = tcp_task.await(io) catch {};
        _ = udp_task.await(io) catch {};
    } else {
        try self.runTcpServer(io);
    }
}

fn runTcpServerTask(io: Io, local: *const Local) !void {
    return local.runTcpServer(io);
}

fn runUdpRelayTask(io: Io, local: *const Local) !void {
    return local.runUdpRelay(io);
}

pub fn runTcpServer(self: *const Local, io: Io) !void {
    var server_socket = try self.local_address.listen(io, .{ .reuse_address = true });
    defer server_socket.deinit(io);

    var group: Io.Group = .init;
    defer group.cancel(io);

    while (true) {
        const client_stream = server_socket.accept(io) catch |err| switch (err) {
            error.Canceled => return,
            else => |e| {
                std.log.err("SOCKS5 accept error: {any}", .{e});
                continue;
            },
        };

        // Spawn concurrent task in the local group to handle each SOCKS5 client
        group.concurrent(io, handleClientTcp, .{ self, io, client_stream }) catch |err| {
            std.log.err("Failed to spawn client task: {any}", .{err});
            client_stream.close(io);
            continue;
        };
    }
}

pub fn handleUdpOnce(self: *const Local, io: Io, inbound_socket: *const Socket, outbound_socket: *const Socket) !void {
    const slen = self.method.saltLength();
    const klen = self.method.keyLength();

    var recv_buf: [65536]u8 = undefined;
    var dec_buf: [65536]u8 = undefined;

    const server_target = Address.initDomain(self.server_host, self.server_port);

    const msg = try inbound_socket.receive(io, &recv_buf);

    const s5_hdr, const hdr_len = try socks5.UdpHeader.decode(msg.data);
    const payload = msg.data[hdr_len..];

    const server_ip = try server_target.resolve(io);

    if (self.method.is2022()) {
        var client_session_id: [8]u8 = undefined;
        io.random(&client_session_id);

        const now_sec = tunnel2022.getCurrentEpochSeconds(io);
        var random_bytes: [24]u8 = undefined;
        io.random(&random_bytes);

        var packet_out: [65536]u8 = undefined;
        const packet_len = try udp2022.encryptClientPacket(
            self.method,
            self.master_key[0..klen],
            &client_session_id,
            0,
            now_sec,
            0,
            s5_hdr.target,
            payload,
            &packet_out,
            &random_bytes,
        );

        // Send to Shadowsocks server via outbound_socket
        try outbound_socket.send(io, &server_ip, packet_out[0..packet_len]);

        // Receive response from server via outbound_socket with timeout
        var server_resp_buf: [65536]u8 = undefined;
        const server_msg = try outbound_socket.receiveTimeout(
            io,
            &server_resp_buf,
            .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
        );

        const dec_server = try udp2022.decryptServerPacket(
            self.method,
            self.master_key[0..klen],
            server_msg.data,
            &client_session_id,
            now_sec,
            &dec_buf,
        );

        const resp_hdr = socks5.UdpHeader{
            .frag = 0,
            .target = dec_server.target,
        };
        var s5_resp_buf: [65536]u8 = undefined;
        const s5_hdr_len = try resp_hdr.encode(&s5_resp_buf);
        @memcpy(s5_resp_buf[s5_hdr_len..][0..dec_server.payload.len], dec_server.payload);

        try inbound_socket.send(io, &msg.from, s5_resp_buf[0 .. s5_hdr_len + dec_server.payload.len]);
    } else {
        var plain_buf: [65536]u8 = undefined;
        var addr_buf: [259]u8 = undefined;
        const addr_len = try s5_hdr.target.encode(&addr_buf);
        @memcpy(plain_buf[0..addr_len], addr_buf[0..addr_len]);
        @memcpy(plain_buf[addr_len..][0..payload.len], payload);
        const total_plain = addr_len + payload.len;

        var salt: [max_salt_len]u8 = undefined;
        io.random(salt[0..slen]);

        var packet_out: [65536]u8 = undefined;
        const packet_len = try crypto.encryptUdpPacket(
            self.method,
            self.master_key[0..klen],
            salt[0..slen],
            plain_buf[0..total_plain],
            &packet_out,
        );

        // Send to Shadowsocks server via outbound_socket
        try outbound_socket.send(io, &server_ip, packet_out[0..packet_len]);

        // Receive response from server via outbound_socket with timeout
        var server_resp_buf: [65536]u8 = undefined;
        const server_msg = try outbound_socket.receiveTimeout(
            io,
            &server_resp_buf,
            .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
        );

        const dec_len = try crypto.decryptUdpPacket(
            self.method,
            self.master_key[0..klen],
            server_msg.data,
            &dec_buf,
        );

        const resp_target, const resp_addr_len = try Address.decode(dec_buf[0..dec_len]);
        const resp_payload = dec_buf[resp_addr_len..dec_len];

        const resp_hdr = socks5.UdpHeader{
            .frag = 0,
            .target = resp_target,
        };
        var s5_resp_buf: [65536]u8 = undefined;
        const s5_hdr_len = try resp_hdr.encode(&s5_resp_buf);
        @memcpy(s5_resp_buf[s5_hdr_len..][0..resp_payload.len], resp_payload);

        try inbound_socket.send(io, &msg.from, s5_resp_buf[0 .. s5_hdr_len + resp_payload.len]);
    }
}

pub fn runUdpRelay(self: *const Local, io: Io) !void {
    const inbound_socket = try self.local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer inbound_socket.close(io);

    var outbound_addr = IpAddress{ .ip4 = .unspecified(0) };
    const outbound_socket = try outbound_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer outbound_socket.close(io);

    while (true) {
        self.handleUdpOnce(io, &inbound_socket, &outbound_socket) catch |err| switch (err) {
            error.Canceled => return,
            else => |e| {
                std.log.debug("Local UDP receive error: {any}", .{e});
                continue;
            },
        };
    }
}

pub fn handleClientTcp(self: *const Local, io: Io, client_stream: Stream) void {
    defer client_stream.close(io);

    const slen = self.method.saltLength();
    const klen = self.method.keyLength();

    var client_r_buf: [stream_buffer_len]u8 = undefined;
    var client_w_buf: [stream_buffer_len]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_r_buf);
    var client_writer = client_stream.writer(io, &client_w_buf);

    // 1. SOCKS5 Handshake
    socks5.serverHandshake(&client_reader.interface, &client_writer.interface) catch |err| {
        if (err != error.EndOfStream and err != error.Canceled and err != error.ReadFailed) {
            std.log.debug("SOCKS5 handshake failed: {any}", .{err});
        }
        return;
    };

    // 2. Read SOCKS5 Request
    var domain_buf: [256]u8 = undefined;
    const req = socks5.readRequest(&client_reader.interface, &domain_buf) catch |err| {
        if (err != error.EndOfStream and err != error.Canceled and err != error.ReadFailed) {
            std.log.debug("SOCKS5 read request failed: {any}", .{err});
        }
        return;
    };

    switch (req.command) {
        .connect => {
            // 3. Resolve remote Shadowsocks server
            const server_target = Address.initDomain(self.server_host, self.server_port);
            const server_ip = server_target.resolve(io) catch |err| {
                std.log.debug("Failed to resolve remote server {s}:{d}: {any}", .{ self.server_host, self.server_port, err });
                socks5.sendReply(&client_writer.interface, .network_unreachable, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                return;
            };

            // 4. Connect to remote Shadowsocks server
            const remote_stream = IpAddress.connect(&server_ip, io, .{ .mode = .stream }) catch |err| {
                std.log.debug("Failed to connect to remote server {s}:{d}: {any}", .{ self.server_host, self.server_port, err });
                socks5.sendReply(&client_writer.interface, .connection_refused, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                return;
            };
            defer remote_stream.close(io);

            var remote_r_buf: [stream_buffer_len]u8 = undefined;
            var remote_w_buf: [stream_buffer_len]u8 = undefined;
            var remote_reader = remote_stream.reader(io, &remote_r_buf);
            var remote_writer = remote_stream.writer(io, &remote_w_buf);

            // 5. Initialize Client Salt
            var client_salt: [max_salt_len]u8 = undefined;
            io.random(client_salt[0..slen]);

            if (self.method.is2022()) {
                // Shadowsocks 2022 Mode
                var enc_w_plain_buf: [stream_buffer_len]u8 = undefined;
                var enc_writer = tunnel2022.EncryptedWriter2022.initClient(
                    io,
                    &remote_writer.interface,
                    self.method,
                    self.master_key[0..klen],
                    client_salt[0..slen],
                    req.target,
                    &enc_w_plain_buf,
                );
                const enc_w = enc_writer.writer();

                // Flush sends the 2022 salt + request fixed header + variable header (with target and padding)
                enc_w.flush() catch {
                    socks5.sendReply(&client_writer.interface, .general_failure, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                    return;
                };

                // Send SOCKS5 success reply to client
                socks5.sendSuccessReply(&client_writer.interface) catch return;

                var enc_r_dec_buf: [max_chunk_payload_len]u8 = undefined;
                var enc_reader = tunnel2022.EncryptedReader2022.initClient(
                    io,
                    &remote_reader.interface,
                    self.method,
                    self.master_key[0..klen],
                    client_salt[0..slen],
                    &enc_r_dec_buf,
                );
                const enc_r = enc_reader.reader();

                tunnel.pipe(
                    io,
                    &client_reader.interface,
                    &client_writer.interface,
                    enc_r,
                    enc_w,
                    client_stream,
                    remote_stream,
                ) catch {};
            } else {
                // Legacy Shadowsocks 2017 AEAD Mode
                var enc_w_plain_buf: [stream_buffer_len]u8 = undefined;
                var enc_writer = tunnel.EncryptedWriter.init(
                    &remote_writer.interface,
                    self.method,
                    self.master_key[0..klen],
                    client_salt[0..slen],
                    &enc_w_plain_buf,
                );
                const enc_w = enc_writer.writer();

                req.target.writeToWriter(enc_w) catch |err| {
                    std.log.debug("Failed to send target address to remote server: {any}", .{err});
                    socks5.sendReply(&client_writer.interface, .general_failure, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                    return;
                };
                enc_w.flush() catch {
                    socks5.sendReply(&client_writer.interface, .general_failure, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                    return;
                };

                socks5.sendSuccessReply(&client_writer.interface) catch return;

                var enc_r_dec_buf: [max_chunk_payload_len]u8 = undefined;
                var enc_reader = tunnel.EncryptedReader.init(
                    &remote_reader.interface,
                    self.method,
                    self.master_key[0..klen],
                    &enc_r_dec_buf,
                );
                const enc_r = enc_reader.reader();

                tunnel.pipe(
                    io,
                    &client_reader.interface,
                    &client_writer.interface,
                    enc_r,
                    enc_w,
                    client_stream,
                    remote_stream,
                ) catch {};
            }
        },
        .udp_associate => {
            if (!self.enable_udp) {
                socks5.sendReply(&client_writer.interface, .command_not_supported, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
                return;
            }
            // Send UDP relay bound address back to client
            socks5.sendReply(&client_writer.interface, .succeeded, Address.fromIpAddress(self.local_address)) catch return;

            // Keep connection open until client closes it
            _ = client_reader.interface.discard(.unlimited) catch {};
        },
        .bind => {
            socks5.sendReply(&client_writer.interface, .command_not_supported, Address.initIp4(.{ 0, 0, 0, 0 }, 0)) catch {};
        },
    }
}
