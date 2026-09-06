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
const tunnel = @import("tunnel.zig");
const tunnel2022 = @import("tunnel2022.zig");
const udp2022 = @import("udp2022.zig");
const replay = @import("replay.zig");
const Server = @This();

pub const stream_buffer_len: usize = 16384;

bind_address: IpAddress,
method: CipherMethod,
master_key: [max_key_len]u8,
enable_udp: bool = false,
salt_cache: replay.SaltCache = replay.SaltCache.init(),

pub fn init(
    bind_address: IpAddress,
    method: CipherMethod,
    password_or_key: []const u8,
    enable_udp: bool,
) Server {
    var s: Server = .{
        .bind_address = bind_address,
        .method = method,
        .master_key = undefined,
        .enable_udp = enable_udp,
        .salt_cache = replay.SaltCache.init(),
    };
    const klen = method.keyLength();
    crypto.parseOrDeriveKey(method, password_or_key, s.master_key[0..klen]) catch {
        crypto.deriveKeyFromPassword(password_or_key, s.master_key[0..klen]);
    };
    return s;
}

/// Start the server and run until canceled or error.
pub fn listenAndServe(self: *const Server, io: Io) !void {
    if (self.enable_udp) {
        var tcp_task = try io.concurrent(runTcpServerTask, .{ io, self });
        defer _ = tcp_task.cancel(io) catch {};
        defer _ = tcp_task.await(io) catch {};

        var udp_task = try io.concurrent(runUdpServerTask, .{ io, self });
        defer _ = udp_task.cancel(io) catch {};
        defer _ = udp_task.await(io) catch {};

        _ = tcp_task.await(io) catch {};
        _ = udp_task.await(io) catch {};
    } else {
        try self.runTcpServer(io);
    }
}

fn runTcpServerTask(io: Io, server: *const Server) !void {
    return server.runTcpServer(io);
}

fn runUdpServerTask(io: Io, server: *const Server) !void {
    return server.runUdpServer(io);
}

pub fn runTcpServer(self: *const Server, io: Io) !void {
    var server_socket = try self.bind_address.listen(io, .{ .reuse_address = true });
    defer server_socket.deinit(io);

    var group: Io.Group = .init;
    defer group.cancel(io);

    while (true) {
        const client_stream = server_socket.accept(io) catch |err| switch (err) {
            error.Canceled => return,
            else => |e| {
                std.log.err("TCP accept error: {any}", .{e});
                continue;
            },
        };

        // Spawn concurrent task in the server group to handle each client connection
        group.concurrent(io, handleClientTcp, .{ self, io, client_stream }) catch |err| {
            std.log.err("Failed to spawn client task: {any}", .{err});
            client_stream.close(io);
            continue;
        };
    }
}

pub fn handleClientTcp(self: *const Server, io: Io, client_stream: Stream) void {
    defer client_stream.close(io);

    const slen = self.method.saltLength();
    const klen = self.method.keyLength();

    var client_r_buf: [stream_buffer_len]u8 = undefined;
    var client_w_buf: [stream_buffer_len]u8 = undefined;
    var client_reader = client_stream.reader(io, &client_r_buf);
    var client_writer = client_stream.writer(io, &client_w_buf);

    if (self.method.is2022()) {
        // Shadowsocks 2022 TCP Mode
        var enc_r_dec_buf: [max_chunk_payload_len]u8 = undefined;
        var enc_reader = tunnel2022.EncryptedReader2022.initServer(
            io,
            &client_reader.interface,
            self.method,
            self.master_key[0..klen],
            &enc_r_dec_buf,
        );
        enc_reader.salt_cache = @constCast(&self.salt_cache);

        const target_addr = enc_reader.getOrReadTargetAddress() catch |err| {
            if (err != error.EndOfStream and err != error.Canceled and err != error.ReadFailed) {
                std.log.debug("Failed to decrypt 2022 target address: {any}", .{err});
            }
            return;
        };

        const target_ip = target_addr.resolve(io) catch |err| {
            var addr_buf: [256]u8 = undefined;
            var w = Io.Writer.fixed(&addr_buf);
            target_addr.format(&w) catch {};
            std.log.debug("Failed to resolve target address {s}: {any}", .{ w.buffered(), err });
            return;
        };

        const target_stream = IpAddress.connect(&target_ip, io, .{ .mode = .stream }) catch |err| {
            var addr_buf: [256]u8 = undefined;
            var w = Io.Writer.fixed(&addr_buf);
            target_addr.format(&w) catch {};
            std.log.debug("Failed to connect to target {s}: {any}", .{ w.buffered(), err });
            return;
        };
        defer target_stream.close(io);

        var target_r_buf: [stream_buffer_len]u8 = undefined;
        var target_w_buf: [stream_buffer_len]u8 = undefined;
        var target_reader = target_stream.reader(io, &target_r_buf);
        var target_writer = target_stream.writer(io, &target_w_buf);

        var server_salt: [max_salt_len]u8 = undefined;
        io.random(server_salt[0..slen]);

        var enc_w_plain_buf: [stream_buffer_len]u8 = undefined;
        var enc_writer = tunnel2022.EncryptedWriter2022.initServer(
            io,
            &client_writer.interface,
            self.method,
            self.master_key[0..klen],
            server_salt[0..slen],
            enc_reader.getClientSalt(),
            &enc_w_plain_buf,
        );

        const enc_r = enc_reader.reader();
        const enc_w = enc_writer.writer();

        tunnel.pipe(
            io,
            enc_r,
            enc_w,
            &target_reader.interface,
            &target_writer.interface,
            client_stream,
            target_stream,
        ) catch {};
    } else {
        // Legacy Shadowsocks 2017 AEAD Mode
        // 1. Initialize EncryptedReader (lazily reads client salt on first read)
        var enc_r_dec_buf: [max_chunk_payload_len]u8 = undefined;
        var enc_reader = tunnel.EncryptedReader.init(
            &client_reader.interface,
            self.method,
            self.master_key[0..klen],
            &enc_r_dec_buf,
        );

        // 2. Initialize EncryptedWriter with server random salt (written on first response chunk)
        var server_salt: [max_salt_len]u8 = undefined;
        io.random(server_salt[0..slen]);

        var enc_w_plain_buf: [stream_buffer_len]u8 = undefined;
        var enc_writer = tunnel.EncryptedWriter.init(
            &client_writer.interface,
            self.method,
            self.master_key[0..klen],
            server_salt[0..slen],
            &enc_w_plain_buf,
        );

        const enc_r = enc_reader.reader();
        const enc_w = enc_writer.writer();

        // 3. Decrypt target destination address (triggers reading client salt in enc_r)
        var domain_buf: [256]u8 = undefined;
        const target_addr = Address.readFromReader(enc_r, &domain_buf) catch |err| {
            if (err != error.EndOfStream and err != error.Canceled and err != error.ReadFailed) {
                std.log.debug("Failed to decrypt target address: {any}", .{err});
            }
            return;
        };

        // 4. Resolve destination address to IP
        const target_ip = target_addr.resolve(io) catch |err| {
            var addr_buf: [256]u8 = undefined;
            var w = Io.Writer.fixed(&addr_buf);
            target_addr.format(&w) catch {};
            std.log.debug("Failed to resolve target address {s}: {any}", .{ w.buffered(), err });
            return;
        };

        // 5. Connect to target destination
        const target_stream = IpAddress.connect(&target_ip, io, .{ .mode = .stream }) catch |err| {
            var addr_buf: [256]u8 = undefined;
            var w = Io.Writer.fixed(&addr_buf);
            target_addr.format(&w) catch {};
            std.log.debug("Failed to connect to target {s}: {any}", .{ w.buffered(), err });
            return;
        };
        defer target_stream.close(io);

        var target_r_buf: [stream_buffer_len]u8 = undefined;
        var target_w_buf: [stream_buffer_len]u8 = undefined;
        var target_reader = target_stream.reader(io, &target_r_buf);
        var target_writer = target_stream.writer(io, &target_w_buf);

        // 6. Bidirectional concurrent pipe using standard *Io.Reader and *Io.Writer
        tunnel.pipe(
            io,
            enc_r,
            enc_w,
            &target_reader.interface,
            &target_writer.interface,
            client_stream,
            target_stream,
        ) catch {};
    }
}

pub fn handleUdpOnce(self: *const Server, io: Io, udp_socket: *const Socket, forward_socket: *const Socket) !void {
    const slen = self.method.saltLength();
    const klen = self.method.keyLength();

    var recv_buf: [65536]u8 = undefined;
    var dec_buf: [65536]u8 = undefined;

    const msg = try udp_socket.receive(io, &recv_buf);

    if (self.method.is2022()) {
        const now_sec = tunnel2022.getCurrentEpochSeconds(io);
        const dec = try udp2022.decryptClientPacket(
            self.method,
            self.master_key[0..klen],
            msg.data,
            now_sec,
            &dec_buf,
        );

        const target_ip = try dec.target.resolve(io);

        // Send payload to target
        try forward_socket.send(io, &target_ip, dec.payload);

        // Receive response from target with timeout
        var target_resp_buf: [65536]u8 = undefined;
        const target_msg = try forward_socket.receiveTimeout(
            io,
            &target_resp_buf,
            .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
        );

        var server_session_id: [8]u8 = undefined;
        io.random(&server_session_id);

        var random_bytes: [24]u8 = undefined;
        io.random(&random_bytes);

        var packet_out: [65536]u8 = undefined;
        const packet_len = try udp2022.encryptServerPacket(
            self.method,
            self.master_key[0..klen],
            &server_session_id,
            0,
            &dec.session_id,
            now_sec,
            0,
            dec.target,
            target_msg.data,
            &packet_out,
            &random_bytes,
        );

        try udp_socket.send(io, &msg.from, packet_out[0..packet_len]);
    } else {
        const dec_len = try crypto.decryptUdpPacket(
            self.method,
            self.master_key[0..klen],
            msg.data,
            &dec_buf,
        );

        const target_addr, const addr_len = try Address.decode(dec_buf[0..dec_len]);
        const target_ip = try target_addr.resolve(io);
        const payload = dec_buf[addr_len..dec_len];

        // Send payload to target
        try forward_socket.send(io, &target_ip, payload);

        // Receive response from target with timeout
        var target_resp_buf: [65536]u8 = undefined;
        const target_msg = try forward_socket.receiveTimeout(
            io,
            &target_resp_buf,
            .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },
        );

        // Construct client response: [target_addr][reply_data]
        var resp_plain_buf: [65536]u8 = undefined;
        var resp_addr_buf: [259]u8 = undefined;
        const resp_addr_len = try target_addr.encode(&resp_addr_buf);
        @memcpy(resp_plain_buf[0..resp_addr_len], resp_addr_buf[0..resp_addr_len]);
        @memcpy(resp_plain_buf[resp_addr_len..][0..target_msg.data.len], target_msg.data);
        const total_plain = resp_addr_len + target_msg.data.len;

        // Encrypt response with random salt
        var salt: [max_salt_len]u8 = undefined;
        io.random(salt[0..slen]);

        var packet_out: [65536]u8 = undefined;
        const packet_len = try crypto.encryptUdpPacket(
            self.method,
            self.master_key[0..klen],
            salt[0..slen],
            resp_plain_buf[0..total_plain],
            &packet_out,
        );

        // Send back to client
        try udp_socket.send(io, &msg.from, packet_out[0..packet_len]);
    }
}

pub fn runUdpServer(self: *const Server, io: Io) !void {
    const udp_socket = try self.bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer udp_socket.close(io);

    var forward_sock_addr = IpAddress{ .ip4 = .unspecified(0) };
    const forward_socket = try forward_sock_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer forward_socket.close(io);

    while (true) {
        self.handleUdpOnce(io, &udp_socket, &forward_socket) catch |err| switch (err) {
            error.Canceled => return,
            else => |e| {
                std.log.debug("Server UDP error: {any}", .{e});
                continue;
            },
        };
    }
}
