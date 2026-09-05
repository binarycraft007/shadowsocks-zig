const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Io = std.Io;
const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;
const StreamCipherState = crypto.StreamCipherState;
const max_key_len = crypto.max_key_len;
const max_salt_len = crypto.max_salt_len;
const max_chunk_payload_len = crypto.max_chunk_payload_len;
const tag_len = crypto.tag_len;
const Address = @import("Address.zig");
const replay = @import("replay.zig");

pub const HeaderTypeClientStream: u8 = 0;
pub const HeaderTypeServerStream: u8 = 1;
pub const MinPaddingLength: usize = 0;
pub const MaxPaddingLength: usize = 900;

pub const Error = error{
    AuthenticationFailed,
    InvalidHeaderType,
    InvalidTimestamp,
    RequestSaltMismatch,
    InvalidPadding,
    BufferTooSmall,
    ReadFailed,
    WriteFailed,
    EndOfStream,
};

/// Get current Unix epoch timestamp in seconds using std.Io.
pub fn getCurrentEpochSeconds(io: Io) u64 {
    const ts = Io.Timestamp.now(io, .real);
    const sec = ts.toSeconds();
    if (sec < 0) return 0;
    return @intCast(sec);
}

/// Shadowsocks 2022 Encrypted Stream Reader implementing *Io.Reader interface.
pub const EncryptedReader2022 = struct {
    io: Io,
    underlying_reader: *Io.Reader,
    cipher: StreamCipherState = undefined,
    has_cipher: bool = false,
    method: CipherMethod,
    master_key: [max_key_len]u8 = undefined,
    master_key_len: usize,
    expected_request_salt: ?[max_salt_len]u8 = null,
    is_server: bool,
    target_address: ?Address = null,
    client_salt: [max_salt_len]u8 = undefined,
    salt_cache: ?*replay.SaltCache = null,
    interface: Io.Reader,
    err: ?crypto.Error = null,

    // Internal encrypted chunk buffer
    encrypted_buf: [max_chunk_payload_len + tag_len]u8 = undefined,

    pub fn initClient(
        io: Io,
        underlying_reader: *Io.Reader,
        method: CipherMethod,
        master_key: []const u8,
        request_salt: []const u8,
        decrypted_buffer: []u8,
    ) EncryptedReader2022 {
        assert(decrypted_buffer.len >= max_chunk_payload_len);
        var r = EncryptedReader2022{
            .io = io,
            .underlying_reader = underlying_reader,
            .method = method,
            .master_key_len = master_key.len,
            .is_server = false,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                    .readVec = readVecImpl,
                },
                .buffer = decrypted_buffer,
                .seek = 0,
                .end = 0,
            },
        };
        @memcpy(r.master_key[0..master_key.len], master_key);
        var req_salt = [_]u8{0} ** max_salt_len;
        @memcpy(req_salt[0..request_salt.len], request_salt);
        r.expected_request_salt = req_salt;
        return r;
    }

    pub fn initServer(
        io: Io,
        underlying_reader: *Io.Reader,
        method: CipherMethod,
        master_key: []const u8,
        decrypted_buffer: []u8,
    ) EncryptedReader2022 {
        assert(decrypted_buffer.len >= max_chunk_payload_len);
        var r = EncryptedReader2022{
            .io = io,
            .underlying_reader = underlying_reader,
            .method = method,
            .master_key_len = master_key.len,
            .is_server = true,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                    .readVec = readVecImpl,
                },
                .buffer = decrypted_buffer,
                .seek = 0,
                .end = 0,
            },
        };
        @memcpy(r.master_key[0..master_key.len], master_key);
        return r;
    }

    pub fn reader(self: *EncryptedReader2022) *Io.Reader {
        return &self.interface;
    }

    pub fn getClientSalt(self: *const EncryptedReader2022) []const u8 {
        return self.client_salt[0..self.method.saltLength()];
    }

    pub fn getOrReadTargetAddress(self: *EncryptedReader2022) !Address {
        if (self.target_address) |addr| return addr;
        try self.processHeader(&self.interface);
        return self.target_address orelse error.ReadFailed;
    }

    /// Read and process Shadowsocks 2022 stream header (Client or Server).
    fn processHeader(self: *EncryptedReader2022, io_r: *Io.Reader) !void {
        const slen = self.method.saltLength();
        const klen = self.method.keyLength();
        const now = getCurrentEpochSeconds(self.io);

        if (!self.has_cipher) {
            var salt: [max_salt_len]u8 = undefined;
            self.underlying_reader.readSliceAll(salt[0..slen]) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => return error.ReadFailed,
            };
            @memcpy(self.client_salt[0..slen], salt[0..slen]);
            self.cipher = StreamCipherState.init(self.method, self.master_key[0..klen], salt[0..slen]);
            self.has_cipher = true;
        }

        if (self.is_server) {
            // Server processing client request:
            // 1. Read Fixed-length Header: 11 bytes plaintext + 16 bytes tag = 27 bytes
            var enc_fixed: [11 + tag_len]u8 = undefined;
            self.underlying_reader.readSliceAll(&enc_fixed) catch return error.ReadFailed;

            var dec_fixed: [11]u8 = undefined;
            _ = self.cipher.decryptMessage(&enc_fixed, &dec_fixed) catch return error.ReadFailed;

            const htype = dec_fixed[0];
            if (htype != HeaderTypeClientStream) return error.ReadFailed;

            const timestamp = mem.readInt(u64, dec_fixed[1..9], .big);
            if (!replay.validateTimestamp(timestamp, now)) return error.ReadFailed;

            if (self.salt_cache) |sc| {
                if (!sc.checkAndAdd(self.client_salt[0..slen], @intCast(now))) {
                    return error.ReadFailed; // Replay detected!
                }
            }

            const var_len = mem.readInt(u16, dec_fixed[9..11], .big);
            if (var_len < 7 or var_len > max_chunk_payload_len) return error.ReadFailed;

            // 2. Read Variable-length Header: var_len bytes + 16 bytes tag
            const enc_var_len = @as(usize, var_len) + tag_len;
            self.underlying_reader.readSliceAll(self.encrypted_buf[0..enc_var_len]) catch return error.ReadFailed;

            var dec_var: [max_chunk_payload_len]u8 = undefined;
            const dec_vlen = self.cipher.decryptMessage(self.encrypted_buf[0..enc_var_len], &dec_var) catch return error.ReadFailed;
            if (dec_vlen != var_len) return error.ReadFailed;

            // Parse target address from variable header
            const target_addr, const addr_len = Address.decode(dec_var[0..dec_vlen]) catch return error.ReadFailed;
            self.target_address = target_addr;

            if (addr_len + 2 > dec_vlen) return error.ReadFailed;
            const pad_len = mem.readInt(u16, dec_var[addr_len..][0..2], .big);
            const total_hdr_prefix = addr_len + 2 + pad_len;
            if (total_hdr_prefix > dec_vlen) return error.ReadFailed;

            const initial_payload = dec_var[total_hdr_prefix..dec_vlen];
            if (initial_payload.len == 0 and pad_len == 0) {
                return error.ReadFailed; // Spec requires non-zero padding or initial payload
            }

            if (initial_payload.len > 0) {
                @memcpy(io_r.buffer[0..initial_payload.len], initial_payload);
                io_r.seek = 0;
                io_r.end = initial_payload.len;
            }
        } else {
            // Client processing server response:
            // 1. Read Response Header: (11 + slen) bytes + 16 bytes tag
            const resp_hdr_plain_len = 11 + slen;
            const resp_hdr_enc_len = resp_hdr_plain_len + tag_len;
            self.underlying_reader.readSliceAll(self.encrypted_buf[0..resp_hdr_enc_len]) catch return error.ReadFailed;

            var dec_resp: [64]u8 = undefined;
            const dec_len = self.cipher.decryptMessage(self.encrypted_buf[0..resp_hdr_enc_len], &dec_resp) catch return error.ReadFailed;
            if (dec_len != resp_hdr_plain_len) return error.ReadFailed;

            const htype = dec_resp[0];
            if (htype != HeaderTypeServerStream) return error.ReadFailed;

            const timestamp = mem.readInt(u64, dec_resp[1..9], .big);
            if (!replay.validateTimestamp(timestamp, now)) return error.ReadFailed;

            const server_echo_req_salt = dec_resp[9 .. 9 + slen];
            if (self.expected_request_salt) |exp_salt| {
                if (!mem.eql(u8, exp_salt[0..slen], server_echo_req_salt)) {
                    return error.ReadFailed; // Request salt mismatch
                }
            }

            const initial_payload_len = mem.readInt(u16, dec_resp[9 + slen ..][0..2], .big);
            if (initial_payload_len > 0) {
                const enc_payload_len = @as(usize, initial_payload_len) + tag_len;
                self.underlying_reader.readSliceAll(self.encrypted_buf[0..enc_payload_len]) catch return error.ReadFailed;

                const dn = self.cipher.decryptMessage(self.encrypted_buf[0..enc_payload_len], io_r.buffer[0..initial_payload_len]) catch return error.ReadFailed;
                io_r.seek = 0;
                io_r.end = dn;
            }
        }
    }

    fn readNextChunk(self: *EncryptedReader2022, io_r: *Io.Reader) !usize {
        assert(io_r.seek == io_r.end);
        io_r.seek = 0;
        io_r.end = 0;

        if (!self.has_cipher) {
            try self.processHeader(io_r);
            if (io_r.end > 0) return io_r.end;
        }

        // Read 18-byte length header: 2 bytes len + 16 bytes tag
        var len_header: [2 + tag_len]u8 = undefined;
        self.underlying_reader.readSliceAll(&len_header) catch |err| switch (err) {
            error.EndOfStream => return 0,
            else => return error.ReadFailed,
        };

        // Decrypt length
        const plen = self.cipher.decryptLength(&len_header) catch return error.ReadFailed;
        if (plen == 0) return 0;

        // Read encrypted payload: plen + 16 bytes
        const enc_len = @as(usize, plen) + tag_len;
        self.underlying_reader.readSliceAll(self.encrypted_buf[0..enc_len]) catch return error.ReadFailed;

        // Decrypt into io_r.buffer
        self.cipher.decryptPayload(self.encrypted_buf[0..enc_len], io_r.buffer[0..plen]) catch return error.ReadFailed;
        io_r.end = plen;
        return plen;
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *EncryptedReader2022 = @alignCast(@fieldParentPtr("interface", io_r));
        if (io_r.seek == io_r.end) {
            const plen = self.readNextChunk(io_r) catch return error.ReadFailed;
            if (plen == 0) return error.EndOfStream;
        }

        const available = io_r.end - io_r.seek;
        const to_stream = limit.slice(io_r.buffer[io_r.seek .. io_r.seek + available]);
        const n = io_w.write(to_stream) catch return error.WriteFailed;
        io_r.seek += n;
        return n;
    }

    fn readVecImpl(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const self: *EncryptedReader2022 = @alignCast(@fieldParentPtr("interface", io_r));
        if (data.len == 0 or data[0].len == 0) return 0;

        if (io_r.seek == io_r.end) {
            const plen = self.readNextChunk(io_r) catch return error.ReadFailed;
            if (plen == 0) return error.EndOfStream;
        }

        const available = io_r.end - io_r.seek;
        const dest = data[0];
        const to_copy = @min(available, dest.len);
        @memcpy(dest[0..to_copy], io_r.buffer[io_r.seek .. io_r.seek + to_copy]);
        io_r.seek += to_copy;
        return to_copy;
    }
};

/// Shadowsocks 2022 Encrypted Stream Writer implementing *Io.Writer interface.
pub const EncryptedWriter2022 = struct {
    io: Io,
    underlying_writer: *Io.Writer,
    cipher: StreamCipherState,
    salt: [max_salt_len]u8 = undefined,
    salt_len: usize = 0,
    header_written: bool = false,
    is_server: bool,
    client_request_salt: ?[max_salt_len]u8 = null,
    target_address: ?Address = null,
    interface: Io.Writer,
    err: ?crypto.Error = null,

    // Buffer for encrypting chunks (2 + tag_len + payload + tag_len)
    chunk_buf: [2 + tag_len + max_chunk_payload_len + tag_len]u8 = undefined,

    pub fn initClient(
        io: Io,
        underlying_writer: *Io.Writer,
        method: CipherMethod,
        master_key: []const u8,
        salt: []const u8,
        target: Address,
        plaintext_buffer: []u8,
    ) EncryptedWriter2022 {
        var w = EncryptedWriter2022{
            .io = io,
            .underlying_writer = underlying_writer,
            .cipher = StreamCipherState.init(method, master_key, salt),
            .salt_len = salt.len,
            .header_written = false,
            .is_server = false,
            .target_address = target,
            .interface = .{
                .vtable = &.{
                    .drain = drainImpl,
                    .flush = flushImpl,
                },
                .buffer = plaintext_buffer,
                .end = 0,
            },
        };
        @memcpy(w.salt[0..salt.len], salt);
        return w;
    }

    pub fn initServer(
        io: Io,
        underlying_writer: *Io.Writer,
        method: CipherMethod,
        master_key: []const u8,
        salt: []const u8,
        client_request_salt: []const u8,
        plaintext_buffer: []u8,
    ) EncryptedWriter2022 {
        var w = EncryptedWriter2022{
            .io = io,
            .underlying_writer = underlying_writer,
            .cipher = StreamCipherState.init(method, master_key, salt),
            .salt_len = salt.len,
            .header_written = false,
            .is_server = true,
            .interface = .{
                .vtable = &.{
                    .drain = drainImpl,
                    .flush = flushImpl,
                },
                .buffer = plaintext_buffer,
                .end = 0,
            },
        };
        @memcpy(w.salt[0..salt.len], salt);
        var req_salt = [_]u8{0} ** max_salt_len;
        @memcpy(req_salt[0..client_request_salt.len], client_request_salt);
        w.client_request_salt = req_salt;
        return w;
    }

    pub fn writer(self: *EncryptedWriter2022) *Io.Writer {
        return &self.interface;
    }

    fn writeHeaders(self: *EncryptedWriter2022, initial_payload: []const u8) Io.Writer.Error!void {
        const now = getCurrentEpochSeconds(self.io);
        const slen = self.salt_len;

        var header_buf: [2048]u8 = undefined;
        var offset: usize = 0;

        // 1. Salt
        @memcpy(header_buf[offset .. offset + slen], self.salt[0..slen]);
        offset += slen;

        if (!self.is_server) {
            // Client Request Header:
            const target = self.target_address.?;
            var addr_raw: [259]u8 = undefined;
            const addr_len = target.encode(&addr_raw) catch return error.WriteFailed;

            // Random padding (if no initial payload, send between 16 and 64 bytes of padding)
            const pad_len: u16 = if (initial_payload.len == 0) 32 else 0;
            const var_plain_len = addr_len + 2 + pad_len + initial_payload.len;

            // Fixed Header (11 bytes): [type 0][timestamp 8B][var_plain_len u16be]
            var fixed_plain: [11]u8 = undefined;
            fixed_plain[0] = HeaderTypeClientStream;
            mem.writeInt(u64, fixed_plain[1..9], now, .big);
            mem.writeInt(u16, fixed_plain[9..11], @intCast(var_plain_len), .big);

            const enc_fixed_len = self.cipher.encryptMessage(&fixed_plain, header_buf[offset..]) catch return error.WriteFailed;
            offset += enc_fixed_len;

            // Variable Header Plaintext: [addr][pad_len 2B][padding][initial_payload]
            var var_plain: [2048]u8 = undefined;
            @memcpy(var_plain[0..addr_len], addr_raw[0..addr_len]);
            mem.writeInt(u16, var_plain[addr_len..][0..2], pad_len, .big);
            if (pad_len > 0) {
                @memset(var_plain[addr_len + 2 ..][0..pad_len], 0x00);
            }
            if (initial_payload.len > 0) {
                @memcpy(var_plain[addr_len + 2 + pad_len ..][0..initial_payload.len], initial_payload);
            }

            const enc_var_len = self.cipher.encryptMessage(var_plain[0..var_plain_len], header_buf[offset..]) catch return error.WriteFailed;
            offset += enc_var_len;
        } else {
            // Server Response Header:
            const resp_plain_len = 11 + slen;
            var resp_plain: [64]u8 = undefined;
            resp_plain[0] = HeaderTypeServerStream;
            mem.writeInt(u64, resp_plain[1..9], now, .big);
            @memcpy(resp_plain[9 .. 9 + slen], self.client_request_salt.?[0..slen]);
            mem.writeInt(u16, resp_plain[9 + slen ..][0..2], @intCast(initial_payload.len), .big);

            const enc_resp_hdr_len = self.cipher.encryptMessage(resp_plain[0..resp_plain_len], header_buf[offset..]) catch return error.WriteFailed;
            offset += enc_resp_hdr_len;

            if (initial_payload.len > 0) {
                const enc_p_len = self.cipher.encryptMessage(initial_payload, header_buf[offset..]) catch return error.WriteFailed;
                offset += enc_p_len;
            }
        }

        // Single write call to underlying socket for detection prevention
        self.underlying_writer.writeAll(header_buf[0..offset]) catch return error.WriteFailed;
        self.header_written = true;
    }

    fn flushImpl(io_w: *Io.Writer) Io.Writer.Error!void {
        const self: *EncryptedWriter2022 = @alignCast(@fieldParentPtr("interface", io_w));
        if (!self.header_written) {
            try self.writeHeaders(io_w.buffer[0..io_w.end]);
            io_w.end = 0;
            self.underlying_writer.flush() catch return error.WriteFailed;
            return;
        }

        if (io_w.end == 0) {
            self.underlying_writer.flush() catch return error.WriteFailed;
            return;
        }

        const plain = io_w.buffer[0..io_w.end];
        const enc_len = self.cipher.encryptChunk(plain, &self.chunk_buf) catch return error.WriteFailed;
        self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch return error.WriteFailed;
        io_w.end = 0;
        self.underlying_writer.flush() catch return error.WriteFailed;
    }

    fn drainImpl(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *EncryptedWriter2022 = @alignCast(@fieldParentPtr("interface", io_w));
        try flushImpl(io_w);

        var total_consumed: usize = 0;
        for (data) |slice| {
            if (slice.len == 0) continue;
            var offset: usize = 0;
            while (offset < slice.len) {
                const chunk_len = @min(slice.len - offset, max_chunk_payload_len);
                const enc_len = self.cipher.encryptChunk(slice[offset .. offset + chunk_len], &self.chunk_buf) catch return error.WriteFailed;
                self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch return error.WriteFailed;
                offset += chunk_len;
                total_consumed += chunk_len;
            }
        }
        if (splat > 0 and data.len > 0) {
            const last_slice = data[data.len - 1];
            if (last_slice.len > 0) {
                for (0..splat) |_| {
                    var offset: usize = 0;
                    while (offset < last_slice.len) {
                        const chunk_len = @min(last_slice.len - offset, max_chunk_payload_len);
                        const enc_len = self.cipher.encryptChunk(last_slice[offset .. offset + chunk_len], &self.chunk_buf) catch return error.WriteFailed;
                        self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch return error.WriteFailed;
                        offset += chunk_len;
                        total_consumed += chunk_len;
                    }
                }
            }
        }
        self.underlying_writer.flush() catch return error.WriteFailed;
        return total_consumed;
    }
};

test "Shadowsocks 2022 Client-to-Server and Server-to-Client full stream roundtrip" {
    const method = CipherMethod.blake3_aes_256_gcm;
    const psk = [_]u8{0xAB} ** 32;
    const client_salt = [_]u8{0x11} ** 32;
    const server_salt = [_]u8{0x22} ** 32;

    const target = Address.initDomain("example.com", 443);

    // 1. Client writes request stream with initial payload
    var wire_c2s_buf: [4096]u8 = undefined;
    var wire_c2s_writer = Io.Writer.fixed(&wire_c2s_buf);

    var client_w_buf: [1024]u8 = undefined;
    var enc_writer_client = EncryptedWriter2022.initClient(
        std.testing.io,
        &wire_c2s_writer,
        method,
        &psk,
        &client_salt,
        target,
        &client_w_buf,
    );
    const client_w = enc_writer_client.writer();

    const client_request_data = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try client_w.writeAll(client_request_data);
    try client_w.flush();

    // 2. Server reads request stream
    const c2s_written = wire_c2s_writer.end;
    var wire_c2s_reader = Io.Reader.fixed(wire_c2s_buf[0..c2s_written]);

    var server_dec_buf: [max_chunk_payload_len]u8 = undefined;
    var enc_reader_server = EncryptedReader2022.initServer(
        std.testing.io,
        &wire_c2s_reader,
        method,
        &psk,
        &server_dec_buf,
    );
    const server_r = enc_reader_server.reader();

    var server_received: [1024]u8 = undefined;
    var server_received_writer = Io.Writer.fixed(&server_received);
    const n_req = try server_r.stream(&server_received_writer, .unlimited);

    try std.testing.expectEqualStrings(client_request_data, server_received[0..n_req]);
    try std.testing.expect(enc_reader_server.target_address != null);
    try std.testing.expectEqualStrings("example.com", enc_reader_server.target_address.?.host.domain);
    try std.testing.expectEqual(@as(u16, 443), enc_reader_server.target_address.?.port);

    // 3. Server writes response stream
    var wire_s2c_buf: [4096]u8 = undefined;
    var wire_s2c_writer = Io.Writer.fixed(&wire_s2c_buf);

    var server_w_buf: [1024]u8 = undefined;
    var enc_writer_server = EncryptedWriter2022.initServer(
        std.testing.io,
        &wire_s2c_writer,
        method,
        &psk,
        &server_salt,
        &client_salt,
        &server_w_buf,
    );
    const server_w = enc_writer_server.writer();

    const server_response_data = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello 2022!";
    try server_w.writeAll(server_response_data);
    try server_w.flush();

    // 4. Client reads response stream
    const s2c_written = wire_s2c_writer.end;
    var wire_s2c_reader = Io.Reader.fixed(wire_s2c_buf[0..s2c_written]);

    var client_dec_buf: [max_chunk_payload_len]u8 = undefined;
    var enc_reader_client = EncryptedReader2022.initClient(
        std.testing.io,
        &wire_s2c_reader,
        method,
        &psk,
        &client_salt,
        &client_dec_buf,
    );
    const client_r = enc_reader_client.reader();

    var client_received: [1024]u8 = undefined;
    var client_received_writer = Io.Writer.fixed(&client_received);
    const n_resp = try client_r.stream(&client_received_writer, .unlimited);

    try std.testing.expectEqualStrings(server_response_data, client_received[0..n_resp]);
}
