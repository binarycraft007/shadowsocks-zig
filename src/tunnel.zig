const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Io = std.Io;
const Stream = Io.net.Stream;
const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;
const StreamCipherState = crypto.StreamCipherState;
const max_chunk_payload_len = crypto.max_chunk_payload_len;
const tag_len = crypto.tag_len;
const max_key_len = crypto.max_key_len;
const max_salt_len = crypto.max_salt_len;

pub const EncryptedReader = struct {
    underlying_reader: *Io.Reader,
    cipher: StreamCipherState = undefined,
    has_cipher: bool = false,
    method: CipherMethod,
    master_key: [max_key_len]u8 = undefined,
    master_key_len: usize,
    interface: Io.Reader,
    err: ?crypto.Error = null,

    // Internal encrypted chunk buffer to receive length tag + ciphertext
    encrypted_buf: [max_chunk_payload_len + tag_len]u8 = undefined,

    pub fn init(
        underlying_reader: *Io.Reader,
        method: CipherMethod,
        master_key: []const u8,
        decrypted_buffer: []u8,
    ) EncryptedReader {
        assert(decrypted_buffer.len >= max_chunk_payload_len);
        var r: EncryptedReader = .{
            .underlying_reader = underlying_reader,
            .cipher = undefined,
            .has_cipher = false,
            .method = method,
            .master_key = undefined,
            .master_key_len = master_key.len,
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

    pub fn initWithSalt(
        underlying_reader: *Io.Reader,
        method: CipherMethod,
        master_key: []const u8,
        salt: []const u8,
        decrypted_buffer: []u8,
    ) EncryptedReader {
        assert(decrypted_buffer.len >= max_chunk_payload_len);
        var r: EncryptedReader = .{
            .underlying_reader = underlying_reader,
            .cipher = StreamCipherState.init(method, master_key, salt),
            .has_cipher = true,
            .method = method,
            .master_key = undefined,
            .master_key_len = master_key.len,
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

    pub fn reader(self: *EncryptedReader) *Io.Reader {
        return &self.interface;
    }

    fn readNextChunk(self: *EncryptedReader, io_r: *Io.Reader) !usize {
        assert(io_r.seek == io_r.end);
        io_r.seek = 0;
        io_r.end = 0;

        if (!self.has_cipher) {
            const slen = self.method.saltLength();
            var salt: [max_salt_len]u8 = undefined;
            self.underlying_reader.readSliceAll(salt[0..slen]) catch |err| switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => {
                    self.err = error.AuthenticationFailed;
                    return error.ReadFailed;
                },
            };
            self.cipher = StreamCipherState.init(
                self.method,
                self.master_key[0..self.master_key_len],
                salt[0..slen],
            );
            self.has_cipher = true;
        }

        // 1. Read 18-byte length header: 2 bytes len + 16 bytes tag
        var len_header: [2 + tag_len]u8 = undefined;
        self.underlying_reader.readSliceAll(&len_header) catch |err| switch (err) {
            error.EndOfStream => return 0,
            error.ReadFailed => {
                self.err = error.AuthenticationFailed;
                return error.ReadFailed;
            },
        };

        // 2. Decrypt length
        const plen = self.cipher.decryptLength(&len_header) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        if (plen == 0) return 0;

        // 3. Read encrypted payload: plen + 16 bytes
        const enc_len = @as(usize, plen) + tag_len;
        self.underlying_reader.readSliceAll(self.encrypted_buf[0..enc_len]) catch |err| switch (err) {
            error.EndOfStream => return error.ReadFailed, // Incomplete chunk is a read failure
            error.ReadFailed => {
                self.err = error.AuthenticationFailed;
                return error.ReadFailed;
            },
        };

        // 4. Decrypt into io_r.buffer
        self.cipher.decryptPayload(self.encrypted_buf[0..enc_len], io_r.buffer[0..plen]) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        io_r.end = plen;
        return plen;
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *EncryptedReader = @alignCast(@fieldParentPtr("interface", io_r));
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
        const self: *EncryptedReader = @alignCast(@fieldParentPtr("interface", io_r));
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

pub const EncryptedWriter = struct {
    underlying_writer: *Io.Writer,
    cipher: StreamCipherState,
    salt: [max_salt_len]u8 = undefined,
    salt_len: usize = 0,
    salt_written: bool = false,
    interface: Io.Writer,
    err: ?crypto.Error = null,

    // Buffer for encrypting chunks (2 + tag_len + payload + tag_len)
    chunk_buf: [2 + tag_len + max_chunk_payload_len + tag_len]u8 = undefined,

    pub fn init(
        underlying_writer: *Io.Writer,
        method: CipherMethod,
        master_key: []const u8,
        salt: []const u8,
        plaintext_buffer: []u8,
    ) EncryptedWriter {
        var w: EncryptedWriter = .{
            .underlying_writer = underlying_writer,
            .cipher = StreamCipherState.init(method, master_key, salt),
            .salt = undefined,
            .salt_len = salt.len,
            .salt_written = false,
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

    pub fn writer(self: *EncryptedWriter) *Io.Writer {
        return &self.interface;
    }

    fn flushImpl(io_w: *Io.Writer) Io.Writer.Error!void {
        const self: *EncryptedWriter = @alignCast(@fieldParentPtr("interface", io_w));
        if (io_w.end == 0) {
            self.underlying_writer.flush() catch return error.WriteFailed;
            return;
        }

        if (!self.salt_written) {
            self.underlying_writer.writeAll(self.salt[0..self.salt_len]) catch {
                return error.WriteFailed;
            };
            self.salt_written = true;
        }

        // Encrypt buffered plaintext in io_w.buffer[0..io_w.end]
        const plain = io_w.buffer[0..io_w.end];
        const enc_len = self.cipher.encryptChunk(plain, &self.chunk_buf) catch {
            return error.WriteFailed;
        };
        self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch {
            return error.WriteFailed;
        };
        io_w.end = 0;
        self.underlying_writer.flush() catch return error.WriteFailed;
    }

    fn drainImpl(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *EncryptedWriter = @alignCast(@fieldParentPtr("interface", io_w));
        // Flush any buffered data first
        try flushImpl(io_w);

        var total_consumed: usize = 0;
        for (data) |slice| {
            if (slice.len == 0) continue;
            if (!self.salt_written) {
                self.underlying_writer.writeAll(self.salt[0..self.salt_len]) catch {
                    return error.WriteFailed;
                };
                self.salt_written = true;
            }
            var offset: usize = 0;
            while (offset < slice.len) {
                const chunk_len = @min(slice.len - offset, max_chunk_payload_len);
                const enc_len = self.cipher.encryptChunk(slice[offset .. offset + chunk_len], &self.chunk_buf) catch {
                    return error.WriteFailed;
                };
                self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch {
                    return error.WriteFailed;
                };
                offset += chunk_len;
                total_consumed += chunk_len;
            }
        }
        if (splat > 0 and data.len > 0) {
            const last_slice = data[data.len - 1];
            if (last_slice.len > 0) {
                if (!self.salt_written) {
                    self.underlying_writer.writeAll(self.salt[0..self.salt_len]) catch {
                        return error.WriteFailed;
                    };
                    self.salt_written = true;
                }
                for (0..splat) |_| {
                    var offset: usize = 0;
                    while (offset < last_slice.len) {
                        const chunk_len = @min(last_slice.len - offset, max_chunk_payload_len);
                        const enc_len = self.cipher.encryptChunk(last_slice[offset .. offset + chunk_len], &self.chunk_buf) catch {
                            return error.WriteFailed;
                        };
                        self.underlying_writer.writeAll(self.chunk_buf[0..enc_len]) catch {
                            return error.WriteFailed;
                        };
                        offset += chunk_len;
                        total_consumed += chunk_len;
                    }
                }
            }
        }
        self.underlying_writer.flush() catch {
            return error.WriteFailed;
        };
        return total_consumed;
    }
};

/// Pump data from an `Io.Reader` to an `Io.Writer` until EndOfStream.
pub fn pump(reader_ptr: *Io.Reader, writer_ptr: *Io.Writer) !usize {
    var total: usize = 0;
    while (true) {
        const n = reader_ptr.stream(writer_ptr, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed, error.WriteFailed => return err,
        };
        try writer_ptr.flush();
        total += n;
    }
    return total;
}

pub const Direction = enum {
    forward,
    backward,
};

pub const TunnelResult = struct {
    direction: Direction,
    bytes: usize,
    err: ?anyerror = null,
};

fn tunnelTask(
    io: Io,
    direction: Direction,
    source_reader: *Io.Reader,
    dest_writer: *Io.Writer,
    source_stream: Stream,
    dest_stream: Stream,
    queue: *Io.Queue(TunnelResult),
) void {
    const bytes = pump(source_reader, dest_writer) catch |err| {
        dest_stream.shutdown(io, .both) catch {};
        source_stream.shutdown(io, .both) catch {};
        queue.putOne(io, .{ .direction = direction, .bytes = 0, .err = err }) catch {};
        return;
    };
    dest_stream.shutdown(io, .send) catch {};
    queue.putOne(io, .{ .direction = direction, .bytes = bytes, .err = null }) catch {};
}

/// Bidirectional pipe between stream1 and stream2 with concurrent pump tasks.
pub fn pipe(
    io: Io,
    r1: *Io.Reader,
    w1: *Io.Writer,
    r2: *Io.Reader,
    w2: *Io.Writer,
    s1: Stream,
    s2: Stream,
) !void {
    var queue_buf: [4]TunnelResult = undefined;
    var queue: Io.Queue(TunnelResult) = .init(&queue_buf);
    defer queue.close(io);

    var forward = try io.concurrent(tunnelTask, .{ io, .forward, r1, w2, s1, s2, &queue });
    defer _ = forward.cancel(io);

    var backward = try io.concurrent(tunnelTask, .{ io, .backward, r2, w1, s2, s1, &queue });
    defer _ = backward.cancel(io);

    _ = queue.getOne(io) catch {};

    _ = forward.cancel(io);
    _ = backward.cancel(io);
    _ = forward.await(io);
    _ = backward.await(io);
}

test "EncryptedReader and EncryptedWriter full Io.Reader and Io.Writer test" {
    const method = CipherMethod.chacha20_ietf_poly1305;
    var master_key: [32]u8 = undefined;
    crypto.deriveKeyFromPassword("test_secret", &master_key);

    var salt: [32]u8 = undefined;
    @memset(&salt, 0x55);

    var intermediate_buf: [4096]u8 = undefined;
    var intermediate_writer = Io.Writer.fixed(&intermediate_buf);

    var enc_writer_plain_buf: [1024]u8 = undefined;
    var enc_writer = EncryptedWriter.init(
        &intermediate_writer,
        method,
        &master_key,
        &salt,
        &enc_writer_plain_buf,
    );
    const writer_interface = enc_writer.writer();

    const test_msg = "Zig 0.16.0 standard Io.Reader and Io.Writer interface test!";
    try writer_interface.writeAll(test_msg);
    try writer_interface.flush();

    const written_len = intermediate_writer.end;
    var intermediate_reader = Io.Reader.fixed(intermediate_buf[0..written_len]);

    var enc_reader_dec_buf: [max_chunk_payload_len]u8 = undefined;
    var enc_reader = EncryptedReader.init(
        &intermediate_reader,
        method,
        &master_key,
        &enc_reader_dec_buf,
    );
    const reader_interface = enc_reader.reader();

    var decrypted_out: [256]u8 = undefined;
    var decrypted_writer = Io.Writer.fixed(&decrypted_out);
    const n = try reader_interface.stream(&decrypted_writer, .unlimited);
    try std.testing.expectEqualStrings(test_msg, decrypted_out[0..n]);
}
