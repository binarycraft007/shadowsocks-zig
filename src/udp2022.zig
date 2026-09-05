const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;
const Address = @import("Address.zig");
const replay = @import("replay.zig");

pub const HeaderTypeClientPacket: u8 = 0;
pub const HeaderTypeServerPacket: u8 = 1;

pub const Error = error{
    AuthenticationFailed,
    InvalidHeaderType,
    InvalidTimestamp,
    InvalidPayloadLength,
    InvalidSessionId,
    BufferTooSmall,
    InvalidAddress,
    UnsupportedMethod,
};

pub const DecryptedClientPacket = struct {
    session_id: [8]u8,
    packet_id: u64,
    timestamp: u64,
    target: Address,
    payload: []const u8,
};

pub const DecryptedServerPacket = struct {
    server_session_id: [8]u8,
    server_packet_id: u64,
    client_session_id: [8]u8,
    timestamp: u64,
    target: Address,
    payload: []const u8,
};

/// Encrypt a client-to-server UDP datagram according to Shadowsocks 2022 specification.
pub fn encryptClientPacket(
    method: CipherMethod,
    psk: []const u8,
    client_session_id: *const [8]u8,
    client_packet_id: u64,
    now_sec: u64,
    padding_len: usize,
    target: Address,
    payload: []const u8,
    out: []u8,
    random_bytes: []const u8, // For chacha20 nonce (24B)
) Error!usize {
    assert(psk.len == method.keyLength());

    var target_buf: [259]u8 = undefined;
    const target_len = target.encode(&target_buf) catch return error.InvalidAddress;

    switch (method) {
        .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
            // 1. Separate header (16 bytes): [session ID 8B][packet ID u64be 8B]
            var sep_hdr: [16]u8 = undefined;
            @memcpy(sep_hdr[0..8], client_session_id);
            mem.writeInt(u64, sep_hdr[8..16], client_packet_id, .big);

            const total_len = 16 + (1 + 8 + 2 + padding_len + target_len + payload.len) + crypto.tag_len;
            if (out.len < total_len) return error.BufferTooSmall;

            // Encrypt separate header with PSK AES block cipher
            crypto.aesBlockEncrypt(psk, &sep_hdr, out[0..16][0..16]);

            // 2. Derive session subkey from PSK + session_id
            var session_subkey: [crypto.max_key_len]u8 = undefined;
            const klen = method.keyLength();
            crypto.deriveSubkey2022(psk, client_session_id, session_subkey[0..klen]);

            // 3. Construct plaintext body: [type 0][timestamp 8B][pad_len 2B][padding][target][payload]
            var body_buf: [65536]u8 = undefined;
            var offset: usize = 0;
            body_buf[offset] = HeaderTypeClientPacket;
            offset += 1;

            mem.writeInt(u64, body_buf[offset..][0..8], now_sec, .big);
            offset += 8;

            mem.writeInt(u16, body_buf[offset..][0..2], @intCast(padding_len), .big);
            offset += 2;

            if (padding_len > 0) {
                @memset(body_buf[offset..][0..padding_len], 0);
                offset += padding_len;
            }

            @memcpy(body_buf[offset..][0..target_len], target_buf[0..target_len]);
            offset += target_len;

            @memcpy(body_buf[offset..][0..payload.len], payload);
            offset += payload.len;

            // 4. Nonce is sep_hdr[4..16] (12 bytes)
            const nonce = sep_hdr[4..16];
            var tag: [crypto.tag_len]u8 = undefined;

            crypto.aeadEncrypt(
                method,
                session_subkey[0..klen],
                nonce,
                "",
                body_buf[0..offset],
                out[16..][0..offset],
                &tag,
            );
            @memcpy(out[16 + offset ..][0..crypto.tag_len], &tag);

            return total_len;
        },
        .blake3_chacha20_poly1305 => {
            // Random 24B nonce
            if (random_bytes.len < 24) return error.BufferTooSmall;
            const nonce = random_bytes[0..24];

            const body_plain_len = 8 + 8 + 1 + 8 + 2 + padding_len + target_len + payload.len;
            const total_len = 24 + body_plain_len + crypto.tag_len;
            if (out.len < total_len) return error.BufferTooSmall;

            @memcpy(out[0..24], nonce);

            var body_buf: [65536]u8 = undefined;
            var offset: usize = 0;

            @memcpy(body_buf[offset..][0..8], client_session_id);
            offset += 8;

            mem.writeInt(u64, body_buf[offset..][0..8], client_packet_id, .big);
            offset += 8;

            body_buf[offset] = HeaderTypeClientPacket;
            offset += 1;

            mem.writeInt(u64, body_buf[offset..][0..8], now_sec, .big);
            offset += 8;

            mem.writeInt(u16, body_buf[offset..][0..2], @intCast(padding_len), .big);
            offset += 2;

            if (padding_len > 0) {
                @memset(body_buf[offset..][0..padding_len], 0);
                offset += padding_len;
            }

            @memcpy(body_buf[offset..][0..target_len], target_buf[0..target_len]);
            offset += target_len;

            @memcpy(body_buf[offset..][0..payload.len], payload);
            offset += payload.len;

            var tag: [crypto.tag_len]u8 = undefined;
            crypto.aeadEncrypt(
                .xchacha20_ietf_poly1305,
                psk,
                nonce,
                "",
                body_buf[0..offset],
                out[24..][0..offset],
                &tag,
            );
            @memcpy(out[24 + offset ..][0..crypto.tag_len], &tag);

            return total_len;
        },
        else => return error.UnsupportedMethod,
    }
}

/// Decrypt a client-to-server UDP datagram (Server side).
pub fn decryptClientPacket(
    method: CipherMethod,
    psk: []const u8,
    packet: []const u8,
    now_sec: u64,
    body_scratch: []u8,
) Error!DecryptedClientPacket {
    assert(psk.len == method.keyLength());

    switch (method) {
        .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
            if (packet.len < 16 + 1 + 8 + 2 + 7 + crypto.tag_len) {
                return error.InvalidPayloadLength;
            }

            // 1. Decrypt separate header (16 bytes)
            var sep_hdr: [16]u8 = undefined;
            crypto.aesBlockDecrypt(psk, packet[0..16][0..16], &sep_hdr);

            var session_id: [8]u8 = undefined;
            @memcpy(&session_id, sep_hdr[0..8]);
            const packet_id = mem.readInt(u64, sep_hdr[8..16], .big);

            // 2. Derive session subkey
            var session_subkey: [crypto.max_key_len]u8 = undefined;
            const klen = method.keyLength();
            crypto.deriveSubkey2022(psk, &session_id, session_subkey[0..klen]);

            // 3. Decrypt body
            const nonce = sep_hdr[4..16];
            const enc_body_len = packet.len - 16 - crypto.tag_len;
            if (body_scratch.len < enc_body_len) return error.BufferTooSmall;

            var tag: [crypto.tag_len]u8 = undefined;
            @memcpy(&tag, packet[packet.len - crypto.tag_len ..]);

            crypto.aeadDecrypt(
                method,
                session_subkey[0..klen],
                nonce,
                "",
                packet[16 .. 16 + enc_body_len],
                tag,
                body_scratch[0..enc_body_len],
            ) catch return error.AuthenticationFailed;

            // 4. Parse main header: [type 1B][timestamp 8B][pad_len 2B][padding][target][payload]
            if (enc_body_len < 1 + 8 + 2 + 7) return error.InvalidPayloadLength;

            const htype = body_scratch[0];
            if (htype != HeaderTypeClientPacket) return error.InvalidHeaderType;

            const ts = mem.readInt(u64, body_scratch[1..9], .big);
            if (!replay.validateTimestamp(ts, now_sec)) return error.InvalidTimestamp;

            const pad_len = mem.readInt(u16, body_scratch[9..11], .big);
            var offset: usize = 11 + pad_len;
            if (offset > enc_body_len) return error.InvalidPayloadLength;

            const target, const addr_len = Address.decode(body_scratch[offset..enc_body_len]) catch return error.InvalidAddress;
            offset += addr_len;

            return DecryptedClientPacket{
                .session_id = session_id,
                .packet_id = packet_id,
                .timestamp = ts,
                .target = target,
                .payload = body_scratch[offset..enc_body_len],
            };
        },
        .blake3_chacha20_poly1305 => {
            if (packet.len < 24 + 8 + 8 + 1 + 8 + 2 + 7 + crypto.tag_len) {
                return error.InvalidPayloadLength;
            }

            const nonce = packet[0..24];
            const enc_body_len = packet.len - 24 - crypto.tag_len;
            if (body_scratch.len < enc_body_len) return error.BufferTooSmall;

            var tag: [crypto.tag_len]u8 = undefined;
            @memcpy(&tag, packet[packet.len - crypto.tag_len ..]);

            crypto.aeadDecrypt(
                .xchacha20_ietf_poly1305,
                psk,
                nonce,
                "",
                packet[24 .. 24 + enc_body_len],
                tag,
                body_scratch[0..enc_body_len],
            ) catch return error.AuthenticationFailed;

            // Parse: [session ID 8B][packet ID 8B][type 1B][timestamp 8B][pad_len 2B][padding][target][payload]
            var session_id: [8]u8 = undefined;
            @memcpy(&session_id, body_scratch[0..8]);
            const packet_id = mem.readInt(u64, body_scratch[8..16], .big);

            const htype = body_scratch[16];
            if (htype != HeaderTypeClientPacket) return error.InvalidHeaderType;

            const ts = mem.readInt(u64, body_scratch[17..25], .big);
            if (!replay.validateTimestamp(ts, now_sec)) return error.InvalidTimestamp;

            const pad_len = mem.readInt(u16, body_scratch[25..27], .big);
            var offset: usize = 27 + pad_len;
            if (offset > enc_body_len) return error.InvalidPayloadLength;

            const target, const addr_len = Address.decode(body_scratch[offset..enc_body_len]) catch return error.InvalidAddress;
            offset += addr_len;

            return DecryptedClientPacket{
                .session_id = session_id,
                .packet_id = packet_id,
                .timestamp = ts,
                .target = target,
                .payload = body_scratch[offset..enc_body_len],
            };
        },
        else => return error.UnsupportedMethod,
    }
}

/// Encrypt a server-to-client UDP datagram according to Shadowsocks 2022 specification.
pub fn encryptServerPacket(
    method: CipherMethod,
    psk: []const u8,
    server_session_id: *const [8]u8,
    server_packet_id: u64,
    client_session_id: *const [8]u8,
    now_sec: u64,
    padding_len: usize,
    target: Address,
    payload: []const u8,
    out: []u8,
    random_bytes: []const u8, // For chacha20 nonce (24B)
) Error!usize {
    assert(psk.len == method.keyLength());

    var target_buf: [259]u8 = undefined;
    const target_len = target.encode(&target_buf) catch return error.InvalidAddress;

    switch (method) {
        .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
            // 1. Separate header (16 bytes): [server session ID 8B][server packet ID u64be 8B]
            var sep_hdr: [16]u8 = undefined;
            @memcpy(sep_hdr[0..8], server_session_id);
            mem.writeInt(u64, sep_hdr[8..16], server_packet_id, .big);

            const total_len = 16 + (1 + 8 + 8 + 2 + padding_len + target_len + payload.len) + crypto.tag_len;
            if (out.len < total_len) return error.BufferTooSmall;

            // Encrypt separate header with PSK AES block cipher
            crypto.aesBlockEncrypt(psk, &sep_hdr, out[0..16][0..16]);

            // 2. Derive session subkey from PSK + server_session_id
            var session_subkey: [crypto.max_key_len]u8 = undefined;
            const klen = method.keyLength();
            crypto.deriveSubkey2022(psk, server_session_id, session_subkey[0..klen]);

            // 3. Plaintext body: [type 1][timestamp 8B][client session ID 8B][pad_len 2B][padding][target][payload]
            var body_buf: [65536]u8 = undefined;
            var offset: usize = 0;
            body_buf[offset] = HeaderTypeServerPacket;
            offset += 1;

            mem.writeInt(u64, body_buf[offset..][0..8], now_sec, .big);
            offset += 8;

            @memcpy(body_buf[offset..][0..8], client_session_id);
            offset += 8;

            mem.writeInt(u16, body_buf[offset..][0..2], @intCast(padding_len), .big);
            offset += 2;

            if (padding_len > 0) {
                @memset(body_buf[offset..][0..padding_len], 0);
                offset += padding_len;
            }

            @memcpy(body_buf[offset..][0..target_len], target_buf[0..target_len]);
            offset += target_len;

            @memcpy(body_buf[offset..][0..payload.len], payload);
            offset += payload.len;

            // 4. Nonce is sep_hdr[4..16] (12 bytes)
            const nonce = sep_hdr[4..16];
            var tag: [crypto.tag_len]u8 = undefined;

            crypto.aeadEncrypt(
                method,
                session_subkey[0..klen],
                nonce,
                "",
                body_buf[0..offset],
                out[16..][0..offset],
                &tag,
            );
            @memcpy(out[16 + offset ..][0..crypto.tag_len], &tag);

            return total_len;
        },
        .blake3_chacha20_poly1305 => {
            if (random_bytes.len < 24) return error.BufferTooSmall;
            const nonce = random_bytes[0..24];

            const body_plain_len = 8 + 8 + 1 + 8 + 8 + 2 + padding_len + target_len + payload.len;
            const total_len = 24 + body_plain_len + crypto.tag_len;
            if (out.len < total_len) return error.BufferTooSmall;

            @memcpy(out[0..24], nonce);

            var body_buf: [65536]u8 = undefined;
            var offset: usize = 0;

            @memcpy(body_buf[offset..][0..8], server_session_id);
            offset += 8;

            mem.writeInt(u64, body_buf[offset..][0..8], server_packet_id, .big);
            offset += 8;

            body_buf[offset] = HeaderTypeServerPacket;
            offset += 1;

            mem.writeInt(u64, body_buf[offset..][0..8], now_sec, .big);
            offset += 8;

            @memcpy(body_buf[offset..][0..8], client_session_id);
            offset += 8;

            mem.writeInt(u16, body_buf[offset..][0..2], @intCast(padding_len), .big);
            offset += 2;

            if (padding_len > 0) {
                @memset(body_buf[offset..][0..padding_len], 0);
                offset += padding_len;
            }

            @memcpy(body_buf[offset..][0..target_len], target_buf[0..target_len]);
            offset += target_len;

            @memcpy(body_buf[offset..][0..payload.len], payload);
            offset += payload.len;

            var tag: [crypto.tag_len]u8 = undefined;
            crypto.aeadEncrypt(
                .xchacha20_ietf_poly1305,
                psk,
                nonce,
                "",
                body_buf[0..offset],
                out[24..][0..offset],
                &tag,
            );
            @memcpy(out[24 + offset ..][0..crypto.tag_len], &tag);

            return total_len;
        },
        else => return error.UnsupportedMethod,
    }
}

/// Decrypt a server-to-client UDP datagram (Client side).
pub fn decryptServerPacket(
    method: CipherMethod,
    psk: []const u8,
    packet: []const u8,
    expected_client_session_id: ?*const [8]u8,
    now_sec: u64,
    body_scratch: []u8,
) Error!DecryptedServerPacket {
    assert(psk.len == method.keyLength());

    switch (method) {
        .blake3_aes_128_gcm, .blake3_aes_256_gcm => {
            if (packet.len < 16 + 1 + 8 + 8 + 2 + 7 + crypto.tag_len) {
                return error.InvalidPayloadLength;
            }

            // 1. Decrypt separate header (16 bytes)
            var sep_hdr: [16]u8 = undefined;
            crypto.aesBlockDecrypt(psk, packet[0..16][0..16], &sep_hdr);

            var server_session_id: [8]u8 = undefined;
            @memcpy(&server_session_id, sep_hdr[0..8]);
            const server_packet_id = mem.readInt(u64, sep_hdr[8..16], .big);

            // 2. Derive session subkey from PSK + server_session_id
            var session_subkey: [crypto.max_key_len]u8 = undefined;
            const klen = method.keyLength();
            crypto.deriveSubkey2022(psk, &server_session_id, session_subkey[0..klen]);

            // 3. Decrypt body
            const nonce = sep_hdr[4..16];
            const enc_body_len = packet.len - 16 - crypto.tag_len;
            if (body_scratch.len < enc_body_len) return error.BufferTooSmall;

            var tag: [crypto.tag_len]u8 = undefined;
            @memcpy(&tag, packet[packet.len - crypto.tag_len ..]);

            crypto.aeadDecrypt(
                method,
                session_subkey[0..klen],
                nonce,
                "",
                packet[16 .. 16 + enc_body_len],
                tag,
                body_scratch[0..enc_body_len],
            ) catch return error.AuthenticationFailed;

            // 4. Parse body: [type 1B][timestamp 8B][client session ID 8B][pad_len 2B][padding][target][payload]
            if (enc_body_len < 1 + 8 + 8 + 2 + 7) return error.InvalidPayloadLength;

            const htype = body_scratch[0];
            if (htype != HeaderTypeServerPacket) return error.InvalidHeaderType;

            const ts = mem.readInt(u64, body_scratch[1..9], .big);
            if (!replay.validateTimestamp(ts, now_sec)) return error.InvalidTimestamp;

            var client_session_id: [8]u8 = undefined;
            @memcpy(&client_session_id, body_scratch[9..17]);

            if (expected_client_session_id) |exp_id| {
                if (!mem.eql(u8, exp_id, &client_session_id)) {
                    return error.InvalidSessionId;
                }
            }

            const pad_len = mem.readInt(u16, body_scratch[17..19], .big);
            var offset: usize = 19 + pad_len;
            if (offset > enc_body_len) return error.InvalidPayloadLength;

            const target, const addr_len = Address.decode(body_scratch[offset..enc_body_len]) catch return error.InvalidAddress;
            offset += addr_len;

            return DecryptedServerPacket{
                .server_session_id = server_session_id,
                .server_packet_id = server_packet_id,
                .client_session_id = client_session_id,
                .timestamp = ts,
                .target = target,
                .payload = body_scratch[offset..enc_body_len],
            };
        },
        .blake3_chacha20_poly1305 => {
            if (packet.len < 24 + 8 + 8 + 1 + 8 + 8 + 2 + 7 + crypto.tag_len) {
                return error.InvalidPayloadLength;
            }

            const nonce = packet[0..24];
            const enc_body_len = packet.len - 24 - crypto.tag_len;
            if (body_scratch.len < enc_body_len) return error.BufferTooSmall;

            var tag: [crypto.tag_len]u8 = undefined;
            @memcpy(&tag, packet[packet.len - crypto.tag_len ..]);

            crypto.aeadDecrypt(
                .xchacha20_ietf_poly1305,
                psk,
                nonce,
                "",
                packet[24 .. 24 + enc_body_len],
                tag,
                body_scratch[0..enc_body_len],
            ) catch return error.AuthenticationFailed;

            // Parse: [server session ID 8B][server packet ID 8B][type 1B][timestamp 8B][client session ID 8B][pad_len 2B][padding][target][payload]
            var server_session_id: [8]u8 = undefined;
            @memcpy(&server_session_id, body_scratch[0..8]);
            const server_packet_id = mem.readInt(u64, body_scratch[8..16], .big);

            const htype = body_scratch[16];
            if (htype != HeaderTypeServerPacket) return error.InvalidHeaderType;

            const ts = mem.readInt(u64, body_scratch[17..25], .big);
            if (!replay.validateTimestamp(ts, now_sec)) return error.InvalidTimestamp;

            var client_session_id: [8]u8 = undefined;
            @memcpy(&client_session_id, body_scratch[25..33]);

            if (expected_client_session_id) |exp_id| {
                if (!mem.eql(u8, exp_id, &client_session_id)) {
                    return error.InvalidSessionId;
                }
            }

            const pad_len = mem.readInt(u16, body_scratch[33..35], .big);
            var offset: usize = 35 + pad_len;
            if (offset > enc_body_len) return error.InvalidPayloadLength;

            const target, const addr_len = Address.decode(body_scratch[offset..enc_body_len]) catch return error.InvalidAddress;
            offset += addr_len;

            return DecryptedServerPacket{
                .server_session_id = server_session_id,
                .server_packet_id = server_packet_id,
                .client_session_id = client_session_id,
                .timestamp = ts,
                .target = target,
                .payload = body_scratch[offset..enc_body_len],
            };
        },
        else => return error.UnsupportedMethod,
    }
}

test "Shadowsocks 2022 UDP AES-128-GCM roundtrip" {
    const method = CipherMethod.blake3_aes_128_gcm;
    const psk = [_]u8{0x12} ** 16;
    const client_session_id = [_]u8{0xAA} ** 8;
    const server_session_id = [_]u8{0xBB} ** 8;
    const now: u64 = 1700000000;
    const target = Address.initIp4([_]u8{ 8, 8, 8, 8 }, 53);
    const payload = "DNS QUERY DATA";

    // 1. Client to Server
    var c2s_packet: [1024]u8 = undefined;
    const c2s_len = try encryptClientPacket(
        method,
        &psk,
        &client_session_id,
        0,
        now,
        16,
        target,
        payload,
        &c2s_packet,
        &[_]u8{},
    );

    var s_scratch: [1024]u8 = undefined;
    const s_dec = try decryptClientPacket(
        method,
        &psk,
        c2s_packet[0..c2s_len],
        now,
        &s_scratch,
    );

    try std.testing.expectEqualStrings(&client_session_id, &s_dec.session_id);
    try std.testing.expectEqual(@as(u64, 0), s_dec.packet_id);
    try std.testing.expectEqual(now, s_dec.timestamp);
    try std.testing.expectEqual(target.port, s_dec.target.port);
    try std.testing.expectEqualStrings(payload, s_dec.payload);

    // 2. Server to Client
    var s2c_packet: [1024]u8 = undefined;
    const s2c_len = try encryptServerPacket(
        method,
        &psk,
        &server_session_id,
        0,
        &client_session_id,
        now,
        0,
        target,
        "DNS RESPONSE DATA",
        &s2c_packet,
        &[_]u8{},
    );

    var c_scratch: [1024]u8 = undefined;
    const c_dec = try decryptServerPacket(
        method,
        &psk,
        s2c_packet[0..s2c_len],
        &client_session_id,
        now,
        &c_scratch,
    );

    try std.testing.expectEqualStrings(&server_session_id, &c_dec.server_session_id);
    try std.testing.expectEqualStrings(&client_session_id, &c_dec.client_session_id);
    try std.testing.expectEqual(@as(u64, 0), c_dec.server_packet_id);
    try std.testing.expectEqualStrings("DNS RESPONSE DATA", c_dec.payload);
}

test "Shadowsocks 2022 UDP AES-256-GCM roundtrip" {
    const method = CipherMethod.blake3_aes_256_gcm;
    const psk = [_]u8{0x34} ** 32;
    const client_session_id = [_]u8{0x10} ** 8;
    const server_session_id = [_]u8{0x20} ** 8;
    const now: u64 = 1700000000;
    const target = Address.initDomain("one.one.one.one", 53);
    const payload = "ANOTHER DNS QUERY";

    var c2s_packet: [1024]u8 = undefined;
    const c2s_len = try encryptClientPacket(
        method,
        &psk,
        &client_session_id,
        42,
        now,
        0,
        target,
        payload,
        &c2s_packet,
        &[_]u8{},
    );

    var s_scratch: [1024]u8 = undefined;
    const s_dec = try decryptClientPacket(
        method,
        &psk,
        c2s_packet[0..c2s_len],
        now,
        &s_scratch,
    );

    try std.testing.expectEqualStrings(&client_session_id, &s_dec.session_id);
    try std.testing.expectEqual(@as(u64, 42), s_dec.packet_id);
    try std.testing.expectEqualStrings("one.one.one.one", s_dec.target.host.domain);
    try std.testing.expectEqualStrings(payload, s_dec.payload);

    var s2c_packet: [1024]u8 = undefined;
    const s2c_len = try encryptServerPacket(
        method,
        &psk,
        &server_session_id,
        99,
        &client_session_id,
        now,
        0,
        target,
        "RESPONSE FOR 256",
        &s2c_packet,
        &[_]u8{},
    );

    var c_scratch: [1024]u8 = undefined;
    const c_dec = try decryptServerPacket(
        method,
        &psk,
        s2c_packet[0..s2c_len],
        &client_session_id,
        now,
        &c_scratch,
    );

    try std.testing.expectEqualStrings(&server_session_id, &c_dec.server_session_id);
    try std.testing.expectEqualStrings(&client_session_id, &c_dec.client_session_id);
    try std.testing.expectEqualStrings("RESPONSE FOR 256", c_dec.payload);
}

test "Shadowsocks 2022 UDP ChaCha20-Poly1305 roundtrip" {
    const method = CipherMethod.blake3_chacha20_poly1305;
    const psk = [_]u8{0x56} ** 32;
    const client_session_id = [_]u8{0x77} ** 8;
    const server_session_id = [_]u8{0x88} ** 8;
    const now: u64 = 1700000000;
    const target = Address.initIp6([_]u8{ 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 }, 53);
    const payload = "IPV6 DNS QUERY";
    const nonce = [_]u8{0x99} ** 24;

    var c2s_packet: [1024]u8 = undefined;
    const c2s_len = try encryptClientPacket(
        method,
        &psk,
        &client_session_id,
        100,
        now,
        8,
        target,
        payload,
        &c2s_packet,
        &nonce,
    );

    var s_scratch: [1024]u8 = undefined;
    const s_dec = try decryptClientPacket(
        method,
        &psk,
        c2s_packet[0..c2s_len],
        now,
        &s_scratch,
    );

    try std.testing.expectEqualStrings(&client_session_id, &s_dec.session_id);
    try std.testing.expectEqual(@as(u64, 100), s_dec.packet_id);
    try std.testing.expectEqualStrings(payload, s_dec.payload);

    var s2c_packet: [1024]u8 = undefined;
    const s2c_len = try encryptServerPacket(
        method,
        &psk,
        &server_session_id,
        200,
        &client_session_id,
        now,
        0,
        target,
        "IPV6 DNS REPLY",
        &s2c_packet,
        &nonce,
    );

    var c_scratch: [1024]u8 = undefined;
    const c_dec = try decryptServerPacket(
        method,
        &psk,
        s2c_packet[0..s2c_len],
        &client_session_id,
        now,
        &c_scratch,
    );

    try std.testing.expectEqualStrings(&server_session_id, &c_dec.server_session_id);
    try std.testing.expectEqualStrings(&client_session_id, &c_dec.client_session_id);
    try std.testing.expectEqualStrings("IPV6 DNS REPLY", c_dec.payload);
}
