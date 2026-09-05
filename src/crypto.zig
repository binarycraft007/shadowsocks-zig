const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const assert = std.debug.assert;
const Io = std.Io;
const Blake3 = std.crypto.hash.Blake3;
const Aes128 = crypto.core.aes.Aes128;
const Aes256 = crypto.core.aes.Aes256;

pub const HkdfSha1 = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.HmacSha1);

pub const CipherMethod = enum {
    chacha20_ietf_poly1305,
    aes_256_gcm,
    aes_128_gcm,
    xchacha20_ietf_poly1305,
    aegis_128l,
    aegis_256,
    blake3_aes_128_gcm,
    blake3_aes_256_gcm,
    blake3_chacha20_poly1305,

    pub fn fromString(str: []const u8) ?CipherMethod {
        if (std.ascii.eqlIgnoreCase(str, "chacha20-ietf-poly1305") or
            std.ascii.eqlIgnoreCase(str, "chacha20-poly1305"))
        {
            return .chacha20_ietf_poly1305;
        } else if (std.ascii.eqlIgnoreCase(str, "aes-256-gcm")) {
            return .aes_256_gcm;
        } else if (std.ascii.eqlIgnoreCase(str, "aes-128-gcm")) {
            return .aes_128_gcm;
        } else if (std.ascii.eqlIgnoreCase(str, "xchacha20-ietf-poly1305") or
            std.ascii.eqlIgnoreCase(str, "xchacha20-poly1305"))
        {
            return .xchacha20_ietf_poly1305;
        } else if (std.ascii.eqlIgnoreCase(str, "aegis-128l") or
            std.ascii.eqlIgnoreCase(str, "aegis128l"))
        {
            return .aegis_128l;
        } else if (std.ascii.eqlIgnoreCase(str, "aegis-256") or
            std.ascii.eqlIgnoreCase(str, "aegis256"))
        {
            return .aegis_256;
        } else if (std.ascii.eqlIgnoreCase(str, "2022-blake3-aes-128-gcm")) {
            return .blake3_aes_128_gcm;
        } else if (std.ascii.eqlIgnoreCase(str, "2022-blake3-aes-256-gcm")) {
            return .blake3_aes_256_gcm;
        } else if (std.ascii.eqlIgnoreCase(str, "2022-blake3-chacha20-poly1305") or
            std.ascii.eqlIgnoreCase(str, "2022-blake3-chacha20-ietf-poly1305"))
        {
            return .blake3_chacha20_poly1305;
        }
        return null;
    }

    pub fn toString(self: CipherMethod) []const u8 {
        return switch (self) {
            .chacha20_ietf_poly1305 => "chacha20-ietf-poly1305",
            .aes_256_gcm => "aes-256-gcm",
            .aes_128_gcm => "aes-128-gcm",
            .xchacha20_ietf_poly1305 => "xchacha20-ietf-poly1305",
            .aegis_128l => "aegis-128l",
            .aegis_256 => "aegis-256",
            .blake3_aes_128_gcm => "2022-blake3-aes-128-gcm",
            .blake3_aes_256_gcm => "2022-blake3-aes-256-gcm",
            .blake3_chacha20_poly1305 => "2022-blake3-chacha20-poly1305",
        };
    }

    pub fn name(self: CipherMethod) []const u8 {
        return self.toString();
    }

    pub fn is2022(self: CipherMethod) bool {
        return switch (self) {
            .blake3_aes_128_gcm, .blake3_aes_256_gcm, .blake3_chacha20_poly1305 => true,
            else => false,
        };
    }

    pub fn keyLength(self: CipherMethod) usize {
        return switch (self) {
            .chacha20_ietf_poly1305 => 32,
            .aes_256_gcm => 32,
            .aes_128_gcm => 16,
            .xchacha20_ietf_poly1305 => 32,
            .aegis_128l => 16,
            .aegis_256 => 32,
            .blake3_aes_128_gcm => 16,
            .blake3_aes_256_gcm => 32,
            .blake3_chacha20_poly1305 => 32,
        };
    }

    pub fn saltLength(self: CipherMethod) usize {
        return self.keyLength();
    }

    pub fn nonceLength(self: CipherMethod) usize {
        return switch (self) {
            .chacha20_ietf_poly1305 => 12,
            .aes_256_gcm => 12,
            .aes_128_gcm => 12,
            .xchacha20_ietf_poly1305 => 24,
            .aegis_128l => 16,
            .aegis_256 => 32,
            .blake3_aes_128_gcm => 12,
            .blake3_aes_256_gcm => 12,
            .blake3_chacha20_poly1305 => 12,
        };
    }

    pub fn tagLength(self: CipherMethod) usize {
        return switch (self) {
            .chacha20_ietf_poly1305 => 16,
            .aes_256_gcm => 16,
            .aes_128_gcm => 16,
            .xchacha20_ietf_poly1305 => 16,
            .aegis_128l => 16,
            .aegis_256 => 16,
            .blake3_aes_128_gcm => 16,
            .blake3_aes_256_gcm => 16,
            .blake3_chacha20_poly1305 => 16,
        };
    }
};

pub const max_key_len = 32;
pub const max_salt_len = 32;
pub const max_nonce_len = 32;
pub const tag_len = 16;
pub const max_chunk_payload_len = 0xFFFF; // Up to 65535 bytes in 2022 edition (0x3FFF for 2017)

pub const Error = error{
    AuthenticationFailed,
    InvalidKeyLength,
    InvalidSaltLength,
    InvalidNonceLength,
    InvalidTagLength,
    InvalidPayloadLength,
    BufferTooSmall,
};

/// Increment a counting nonce as a little-endian unsigned integer (u96le).
pub fn incrementNonce(nonce: []u8) void {
    var c: u16 = 1;
    for (nonce) |*b| {
        c += @as(u16, b.*);
        b.* = @truncate(c);
        c >>= 8;
        if (c == 0) break;
    }
}

/// Key derivation from password using EVP_BytesToKey (MD5).
pub fn deriveKeyFromPassword(password: []const u8, key: []u8) void {
    var digest: [16]u8 = undefined;
    var written: usize = 0;
    var first = true;
    while (written < key.len) {
        var h = crypto.hash.Md5.init(.{});
        if (!first) {
            h.update(&digest);
        }
        h.update(password);
        h.final(&digest);
        first = false;

        const to_copy = @min(digest.len, key.len - written);
        @memcpy(key[written..][0..to_copy], digest[0..to_copy]);
        written += to_copy;
    }
}

pub const subkey_info = "ss-subkey";

/// Derive a session subkey from master key and salt using HKDF-SHA1 (Shadowsocks 2017 AEAD).
pub fn deriveSubkey(master_key: []const u8, salt: []const u8, subkey: []u8) void {
    const prk = HkdfSha1.extract(salt, master_key);
    HkdfSha1.expand(subkey, subkey_info, prk);
}

pub const subkey_2022_context = "shadowsocks 2022 session subkey";
pub const identity_2022_context = "shadowsocks 2022 identity subkey";

/// Derive a session subkey using BLAKE3 KDF (Shadowsocks 2022 Edition).
pub fn deriveSubkey2022(key: []const u8, salt: []const u8, subkey: []u8) void {
    var b3 = Blake3.initKdf(subkey_2022_context, .{});
    b3.update(key);
    b3.update(salt);
    b3.final(subkey);
}

/// Derive an identity subkey using BLAKE3 KDF (Shadowsocks 2022-2 Extensible Identity Headers).
pub fn deriveIdentitySubkey2022(ipsk: []const u8, salt: []const u8, subkey: []u8) void {
    var b3 = Blake3.initKdf(identity_2022_context, .{});
    b3.update(ipsk);
    b3.update(salt);
    b3.final(subkey);
}

/// Encrypt a 16-byte block with AES-128 or AES-256 (for Shadowsocks 2022 separate UDP header / identity header).
pub fn aesBlockEncrypt(key: []const u8, in: *const [16]u8, out: *[16]u8) void {
    if (key.len == 16) {
        const ctx = Aes128.initEnc(key[0..16].*);
        ctx.encrypt(out, in);
    } else if (key.len == 32) {
        const ctx = Aes256.initEnc(key[0..32].*);
        ctx.encrypt(out, in);
    } else {
        unreachable;
    }
}

/// Decrypt a 16-byte block with AES-128 or AES-256 (for Shadowsocks 2022 separate UDP header / identity header).
pub fn aesBlockDecrypt(key: []const u8, in: *const [16]u8, out: *[16]u8) void {
    if (key.len == 16) {
        const ctx = Aes128.initDec(key[0..16].*);
        ctx.decrypt(out, in);
    } else if (key.len == 32) {
        const ctx = Aes256.initDec(key[0..32].*);
        ctx.decrypt(out, in);
    } else {
        unreachable;
    }
}

/// Parse or derive master key from user input (supports base64 PSK for 2022 or raw password).
pub fn parseOrDeriveKey(method: CipherMethod, pass_or_b64: []const u8, out_key: []u8) !void {
    const klen = method.keyLength();
    assert(out_key.len >= klen);
    if (method.is2022()) {
        if (pass_or_b64.len == klen) {
            @memcpy(out_key[0..klen], pass_or_b64);
            return;
        }
        const decoder = std.base64.standard.Decoder;
        const decoded_len = decoder.calcSizeForSlice(pass_or_b64) catch return error.InvalidKeyLength;
        if (decoded_len != klen) return error.InvalidKeyLength;
        try decoder.decode(out_key[0..klen], pass_or_b64);
    } else {
        if (pass_or_b64.len == klen) {
            @memcpy(out_key[0..klen], pass_or_b64);
        } else {
            deriveKeyFromPassword(pass_or_b64, out_key[0..klen]);
        }
    }
}

/// Generic one-shot AEAD encrypt function.
pub fn aeadEncrypt(
    method: CipherMethod,
    subkey: []const u8,
    nonce: []const u8,
    ad: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[tag_len]u8,
) void {
    assert(ciphertext.len == plaintext.len);
    switch (method) {
        .chacha20_ietf_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .aes_256_gcm => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .aes_128_gcm => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes128Gcm.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .xchacha20_ietf_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [24]u8 = undefined;
            @memcpy(&n, nonce[0..24]);
            crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .aegis_128l => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [16]u8 = undefined;
            @memcpy(&n, nonce[0..16]);
            crypto.aead.aegis.Aegis128L.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .aegis_256 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [32]u8 = undefined;
            @memcpy(&n, nonce[0..32]);
            crypto.aead.aegis.Aegis256.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .blake3_aes_128_gcm => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes128Gcm.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .blake3_aes_256_gcm => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
        .blake3_chacha20_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(ciphertext, tag, plaintext, ad, n, k);
        },
    }
}

/// Generic one-shot AEAD decrypt function.
pub fn aeadDecrypt(
    method: CipherMethod,
    subkey: []const u8,
    nonce: []const u8,
    ad: []const u8,
    ciphertext: []const u8,
    tag: [tag_len]u8,
    plaintext: []u8,
) Error!void {
    assert(ciphertext.len == plaintext.len);
    switch (method) {
        .chacha20_ietf_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .aes_256_gcm => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .aes_128_gcm => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes128Gcm.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .xchacha20_ietf_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [24]u8 = undefined;
            @memcpy(&n, nonce[0..24]);
            crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .aegis_128l => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [16]u8 = undefined;
            @memcpy(&n, nonce[0..16]);
            crypto.aead.aegis.Aegis128L.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .aegis_256 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [32]u8 = undefined;
            @memcpy(&n, nonce[0..32]);
            crypto.aead.aegis.Aegis256.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .blake3_aes_128_gcm => {
            var k: [16]u8 = undefined;
            @memcpy(&k, subkey[0..16]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes128Gcm.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .blake3_aes_256_gcm => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
        .blake3_chacha20_poly1305 => {
            var k: [32]u8 = undefined;
            @memcpy(&k, subkey[0..32]);
            var n: [12]u8 = undefined;
            @memcpy(&n, nonce[0..12]);
            crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, ad, n, k) catch {
                return error.AuthenticationFailed;
            };
        },
    }
}

/// State for a unidirectional TCP or session stream.
pub const StreamCipherState = struct {
    method: CipherMethod,
    subkey: [max_key_len]u8,
    nonce: [max_nonce_len]u8,

    pub fn init(method: CipherMethod, master_key: []const u8, salt: []const u8) StreamCipherState {
        var state: StreamCipherState = .{
            .method = method,
            .subkey = undefined,
            .nonce = [_]u8{0} ** max_nonce_len,
        };
        const klen = method.keyLength();
        if (method.is2022()) {
            deriveSubkey2022(master_key, salt, state.subkey[0..klen]);
        } else {
            deriveSubkey(master_key, salt, state.subkey[0..klen]);
        }
        return state;
    }

    /// Encrypt a standalone message/chunk (e.g. Shadowsocks 2022 fixed/variable headers).
    /// Output buffer must have capacity of at least `plaintext.len + tag_len`.
    /// Returns total ciphertext length written (`plaintext.len + tag_len`).
    pub fn encryptMessage(self: *StreamCipherState, plaintext: []const u8, out: []u8) Error!usize {
        const total = plaintext.len + tag_len;
        if (out.len < total) return error.BufferTooSmall;

        const klen = self.method.keyLength();
        const nlen = self.method.nonceLength();

        var tag: [tag_len]u8 = undefined;
        aeadEncrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            plaintext,
            out[0..plaintext.len],
            &tag,
        );
        @memcpy(out[plaintext.len..][0..tag_len], &tag);
        incrementNonce(self.nonce[0..nlen]);
        return total;
    }

    /// Decrypt a standalone message/chunk (e.g. Shadowsocks 2022 fixed/variable headers).
    /// `ciphertext_with_tag` must be at least `tag_len` bytes.
    /// `out_plaintext` must have capacity of at least `ciphertext_with_tag.len - tag_len`.
    /// Returns decrypted plaintext length.
    pub fn decryptMessage(self: *StreamCipherState, ciphertext_with_tag: []const u8, out_plaintext: []u8) Error!usize {
        if (ciphertext_with_tag.len < tag_len) return error.InvalidPayloadLength;
        const plen = ciphertext_with_tag.len - tag_len;
        if (out_plaintext.len < plen) return error.BufferTooSmall;

        const klen = self.method.keyLength();
        const nlen = self.method.nonceLength();

        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, ciphertext_with_tag[plen..][0..tag_len]);

        try aeadDecrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            ciphertext_with_tag[0..plen],
            tag,
            out_plaintext[0..plen],
        );
        incrementNonce(self.nonce[0..nlen]);
        return plen;
    }

    /// Encrypt a single TCP chunk.
    /// Output buffer must have capacity of at least `2 + tag_len + payload.len + tag_len` = `payload.len + 34` bytes.
    /// Returns the total bytes written to `out`.
    pub fn encryptChunk(self: *StreamCipherState, payload: []const u8, out: []u8) Error!usize {
        if (payload.len > max_chunk_payload_len) return error.InvalidPayloadLength;
        const total_len = 2 + tag_len + payload.len + tag_len;
        if (out.len < total_len) return error.BufferTooSmall;

        const klen = self.method.keyLength();
        const nlen = self.method.nonceLength();

        // 1. Encrypt 2-byte big-endian length
        var len_buf: [2]u8 = undefined;
        mem.writeInt(u16, &len_buf, @intCast(payload.len), .big);
        var len_tag: [tag_len]u8 = undefined;

        aeadEncrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            &len_buf,
            out[0..2],
            &len_tag,
        );
        @memcpy(out[2..][0..tag_len], &len_tag);
        incrementNonce(self.nonce[0..nlen]);

        // 2. Encrypt payload
        var payload_tag: [tag_len]u8 = undefined;
        const payload_out = out[2 + tag_len ..][0..payload.len];

        aeadEncrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            payload,
            payload_out,
            &payload_tag,
        );
        @memcpy(out[2 + tag_len + payload.len ..][0..tag_len], &payload_tag);
        incrementNonce(self.nonce[0..nlen]);

        return total_len;
    }

    /// Decrypt 2-byte chunk length header (must be 18 bytes: 2 bytes ciphertext + 16 bytes tag).
    pub fn decryptLength(self: *StreamCipherState, len_header: []const u8) Error!u16 {
        if (len_header.len != 2 + tag_len) return error.InvalidPayloadLength;

        const klen = self.method.keyLength();
        const nlen = self.method.nonceLength();

        var len_buf: [2]u8 = undefined;
        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, len_header[2..][0..tag_len]);

        try aeadDecrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            len_header[0..2],
            tag,
            &len_buf,
        );
        incrementNonce(self.nonce[0..nlen]);

        const plen = mem.readInt(u16, &len_buf, .big);
        if (plen > max_chunk_payload_len) return error.InvalidPayloadLength;
        return plen;
    }

    /// Decrypt chunk payload (must be `payload_len + 16` bytes: ciphertext + tag).
    pub fn decryptPayload(self: *StreamCipherState, payload_data: []const u8, out_plaintext: []u8) Error!void {
        if (payload_data.len < tag_len) return error.InvalidPayloadLength;
        const plen = payload_data.len - tag_len;
        if (out_plaintext.len < plen) return error.BufferTooSmall;

        const klen = self.method.keyLength();
        const nlen = self.method.nonceLength();

        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, payload_data[plen..][0..tag_len]);

        try aeadDecrypt(
            self.method,
            self.subkey[0..klen],
            self.nonce[0..nlen],
            "",
            payload_data[0..plen],
            tag,
            out_plaintext[0..plen],
        );
        incrementNonce(self.nonce[0..nlen]);
    }
};

/// Encrypt a single UDP datagram: `[salt (salt_len bytes)][ciphertext][tag (16 bytes)]`.
pub fn encryptUdpPacket(
    method: CipherMethod,
    master_key: []const u8,
    salt: []const u8,
    plaintext: []const u8,
    out: []u8,
) Error!usize {
    const slen = method.saltLength();
    const klen = method.keyLength();
    const nlen = method.nonceLength();
    const total_len = slen + plaintext.len + tag_len;
    if (out.len < total_len) return error.BufferTooSmall;

    @memcpy(out[0..slen], salt);

    var subkey: [max_key_len]u8 = undefined;
    deriveSubkey(master_key, salt, subkey[0..klen]);

    const zero_nonce = [_]u8{0} ** max_nonce_len;
    var tag: [tag_len]u8 = undefined;

    aeadEncrypt(
        method,
        subkey[0..klen],
        zero_nonce[0..nlen],
        "",
        plaintext,
        out[slen..][0..plaintext.len],
        &tag,
    );
    @memcpy(out[slen + plaintext.len ..][0..tag_len], &tag);

    return total_len;
}

/// Decrypt a single UDP datagram: `[salt (salt_len bytes)][ciphertext][tag (16 bytes)]`.
pub fn decryptUdpPacket(
    method: CipherMethod,
    master_key: []const u8,
    packet: []const u8,
    out_plaintext: []u8,
) Error!usize {
    const slen = method.saltLength();
    const klen = method.keyLength();
    const nlen = method.nonceLength();

    if (packet.len < slen + tag_len) return error.InvalidPayloadLength;
    const plen = packet.len - slen - tag_len;
    if (out_plaintext.len < plen) return error.BufferTooSmall;

    const salt = packet[0..slen];
    var subkey: [max_key_len]u8 = undefined;
    deriveSubkey(master_key, salt, subkey[0..klen]);

    const zero_nonce = [_]u8{0} ** max_nonce_len;
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, packet[slen + plen ..][0..tag_len]);

    try aeadDecrypt(
        method,
        subkey[0..klen],
        zero_nonce[0..nlen],
        "",
        packet[slen..][0..plen],
        tag,
        out_plaintext[0..plen],
    );

    return plen;
}

test "nonce increment" {
    var nonce = [_]u8{0} ** 12;
    incrementNonce(&nonce);
    try std.testing.expectEqual(@as(u8, 1), nonce[0]);
    try std.testing.expectEqual(@as(u8, 0), nonce[1]);

    nonce[0] = 255;
    incrementNonce(&nonce);
    try std.testing.expectEqual(@as(u8, 0), nonce[0]);
    try std.testing.expectEqual(@as(u8, 1), nonce[1]);
}

test "key derivation" {
    var key: [32]u8 = undefined;
    deriveKeyFromPassword("secret_password_123", &key);
    // Ensure key is populated and deterministic
    var key2: [32]u8 = undefined;
    deriveKeyFromPassword("secret_password_123", &key2);
    try std.testing.expectEqualSlices(u8, &key, &key2);
}

test "AEAD chunk encryption/decryption roundtrip for all ciphers" {
    const methods = [_]CipherMethod{
        .chacha20_ietf_poly1305,
        .aes_256_gcm,
        .aes_128_gcm,
        .xchacha20_ietf_poly1305,
        .aegis_128l,
        .aegis_256,
    };

    for (methods) |m| {
        const klen = m.keyLength();
        const slen = m.saltLength();

        var master_key: [max_key_len]u8 = undefined;
        deriveKeyFromPassword("test_password", master_key[0..klen]);

        var salt: [max_salt_len]u8 = undefined;
        @memset(salt[0..slen], 0x42);

        var enc_state = StreamCipherState.init(m, master_key[0..klen], salt[0..slen]);
        var dec_state = StreamCipherState.init(m, master_key[0..klen], salt[0..slen]);

        const msg = "Hello Shadowsocks from pure Zig 0.16.0!";
        var enc_buf: [1024]u8 = undefined;
        const total_enc = try enc_state.encryptChunk(msg, &enc_buf);

        // Decrypt length header
        const plen = try dec_state.decryptLength(enc_buf[0 .. 2 + tag_len]);
        try std.testing.expectEqual(@as(u16, msg.len), plen);

        // Decrypt payload
        var dec_buf: [1024]u8 = undefined;
        try dec_state.decryptPayload(enc_buf[2 + tag_len .. total_enc], &dec_buf);
        try std.testing.expectEqualStrings(msg, dec_buf[0..plen]);
    }
}

test "UDP packet encryption/decryption roundtrip" {
    const methods = [_]CipherMethod{
        .chacha20_ietf_poly1305,
        .aes_256_gcm,
        .aes_128_gcm,
        .xchacha20_ietf_poly1305,
    };

    for (methods) |m| {
        const klen = m.keyLength();
        const slen = m.saltLength();

        var master_key: [max_key_len]u8 = undefined;
        deriveKeyFromPassword("udp_secret", master_key[0..klen]);

        var salt: [max_salt_len]u8 = undefined;
        std.testing.io.random(salt[0..slen]);

        const msg = "UDP datagram payload content";
        var packet_buf: [1024]u8 = undefined;
        const packet_len = try encryptUdpPacket(m, master_key[0..klen], salt[0..slen], msg, &packet_buf);

        var dec_buf: [1024]u8 = undefined;
        const dec_len = try decryptUdpPacket(m, master_key[0..klen], packet_buf[0..packet_len], &dec_buf);
        try std.testing.expectEqualStrings(msg, dec_buf[0..dec_len]);
    }
}

test "Shadowsocks 2022 BLAKE3 KDF and AES block encryption" {
    // 1. BLAKE3 KDF
    const key = [_]u8{0x12} ** 16;
    const salt = [_]u8{0x34} ** 16;
    var subkey1: [16]u8 = undefined;
    deriveSubkey2022(&key, &salt, &subkey1);

    var subkey2: [16]u8 = undefined;
    deriveSubkey2022(&key, &salt, &subkey2);
    try std.testing.expectEqualSlices(u8, &subkey1, &subkey2);

    // 2. AES-128 Block
    const block_in = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    var block_enc: [16]u8 = undefined;
    var block_dec: [16]u8 = undefined;
    aesBlockEncrypt(&key, &block_in, &block_enc);
    aesBlockDecrypt(&key, &block_enc, &block_dec);
    try std.testing.expectEqualSlices(u8, &block_in, &block_dec);

    // 3. AES-256 Block
    const key256 = [_]u8{0x56} ** 32;
    var block_enc256: [16]u8 = undefined;
    var block_dec256: [16]u8 = undefined;
    aesBlockEncrypt(&key256, &block_in, &block_enc256);
    aesBlockDecrypt(&key256, &block_enc256, &block_dec256);
    try std.testing.expectEqualSlices(u8, &block_in, &block_dec256);
}

test "Shadowsocks 2022 StreamCipherState message encryption/decryption" {
    const methods_2022 = [_]CipherMethod{
        .blake3_aes_128_gcm,
        .blake3_aes_256_gcm,
        .blake3_chacha20_poly1305,
    };

    for (methods_2022) |m| {
        const klen = m.keyLength();
        const slen = m.saltLength();

        var psk: [max_key_len]u8 = undefined;
        @memset(psk[0..klen], 0x77);

        var salt: [max_salt_len]u8 = undefined;
        @memset(salt[0..slen], 0x88);

        var sender = StreamCipherState.init(m, psk[0..klen], salt[0..slen]);
        var receiver = StreamCipherState.init(m, psk[0..klen], salt[0..slen]);

        // Standalone message 1 (e.g. fixed header)
        const header1 = "FixedLengthHdr11B";
        var enc_hdr1: [64]u8 = undefined;
        const n1 = try sender.encryptMessage(header1, &enc_hdr1);

        var dec_hdr1: [64]u8 = undefined;
        const dn1 = try receiver.decryptMessage(enc_hdr1[0..n1], &dec_hdr1);
        try std.testing.expectEqualStrings(header1, dec_hdr1[0..dn1]);

        // Standalone message 2 (e.g. variable header)
        const header2 = "VariableLengthTargetHeaderWithPadding!";
        var enc_hdr2: [128]u8 = undefined;
        const n2 = try sender.encryptMessage(header2, &enc_hdr2);

        var dec_hdr2: [128]u8 = undefined;
        const dn2 = try receiver.decryptMessage(enc_hdr2[0..n2], &dec_hdr2);
        try std.testing.expectEqualStrings(header2, dec_hdr2[0..dn2]);

        // Standard chunk stream payload
        const payload = "Continuous stream chunk payload data in 2022 format";
        var chunk_enc: [256]u8 = undefined;
        const cn = try sender.encryptChunk(payload, &chunk_enc);

        const plen = try receiver.decryptLength(chunk_enc[0 .. 2 + tag_len]);
        try std.testing.expectEqual(@as(u16, payload.len), plen);

        var dec_payload: [256]u8 = undefined;
        try receiver.decryptPayload(chunk_enc[2 + tag_len .. cn], &dec_payload);
        try std.testing.expectEqualStrings(payload, dec_payload[0..plen]);
    }
}
