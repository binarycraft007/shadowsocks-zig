const std = @import("std");
const mem = std.mem;
const Uri = std.Uri;
const crypto = @import("crypto.zig");
const CipherMethod = crypto.CipherMethod;

pub const ParsedUrl = struct {
    method: CipherMethod,
    password: []const u8,
    host: []const u8,
    port: u16,
    tag: ?[]const u8 = null,
};

pub const Error = error{
    InvalidScheme,
    InvalidUserInfo,
    InvalidHost,
    InvalidPort,
    InvalidMethod,
    BufferTooSmall,
    InvalidUrlEncoding,
    OutOfMemory,
};

/// Parse a Shadowsocks configuration URL using `std.Uri` (with backwards compatibility for SIP002 base64 URLs).
pub fn parseUrl(allocator: mem.Allocator, raw_url: []const u8) !ParsedUrl {
    const trimmed = mem.trim(u8, raw_url, " \t\r\n");

    // 1. Try standard RFC3986 URI parsing with std.Uri
    if (Uri.parse(trimmed)) |uri| {
        if (!mem.eql(u8, uri.scheme, "ss")) {
            return error.InvalidScheme;
        }

        // Standard Shadowsocks 2022 / SIP002 URL format: ss://method:password@host:port/#name
        if (uri.user != null and uri.password != null and uri.host != null and uri.port != null) {
            var method_buf: [64]u8 = undefined;
            const method_str = try uri.user.?.toRaw(&method_buf);
            const method = CipherMethod.fromString(method_str) orelse return error.InvalidMethod;

            var pass_buf: [1024]u8 = undefined;
            const dec_pass = try uri.password.?.toRaw(&pass_buf);
            const password = try allocator.dupe(u8, dec_pass);
            errdefer allocator.free(password);

            var host_buf: [256]u8 = undefined;
            const raw_host = try uri.host.?.toRaw(&host_buf);
            const host_clean = stripIpv6Brackets(raw_host);
            const host = try allocator.dupe(u8, host_clean);
            errdefer allocator.free(host);

            var tag: ?[]const u8 = null;
            if (uri.fragment) |frag| {
                var frag_buf: [256]u8 = undefined;
                const raw_frag = try frag.toRaw(&frag_buf);
                if (raw_frag.len > 0) {
                    tag = try allocator.dupe(u8, raw_frag);
                }
            }

            return ParsedUrl{
                .method = method,
                .password = password,
                .host = host,
                .port = uri.port.?,
                .tag = tag,
            };
        }

        // SIP002 userinfo base64: ss://BASE64(method:password)@host:port/#name
        if (uri.user != null and uri.password == null and uri.host != null and uri.port != null) {
            var user_buf: [1024]u8 = undefined;
            const user_raw = try uri.user.?.toRaw(&user_buf);
            const decoded = try decodeBase64(allocator, user_raw);
            defer allocator.free(decoded);

            const colon_idx = mem.indexOfScalar(u8, decoded, ':') orelse return error.InvalidUserInfo;
            const method_str = decoded[0..colon_idx];
            const method = CipherMethod.fromString(method_str) orelse return error.InvalidMethod;
            const password = try allocator.dupe(u8, decoded[colon_idx + 1 ..]);
            errdefer allocator.free(password);

            var host_buf: [256]u8 = undefined;
            const raw_host = try uri.host.?.toRaw(&host_buf);
            const host_clean = stripIpv6Brackets(raw_host);
            const host = try allocator.dupe(u8, host_clean);
            errdefer allocator.free(host);

            var tag: ?[]const u8 = null;
            if (uri.fragment) |frag| {
                var frag_buf: [256]u8 = undefined;
                const raw_frag = try frag.toRaw(&frag_buf);
                if (raw_frag.len > 0) {
                    tag = try allocator.dupe(u8, raw_frag);
                }
            }

            return ParsedUrl{
                .method = method,
                .password = password,
                .host = host,
                .port = uri.port.?,
                .tag = tag,
            };
        }
    } else |_| {}

    // 2. Fallback for legacy SIP002 full URL base64: ss://BASE64(method:password@host:port)[#name]
    const scheme_prefix = "ss://";
    if (!mem.startsWith(u8, trimmed, scheme_prefix)) {
        return error.InvalidScheme;
    }
    var body = trimmed[scheme_prefix.len..];

    var tag: ?[]const u8 = null;
    if (mem.indexOfScalar(u8, body, '#')) |hash_idx| {
        tag = try allocator.dupe(u8, body[hash_idx + 1 ..]);
        body = body[0..hash_idx];
    }

    const decoded = try decodeBase64(allocator, body);
    defer allocator.free(decoded);

    const at_idx = mem.lastIndexOfScalar(u8, decoded, '@') orelse return error.InvalidUserInfo;
    const userinfo = decoded[0..at_idx];
    const hostport = decoded[at_idx + 1 ..];

    const colon_idx = mem.indexOfScalar(u8, userinfo, ':') orelse return error.InvalidUserInfo;
    const method_str = userinfo[0..colon_idx];
    const method = CipherMethod.fromString(method_str) orelse return error.InvalidMethod;
    const password = try allocator.dupe(u8, userinfo[colon_idx + 1 ..]);
    errdefer allocator.free(password);

    const host_raw, const port = try parseHostPort(allocator, hostport);
    const host = host_raw;

    return ParsedUrl{
        .method = method,
        .password = password,
        .host = host,
        .port = port,
        .tag = tag,
    };
}

fn stripIpv6Brackets(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return host[1 .. host.len - 1];
    }
    return host;
}

fn decodeBase64(allocator: mem.Allocator, src: []const u8) ![]u8 {
    const url_dec = std.base64.url_safe_no_pad.Decoder;
    const std_dec = std.base64.standard.Decoder;
    const std_no_pad_dec = std.base64.standard_no_pad.Decoder;
    const url_pad_dec = std.base64.url_safe.Decoder;

    const calc_len = url_dec.calcSizeForSlice(src) catch
        std_dec.calcSizeForSlice(src) catch
        std_no_pad_dec.calcSizeForSlice(src) catch
        url_pad_dec.calcSizeForSlice(src) catch return error.InvalidUserInfo;

    const buf = try allocator.alloc(u8, calc_len);
    errdefer allocator.free(buf);

    url_dec.decode(buf, src) catch
        std_dec.decode(buf, src) catch
        std_no_pad_dec.decode(buf, src) catch
        url_pad_dec.decode(buf, src) catch return error.InvalidUserInfo;

    return buf;
}

fn parseHostPort(allocator: mem.Allocator, hostport: []const u8) !struct { []const u8, u16 } {
    if (hostport.len == 0) return error.InvalidHost;

    if (hostport[0] == '[') {
        const close_bracket = mem.indexOfScalar(u8, hostport, ']') orelse return error.InvalidHost;
        const host = try allocator.dupe(u8, hostport[1..close_bracket]);
        errdefer allocator.free(host);

        if (close_bracket + 1 >= hostport.len or hostport[close_bracket + 1] != ':') {
            return error.InvalidPort;
        }
        const port_str = hostport[close_bracket + 2 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
        return .{ host, port };
    } else {
        const colon_idx = mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.InvalidPort;
        const host = try allocator.dupe(u8, hostport[0..colon_idx]);
        errdefer allocator.free(host);

        const port_str = hostport[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
        return .{ host, port };
    }
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

fn percentEncodePassword(allocator: mem.Allocator, raw: []const u8) ![]u8 {
    var extra: usize = 0;
    for (raw) |c| {
        if (!isUnreserved(c)) {
            extra += 2;
        }
    }
    if (extra == 0) {
        return allocator.dupe(u8, raw);
    }
    const result = try allocator.alloc(u8, raw.len + extra);
    var out_idx: usize = 0;
    for (raw) |c| {
        if (isUnreserved(c)) {
            result[out_idx] = c;
            out_idx += 1;
        } else {
            const hex = "0123456789ABCDEF";
            result[out_idx] = '%';
            result[out_idx + 1] = hex[(c >> 4) & 0xF];
            result[out_idx + 2] = hex[c & 0xF];
            out_idx += 3;
        }
    }
    return result;
}

/// Format a Shadowsocks 2022 configuration URL using `std.Uri`.
pub fn formatUrl(
    allocator: mem.Allocator,
    method: CipherMethod,
    password_or_key: []const u8,
    host: []const u8,
    port: u16,
    tag: ?[]const u8,
) ![]u8 {
    const is_ipv6 = mem.indexOfScalar(u8, host, ':') != null and host[0] != '[';
    const formatted_host = if (is_ipv6)
        try std.fmt.allocPrint(allocator, "[{s}]", .{host})
    else
        host;
    defer if (is_ipv6) allocator.free(formatted_host);

    const encoded_password = try percentEncodePassword(allocator, password_or_key);
    defer allocator.free(encoded_password);

    const uri = Uri{
        .scheme = "ss",
        .user = .{ .percent_encoded = method.toString() },
        .password = .{ .percent_encoded = encoded_password },
        .host = .{ .raw = formatted_host },
        .port = port,
        .path = .{ .percent_encoded = "/" },
        .fragment = if (tag) |t| .{ .percent_encoded = t } else null,
    };

    return std.fmt.allocPrint(allocator, "{f}", .{&uri});
}

test "Shadowsocks 2022 standard URL parsing and formatting using std.Uri" {
    const allocator = std.testing.allocator;

    const url1 = "ss://2022-blake3-aes-128-gcm:5mOQSa20Kt6ay2LXruBoHQ%3D%3D@example.com:443/#name";
    const parsed1 = try parseUrl(allocator, url1);
    defer {
        allocator.free(parsed1.password);
        allocator.free(parsed1.host);
        if (parsed1.tag) |t| allocator.free(t);
    }

    try std.testing.expectEqual(CipherMethod.blake3_aes_128_gcm, parsed1.method);
    try std.testing.expectEqualStrings("5mOQSa20Kt6ay2LXruBoHQ==", parsed1.password);
    try std.testing.expectEqualStrings("example.com", parsed1.host);
    try std.testing.expectEqual(@as(u16, 443), parsed1.port);
    try std.testing.expectEqualStrings("name", parsed1.tag.?);

    const formatted1 = try formatUrl(allocator, parsed1.method, parsed1.password, parsed1.host, parsed1.port, parsed1.tag);
    defer allocator.free(formatted1);
    try std.testing.expectEqualStrings(url1, formatted1);
}

test "Shadowsocks 2022 IPv6 URL parsing and formatting using std.Uri" {
    const allocator = std.testing.allocator;

    const url2 = "ss://2022-blake3-aes-256-gcm:t7XRzLCvgsH4r4r669cyqPnVNFG2c%2FHC5Tt%2BMjINJB0%3D@[2001:db8:1f74:3c86:aef9:a75:5d2a:425e]:20220/#name";
    const parsed2 = try parseUrl(allocator, url2);
    defer {
        allocator.free(parsed2.password);
        allocator.free(parsed2.host);
        if (parsed2.tag) |t| allocator.free(t);
    }

    try std.testing.expectEqual(CipherMethod.blake3_aes_256_gcm, parsed2.method);
    try std.testing.expectEqualStrings("t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=", parsed2.password);
    try std.testing.expectEqualStrings("2001:db8:1f74:3c86:aef9:a75:5d2a:425e", parsed2.host);
    try std.testing.expectEqual(@as(u16, 20220), parsed2.port);
    try std.testing.expectEqualStrings("name", parsed2.tag.?);

    const formatted2 = try formatUrl(allocator, parsed2.method, parsed2.password, parsed2.host, parsed2.port, parsed2.tag);
    defer allocator.free(formatted2);
    try std.testing.expectEqualStrings(url2, formatted2);
}
