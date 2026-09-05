const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Io = std.Io;
const Address = @import("Address.zig");
const max_domain_len = Address.max_domain_len;

pub const VERSION: u8 = 0x05;

pub const AuthMethod = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable_methods = 0xFF,
};

pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

pub const ReplyStatus = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub const Request = struct {
    command: Command,
    target: Address,
};

pub const Error = error{
    InvalidVersion,
    InvalidAuthMethod,
    NoAcceptableAuthMethod,
    InvalidCommand,
    InvalidReservedByte,
    InvalidAddressType,
    InvalidAddress,
    Incomplete,
    BufferTooSmall,
};

/// Perform SOCKS5 server-side handshake on a reader/writer pair.
/// Expects client greeting and responds with NO_AUTH.
pub fn serverHandshake(reader: *Io.Reader, writer: *Io.Writer) !void {
    var header: [2]u8 = undefined;
    try reader.readSliceAll(&header);

    if (header[0] != VERSION) return error.InvalidVersion;
    const nmethods = header[1];
    if (nmethods == 0) return error.NoAcceptableAuthMethod;

    var methods: [255]u8 = undefined;
    try reader.readSliceAll(methods[0..nmethods]);

    var supports_no_auth = false;
    for (methods[0..nmethods]) |m| {
        if (m == @intFromEnum(AuthMethod.no_auth)) {
            supports_no_auth = true;
            break;
        }
    }

    if (!supports_no_auth) {
        var reply = [_]u8{ VERSION, @intFromEnum(AuthMethod.no_acceptable_methods) };
        try writer.writeAll(&reply);
        try writer.flush();
        return error.NoAcceptableAuthMethod;
    }

    var reply = [_]u8{ VERSION, @intFromEnum(AuthMethod.no_auth) };
    try writer.writeAll(&reply);
    try writer.flush();
}

/// Read a SOCKS5 request from the client after handshake.
/// `domain_buffer` stores the domain name string if ATYP is domain.
pub fn readRequest(reader: *Io.Reader, domain_buffer: []u8) !Request {
    var header: [3]u8 = undefined;
    try reader.readSliceAll(&header);

    if (header[0] != VERSION) return error.InvalidVersion;
    const cmd: Command = switch (header[1]) {
        0x01 => .connect,
        0x02 => .bind,
        0x03 => .udp_associate,
        else => return error.InvalidCommand,
    };
    if (header[2] != 0x00) return error.InvalidReservedByte;

    const target = try Address.readFromReader(reader, domain_buffer);
    return .{
        .command = cmd,
        .target = target,
    };
}

/// Send a SOCKS5 reply to the client.
pub fn sendReply(writer: *Io.Writer, status: ReplyStatus, bound_addr: Address) !void {
    var buf: [300]u8 = undefined;
    buf[0] = VERSION;
    buf[1] = @intFromEnum(status);
    buf[2] = 0x00; // RSV

    const addr_len = try bound_addr.encode(buf[3..]);
    try writer.writeAll(buf[0 .. 3 + addr_len]);
    try writer.flush();
}

/// Send a standard SOCKS5 success reply with bound address `0.0.0.0:0`.
pub fn sendSuccessReply(writer: *Io.Writer) !void {
    const default_bnd = Address.initIp4(.{ 0, 0, 0, 0 }, 0);
    try sendReply(writer, .succeeded, default_bnd);
}

/// SOCKS5 UDP header representation (RFC 1928 Section 7).
/// Format: `[RSV 2 bytes (0x00, 0x00)][FRAG 1 byte (0x00)][ATYP + ADDR + PORT][DATA]`
pub const UdpHeader = struct {
    frag: u8,
    target: Address,

    pub fn decode(packet: []const u8) !struct { UdpHeader, usize } {
        if (packet.len < 4) return error.Incomplete;
        if (packet[0] != 0x00 or packet[1] != 0x00) return error.InvalidReservedByte;
        const frag = packet[2];

        const target, const addr_len = try Address.decode(packet[3..]);
        const header_len = 3 + addr_len;
        return .{
            .{
                .frag = frag,
                .target = target,
            },
            header_len,
        };
    }

    pub fn encode(self: UdpHeader, buf: []u8) error{BufferTooSmall}!usize {
        if (buf.len < 3) return error.BufferTooSmall;
        buf[0] = 0x00;
        buf[1] = 0x00;
        buf[2] = self.frag;

        const addr_len = try self.target.encode(buf[3..]);
        return 3 + addr_len;
    }
};

test "socks5 UDP header encode and decode" {
    const target = Address.initIp4(.{ 8, 8, 8, 8 }, 53);
    const udp_hdr = UdpHeader{
        .frag = 0,
        .target = target,
    };

    var buf: [128]u8 = undefined;
    const n = try udp_hdr.encode(&buf);

    const decoded_hdr, const decoded_n = try UdpHeader.decode(buf[0..n]);
    try std.testing.expectEqual(n, decoded_n);
    try std.testing.expectEqual(udp_hdr.frag, decoded_hdr.frag);
    try std.testing.expectEqual(udp_hdr.target.port, decoded_hdr.target.port);
    try std.testing.expectEqualSlices(u8, &udp_hdr.target.host.ipv4, &decoded_hdr.target.host.ipv4);
}
