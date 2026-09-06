const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Ip4Address = Io.net.Ip4Address;
const Ip6Address = Io.net.Ip6Address;
const HostName = Io.net.HostName;
const Stream = Io.net.Stream;
const Address = @This();

pub const Type = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const max_domain_len = 255;
pub const max_address_wire_len = 1 + 1 + max_domain_len + 2; // 259 bytes

host: Host,
port: u16,

pub const Host = union(Type) {
    ipv4: [4]u8,
    domain: []const u8,
    ipv6: [16]u8,
};

pub fn initIp4(bytes: [4]u8, port: u16) Address {
    return .{
        .host = .{ .ipv4 = bytes },
        .port = port,
    };
}

pub fn initIp6(bytes: [16]u8, port: u16) Address {
    return .{
        .host = .{ .ipv6 = bytes },
        .port = port,
    };
}

pub fn initDomain(domain_name: []const u8, port: u16) Address {
    return .{
        .host = .{ .domain = domain_name },
        .port = port,
    };
}

pub fn fromIpAddress(ip: IpAddress) Address {
    return switch (ip) {
        .ip4 => |ip4| initIp4(ip4.bytes, ip4.port),
        .ip6 => |ip6| initIp6(ip6.bytes, ip6.port),
    };
}

/// Encode address to Shadowsocks / SOCKS5 binary format.
/// Returns the number of bytes written to `buf`.
pub fn encode(self: Address, buf: []u8) error{BufferTooSmall}!usize {
    switch (self.host) {
        .ipv4 => |ip| {
            if (buf.len < 1 + 4 + 2) return error.BufferTooSmall;
            buf[0] = @intFromEnum(Type.ipv4);
            @memcpy(buf[1..5], &ip);
            mem.writeInt(u16, buf[5..7], self.port, .big);
            return 7;
        },
        .domain => |d| {
            if (d.len > max_domain_len) return error.BufferTooSmall;
            const total = 1 + 1 + d.len + 2;
            if (buf.len < total) return error.BufferTooSmall;
            buf[0] = @intFromEnum(Type.domain);
            buf[1] = @intCast(d.len);
            @memcpy(buf[2 .. 2 + d.len], d);
            mem.writeInt(u16, buf[2 + d.len ..][0..2], self.port, .big);
            return total;
        },
        .ipv6 => |ip| {
            if (buf.len < 1 + 16 + 2) return error.BufferTooSmall;
            buf[0] = @intFromEnum(Type.ipv6);
            @memcpy(buf[1..17], &ip);
            mem.writeInt(u16, buf[17..19], self.port, .big);
            return 19;
        },
    }
}

/// Decode address from raw binary slice.
/// Returns decoded Address and number of bytes consumed.
pub fn decode(buf: []const u8) error{ InvalidAddress, Incomplete }!struct { Address, usize } {
    if (buf.len < 1) return error.Incomplete;
    const atyp: Type = switch (buf[0]) {
        0x01 => .ipv4,
        0x03 => .domain,
        0x04 => .ipv6,
        else => return error.InvalidAddress,
    };

    switch (atyp) {
        .ipv4 => {
            if (buf.len < 7) return error.Incomplete;
            var ip: [4]u8 = undefined;
            @memcpy(&ip, buf[1..5]);
            const port = mem.readInt(u16, buf[5..7], .big);
            return .{ initIp4(ip, port), 7 };
        },
        .domain => {
            if (buf.len < 2) return error.Incomplete;
            const dlen = buf[1];
            const total = 1 + 1 + @as(usize, dlen) + 2;
            if (buf.len < total) return error.Incomplete;
            const domain = buf[2 .. 2 + dlen];
            const port = mem.readInt(u16, buf[2 + dlen ..][0..2], .big);
            return .{ initDomain(domain, port), total };
        },
        .ipv6 => {
            if (buf.len < 19) return error.Incomplete;
            var ip: [16]u8 = undefined;
            @memcpy(&ip, buf[1..17]);
            const port = mem.readInt(u16, buf[17..19], .big);
            return .{ initIp6(ip, port), 19 };
        },
    }
}

/// Read address from an `Io.Reader`.
/// `domain_buffer` is used to store domain name bytes if ATYP is domain.
pub fn readFromReader(
    reader: *Io.Reader,
    domain_buffer: []u8,
) !Address {
    var atyp_buf: [1]u8 = undefined;
    try reader.readSliceAll(&atyp_buf);

    const atyp: Type = switch (atyp_buf[0]) {
        0x01 => .ipv4,
        0x03 => .domain,
        0x04 => .ipv6,
        else => return error.InvalidAddress,
    };

    switch (atyp) {
        .ipv4 => {
            var ip_port: [6]u8 = undefined;
            try reader.readSliceAll(&ip_port);
            var ip: [4]u8 = undefined;
            @memcpy(&ip, ip_port[0..4]);
            const port = mem.readInt(u16, ip_port[4..6], .big);
            return initIp4(ip, port);
        },
        .domain => {
            var len_buf: [1]u8 = undefined;
            try reader.readSliceAll(&len_buf);
            const dlen = len_buf[0];
            if (dlen > domain_buffer.len) return error.NameTooLong;
            try reader.readSliceAll(domain_buffer[0..dlen]);
            var port_buf: [2]u8 = undefined;
            try reader.readSliceAll(&port_buf);
            const port = mem.readInt(u16, &port_buf, .big);
            return initDomain(domain_buffer[0..dlen], port);
        },
        .ipv6 => {
            var ip_port: [18]u8 = undefined;
            try reader.readSliceAll(&ip_port);
            var ip: [16]u8 = undefined;
            @memcpy(&ip, ip_port[0..16]);
            const port = mem.readInt(u16, ip_port[16..18], .big);
            return initIp6(ip, port);
        },
    }
}

/// Write address to an `Io.Writer`.
pub fn writeToWriter(self: Address, writer: *Io.Writer) !void {
    var buf: [max_address_wire_len]u8 = undefined;
    const n = try self.encode(&buf);
    try writer.writeAll(buf[0..n]);
}

/// Resolve this address to an `Io.net.IpAddress` using `Io`.
pub fn resolve(self: Address, io: Io) !IpAddress {
    switch (self.host) {
        .ipv4 => |ip| {
            return .{
                .ip4 = .{
                    .bytes = ip,
                    .port = self.port,
                },
            };
        },
        .ipv6 => |ip| {
            return .{
                .ip6 = .{
                    .bytes = ip,
                    .port = self.port,
                },
            };
        },
        .domain => |domain_name| {
            // First try to parse as IP string (e.g. "127.0.0.1" or "::1")
            if (IpAddress.parse(domain_name, self.port)) |parsed_ip| {
                return parsed_ip;
            } else |_| {}

            // Use Io.net.HostName lookup
            const host_name = HostName.init(domain_name) catch return error.InvalidHostName;
            var queue_buf: [16]HostName.LookupResult = undefined;
            var queue: Io.Queue(HostName.LookupResult) = .init(&queue_buf);
            defer queue.close(io);

            var lookup_future = io.async(lookupTask, .{ host_name, io, &queue, self.port });
            defer _ = lookup_future.cancel(io) catch {};
            defer _ = lookup_future.await(io) catch {};

            var fallback_ip6: ?IpAddress = null;

            while (true) {
                const item = queue.getOne(io) catch |err| switch (err) {
                    error.Closed => break,
                    else => |e| return e,
                };
                switch (item) {
                    .address => |addr| {
                        switch (addr) {
                            .ip4 => {
                                _ = lookup_future.await(io) catch {};
                                return addr;
                            },
                            .ip6 => {
                                if (fallback_ip6 == null) fallback_ip6 = addr;
                            },
                        }
                    },
                    .canonical_name => {},
                }
            }
            _ = lookup_future.await(io) catch {};
            if (fallback_ip6) |addr| return addr;
            return error.UnknownHostName;
        },
    }
}

fn lookupTask(
    host_name: HostName,
    io: Io,
    resolved: *Io.Queue(HostName.LookupResult),
    port: u16,
) !void {
    return HostName.lookup(host_name, io, resolved, .{ .port = port });
}

/// Format address to string for logging / printing.
pub fn format(self: Address, w: *Io.Writer) !void {
    switch (self.host) {
        .ipv4 => |ip| {
            try w.print("{d}.{d}.{d}.{d}:{d}", .{ ip[0], ip[1], ip[2], ip[3], self.port });
        },
        .domain => |d| {
            try w.print("{s}:{d}", .{ d, self.port });
        },
        .ipv6 => |ip| {
            try w.print("[", .{});
            for (0..8) |i| {
                const word = mem.readInt(u16, ip[i * 2 ..][0..2], .big);
                if (i > 0) try w.print(":", .{});
                try w.print("{x}", .{word});
            }
            try w.print("]:{d}", .{self.port});
        },
    }
}
