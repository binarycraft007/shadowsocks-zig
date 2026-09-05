const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Io = std.Io;
const File = Io.File;
const CipherMethod = @import("crypto.zig").CipherMethod;
const Config = @This();

pub const Mode = enum {
    local,
    server,
};

mode: Mode = .local,
server_host: []const u8 = "127.0.0.1",
server_port: u16 = 8388,
local_host: []const u8 = "127.0.0.1",
local_port: u16 = 1080,
password: []const u8 = "barfoo!",
key: ?[]const u8 = null,
method: CipherMethod = .chacha20_ietf_poly1305,
timeout: u32 = 300,
enable_udp: bool = false,

pub const ZonSchema = struct {
    mode: ?Mode = null,
    server_host: ?[]const u8 = null,
    server: ?[]const u8 = null,
    server_port: ?u16 = null,
    local_host: ?[]const u8 = null,
    local_address: ?[]const u8 = null,
    local_port: ?u16 = null,
    password: ?[]const u8 = null,
    key: ?[]const u8 = null,
    method: ?CipherMethod = null,
    timeout: ?u32 = null,
    enable_udp: ?bool = null,
};

pub fn parseZon(allocator: Allocator, zon_text: []const u8) !Config {
    const null_terminated = try allocator.dupeZ(u8, zon_text);
    defer allocator.free(null_terminated);

    var diag: std.zon.parse.Diagnostics = .{};
    defer diag.deinit(allocator);

    const parsed = std.zon.parse.fromSliceAlloc(ZonSchema, allocator, null_terminated, &diag, .{
        .ignore_unknown_fields = true,
        .free_on_error = true,
    }) catch |err| {
        return err;
    };
    defer std.zon.parse.free(allocator, parsed);

    var cfg = Config{};
    if (parsed.mode) |m| cfg.mode = m;
    if (parsed.server_host orelse parsed.server) |s| cfg.server_host = try allocator.dupe(u8, s);
    if (parsed.server_port) |p| cfg.server_port = p;
    if (parsed.local_host orelse parsed.local_address) |a| cfg.local_host = try allocator.dupe(u8, a);
    if (parsed.local_port) |p| cfg.local_port = p;
    if (parsed.password) |pwd| cfg.password = try allocator.dupe(u8, pwd);
    if (parsed.key) |k| cfg.key = try allocator.dupe(u8, k);
    if (parsed.method) |m| cfg.method = m;
    if (parsed.timeout) |t| cfg.timeout = t;
    if (parsed.enable_udp) |u| cfg.enable_udp = u;
    return cfg;
}

pub fn loadFromFile(allocator: Allocator, io: Io, file_path: []const u8) !Config {
    const file = try Io.Dir.openFile(.cwd(), io, file_path, .{ .mode = .read_only });
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &buf);
    const content = try file_reader.interface.allocRemaining(allocator, .limited(1024 * 1024));
    defer allocator.free(content);

    return parseZon(allocator, content);
}

const url = @import("url.zig");

pub fn parseCliArgs(allocator: Allocator, io: Io, args: []const []const u8) !Config {
    var cfg = Config{};
    var i: usize = 1;

    // Check if first arg is subcommand "local" or "server"
    if (args.len > 0) {
        if (std.ascii.eqlIgnoreCase(args[0], "local")) {
            cfg.mode = .local;
            i += 1;
        } else if (std.ascii.eqlIgnoreCase(args[0], "server")) {
            cfg.mode = .server;
            i += 1;
        }
    }

    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.startsWith(u8, arg, "ss://")) {
            const parsed = try url.parseUrl(allocator, arg);
            cfg.method = parsed.method;
            cfg.password = parsed.password;
            cfg.server_host = parsed.host;
            cfg.server_port = parsed.port;
        } else if (mem.eql(u8, arg, "-c") or mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg = try loadFromFile(allocator, io, args[i]);
            break;
        } else if (mem.eql(u8, arg, "-s") or mem.eql(u8, arg, "--server")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg.server_host = args[i];
        } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg.server_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (mem.eql(u8, arg, "-b") or mem.eql(u8, arg, "--local-addr")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg.local_host = args[i];
        } else if (mem.eql(u8, arg, "-l") or mem.eql(u8, arg, "--local-port")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg.local_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (mem.eql(u8, arg, "-k") or mem.eql(u8, arg, "--password")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            cfg.password = args[i];
        } else if (mem.eql(u8, arg, "-m") or mem.eql(u8, arg, "--method")) {
            i += 1;
            if (i >= args.len) return error.MissingArgumentValue;
            if (CipherMethod.fromString(args[i])) |m| {
                cfg.method = m;
            } else {
                return error.InvalidCipherMethod;
            }
        } else if (mem.eql(u8, arg, "-u") or mem.eql(u8, arg, "--enable-udp")) {
            cfg.enable_udp = true;
        } else if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            return error.HelpRequested;
        }
    }

    return cfg;
}

test "parse zon config" {
    const zon_data =
        \\.{
        \\    .server = "1.2.3.4",
        \\    .server_port = 9999,
        \\    .local_address = "0.0.0.0",
        \\    .local_port = 1088,
        \\    .password = "my_secure_pass",
        \\    .method = .aes_256_gcm,
        \\    .timeout = 600,
        \\    .enable_udp = true,
        \\    .mode = .local,
        \\}
    ;
    const cfg = try Config.parseZon(std.testing.allocator, zon_data);
    defer {
        std.testing.allocator.free(cfg.server_host);
        std.testing.allocator.free(cfg.local_host);
        std.testing.allocator.free(cfg.password);
    }

    try std.testing.expectEqualStrings("1.2.3.4", cfg.server_host);
    try std.testing.expectEqual(@as(u16, 9999), cfg.server_port);
    try std.testing.expectEqualStrings("0.0.0.0", cfg.local_host);
    try std.testing.expectEqual(@as(u16, 1088), cfg.local_port);
    try std.testing.expectEqualStrings("my_secure_pass", cfg.password);
    try std.testing.expectEqual(CipherMethod.aes_256_gcm, cfg.method);
    try std.testing.expectEqual(@as(u32, 600), cfg.timeout);
    try std.testing.expect(cfg.enable_udp);
    try std.testing.expectEqual(Mode.local, cfg.mode);
}
