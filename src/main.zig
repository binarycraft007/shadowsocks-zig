const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;

const shadowsocks = @import("shadowsocks");
const Address = shadowsocks.Address;
const Config = shadowsocks.Config;
const Local = shadowsocks.Local;
const Server = shadowsocks.Server;

const usage =
    \\shadowsocks [local|server] [options] [ss://URL]
    \\
    \\Commands:
    \\  local                     Run as local SOCKS5 proxy (ss-local)
    \\  server                    Run as remote Shadowsocks server (ss-server)
    \\
    \\Options:
    \\  -s, --server <host>       Server hostname or IP address (default: 127.0.0.1 / 0.0.0.0)
    \\  -p, --port <port>         Server port number (default: 8388)
    \\  -b, --local-addr <host>   Local bind address (default: 127.0.0.1)
    \\  -l, --local-port <port>   Local port number (default: 1080)
    \\  -k, --password <pass>     Password / Base64 Pre-shared key
    \\  -m, --method <cipher>     AEAD Cipher method (default: chacha20-ietf-poly1305)
    \\                            2022 Editions: 2022-blake3-aes-128-gcm,
    \\                                           2022-blake3-aes-256-gcm,
    \\                                           2022-blake3-chacha20-poly1305
    \\                            2017 AEAD:     chacha20-ietf-poly1305, aes-256-gcm,
    \\                                           aes-128-gcm, xchacha20-ietf-poly1305,
    \\                                           aegis-128l, aegis-256
    \\  -c, --config <file.zon>   ZON configuration file path
    \\  -u, --enable-udp          Enable UDP relay
    \\  -h, --help                Show this help message
    \\
;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);

    if (args.len < 2) fatal("{s}", .{usage});

    const cfg = Config.parseCliArgs(arena, io, args) catch |err| switch (err) {
        error.HelpRequested => {
            try Io.File.stdout().writeStreamingAll(io, usage);
            return std.process.cleanExit(io);
        },
        else => |e| return e,
    };

    switch (cfg.mode) {
        .local => {
            const bind_addr = Address.initDomain(cfg.local_host, cfg.local_port);
            const bind_ip = bind_addr.resolve(io) catch |err| {
                std.log.err("Failed to resolve local address {s}:{d}: {any}", .{ cfg.local_host, cfg.local_port, err });
                return err;
            };

            const key_or_pass = cfg.key orelse cfg.password;
            const local_instance = Local.init(
                bind_ip,
                cfg.server_host,
                cfg.server_port,
                cfg.method,
                key_or_pass,
                cfg.enable_udp,
            );

            std.log.info("Starting Shadowsocks SOCKS5 local proxy on {s}:{d} -> remote {s}:{d} ({s})", .{
                cfg.local_host,
                cfg.local_port,
                cfg.server_host,
                cfg.server_port,
                cfg.method.name(),
            });

            try local_instance.listenAndServe(io);
        },
        .server => {
            const bind_addr = Address.initDomain(cfg.server_host, cfg.server_port);
            const bind_ip = bind_addr.resolve(io) catch |err| {
                std.log.err("Failed to resolve server bind address {s}:{d}: {any}", .{ cfg.server_host, cfg.server_port, err });
                return err;
            };

            const key_or_pass = cfg.key orelse cfg.password;
            const server_instance = Server.init(
                bind_ip,
                cfg.method,
                key_or_pass,
                cfg.enable_udp,
            );

            std.log.info("Starting Shadowsocks remote server on {s}:{d} ({s})", .{
                cfg.server_host,
                cfg.server_port,
                cfg.method.name(),
            });

            try server_instance.listenAndServe(io);
        },
    }
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(format, args);
    std.process.exit(1);
}
