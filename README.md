# shadowsocks-zig

A pure Zig implementation of Shadowsocks (both local SOCKS5 client and remote server) designed for **Zig 0.16.0** using the new `std.Io` asynchronous concurrency subsystem.

## Highlights

- **Shadowsocks 2022 Edition**: Full support for the modern 2022 specification family:
  - BLAKE3 Key Derivation Function (`std.crypto.hash.Blake3.initKdf`)
  - Standalone detection-prevention headers and detection probe mitigation
  - Full TCP timestamp validation ($\pm 30$s) and 60-second salt cache replay protection
  - Session-based UDP relay with separate AES block encryption and sliding window anti-replay filter
  - Shadowsocks configuration URLs (`ss://`) with percent encoding/decoding and SIP002 compatibility
- **Pure Zig**: Zero external C dependencies. No `libsodium`, `mbedtls`, `openssl`, or `libuv`.
- **Full Streaming**: Direct zero-copy piping between sockets and AEAD framing using `*std.Io.Reader` and `*std.Io.Writer`.
- **Supported Ciphers**:
  - **Shadowsocks 2022**:
    - `2022-blake3-aes-128-gcm`
    - `2022-blake3-aes-256-gcm`
    - `2022-blake3-chacha20-poly1305`
  - **Shadowsocks 2017 AEAD**:
    - `chacha20-ietf-poly1305` *(default)*
    - `aes-256-gcm`
    - `aes-128-gcm`
    - `xchacha20-ietf-poly1305`
    - `aegis-128l`
    - `aegis-256`
- **Native ZON Config**: Uses Zig Object Notation (`.zon`) files for type-safe configuration.

---

## Getting Started

### Prerequisites

- Zig `0.16.0` or later

### Build

```bash
zig build -Doptimize=ReleaseFast
```

The executable will be located at `zig-out/bin/shadowsocks`.

### Run Tests

```bash
zig build test
```

Runs all unit tests and end-to-end integration tests (testing SOCKS5 handshakes, encrypted streaming tunnels, 2022 BLAKE3 KDF, anti-replay filters, session UDP, and echo servers).

---

## Usage

### 1. Start Remote Server (2022 Edition)

```bash
shadowsocks server -p 8388 -k "t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=" -m 2022-blake3-aes-256-gcm
```

### 2. Start Local SOCKS5 Proxy (2022 Edition)

```bash
shadowsocks local -s 127.0.0.1 -p 8388 -b 127.0.0.1 -l 1080 -k "t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=" -m 2022-blake3-aes-256-gcm
```

### 3. Connect using `ss://` URL

```bash
shadowsocks local -b 127.0.0.1 -l 1080 "ss://2022-blake3-aes-256-gcm:t7XRzLCvgsH4r4r669cyqPnVNFG2c%2FHC5Tt%2BMjINJB0%3D@127.0.0.1:8388/#my_server"
```

Now configure your applications/browser to use SOCKS5 proxy `127.0.0.1:1080`.

---

## Configuration via ZON

You can also configure both client and server via a `.zon` file:

```zig
// config.zon
.{
    .mode = .local, // .local or .server
    .server_host = "127.0.0.1",
    .server_port = 8388,
    .local_host = "127.0.0.1",
    .local_port = 1080,
    .password = "t7XRzLCvgsH4r4r669cyqPnVNFG2c/HC5Tt+MjINJB0=",
    .method = .blake3_aes_256_gcm,
    .enable_udp = true,
}
```

Run with:

```bash
shadowsocks -c config.zon
```

---

## CLI Options

```
shadowsocks [local|server] [options] [ss://URL]

Commands:
  local                     Run as local SOCKS5 proxy (ss-local)
  server                    Run as remote Shadowsocks server (ss-server)

Options:
  -s, --server <host>       Server hostname or IP address (default: 127.0.0.1 / 0.0.0.0)
  -p, --port <port>         Server port number (default: 8388)
  -b, --local-addr <host>   Local bind address (default: 127.0.0.1)
  -l, --local-port <port>   Local port number (default: 1080)
  -k, --password <pass>     Password / Base64 Pre-shared key
  -m, --method <cipher>     AEAD Cipher method (default: chacha20-ietf-poly1305)
                            2022 Editions: 2022-blake3-aes-128-gcm,
                                           2022-blake3-aes-256-gcm,
                                           2022-blake3-chacha20-poly1305
                            2017 AEAD:     chacha20-ietf-poly1305, aes-256-gcm,
                                           aes-128-gcm, xchacha20-ietf-poly1305,
                                           aegis-128l, aegis-256
  -c, --config <file.zon>   ZON configuration file path
  -u, --enable-udp          Enable UDP relay
  -h, --help                Show this help message
```

---

## License

MIT

