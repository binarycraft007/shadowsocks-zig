const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const crypto = @import("crypto.zig");
const max_salt_len = crypto.max_salt_len;
const Io = std.Io;
const Timestamp = Io.Timestamp;
const Duration = Io.Duration;

pub const max_time_difference: i64 = 30; // 30 seconds
pub const salt_cache_ttl: i64 = 60; // 60 seconds

/// Check if a Unix timestamp (in seconds) is within the valid +/- 30 second window.
/// Utilizes `std.Io.Timestamp.durationTo` and `std.Io.Duration`.
pub fn validateTimestamp(timestamp_sec: u64, now_sec: u64) bool {
    const ts = Timestamp.fromNanoseconds(@as(i96, @intCast(timestamp_sec)) * std.time.ns_per_s);
    const now_ts = Timestamp.fromNanoseconds(@as(i96, @intCast(now_sec)) * std.time.ns_per_s);
    const duration = ts.durationTo(now_ts);
    const diff_sec = duration.toSeconds();
    return diff_sec >= -max_time_difference and diff_sec <= max_time_difference;
}

/// Check if a `std.Io.Timestamp` is within the valid +/- 30 second window of `now`.
pub fn validateTimestampTs(timestamp: Timestamp, now: Timestamp) bool {
    const duration = timestamp.durationTo(now);
    const diff_sec = duration.toSeconds();
    return diff_sec >= -max_time_difference and diff_sec <= max_time_difference;
}

/// Fixed-capacity ring buffer salt cache for TCP replay protection.
/// Salts are retained for 60 seconds.
pub const SaltCache = struct {
    const Entry = struct {
        salt: [max_salt_len]u8,
        salt_len: usize,
        expire_at: i64,
        valid: bool,
    };

    const capacity: usize = 4096;
    entries: [capacity]Entry,
    head: usize = 0,

    pub fn init() SaltCache {
        return .{
            .entries = [_]Entry{.{
                .salt = undefined,
                .salt_len = 0,
                .expire_at = 0,
                .valid = false,
            }} ** capacity,
        };
    }

    /// Check if salt is present (repeated). If not present and valid, adds it and returns true.
    /// Returns false if salt was already seen (replay detected).
    pub fn checkAndAdd(self: *SaltCache, salt: []const u8, now_sec: i64) bool {
        // 1. Scan for duplicates while cleaning expired entries
        for (&self.entries) |*entry| {
            if (!entry.valid) continue;
            if (entry.expire_at <= now_sec) {
                entry.valid = false;
                continue;
            }
            if (entry.salt_len == salt.len and mem.eql(u8, entry.salt[0..salt.len], salt)) {
                return false; // Replay detected!
            }
        }

        // 2. Insert new salt
        const idx = self.head;
        self.head = (self.head + 1) % capacity;

        var target = &self.entries[idx];
        assert(salt.len <= max_salt_len);
        @memcpy(target.salt[0..salt.len], salt);
        target.salt_len = salt.len;
        target.expire_at = now_sec + salt_cache_ttl;
        target.valid = true;

        return true;
    }
};

/// 128-packet Sliding Window Anti-Replay Filter (WireGuard / RFC 6479 algorithm).
pub const SlidingWindow = struct {
    pub const window_size: u64 = 128;
    last_seq: u64 = 0,
    bitmap: u128 = 0,
    has_seen: bool = false,

    pub fn init() SlidingWindow {
        return .{
            .last_seq = 0,
            .bitmap = 0,
            .has_seen = false,
        };
    }

    /// Check if packet_id is valid and unplayed without mutating filter state.
    pub fn check(self: *const SlidingWindow, packet_id: u64) bool {
        if (!self.has_seen) return true;

        if (packet_id > self.last_seq) {
            return true; // Strictly newer packet
        }

        const diff = self.last_seq - packet_id;
        if (diff >= window_size) {
            return false; // Too old (outside sliding window)
        }

        const bit = @as(u128, 1) << @intCast(diff);
        return (self.bitmap & bit) == 0; // Valid if bit is not yet set
    }

    /// Commit a validated packet_id to the sliding window filter.
    pub fn commit(self: *SlidingWindow, packet_id: u64) void {
        if (!self.has_seen) {
            self.has_seen = true;
            self.last_seq = packet_id;
            self.bitmap = 1;
            return;
        }

        if (packet_id > self.last_seq) {
            const shift = packet_id - self.last_seq;
            if (shift < window_size) {
                self.bitmap <<= @intCast(shift);
            } else {
                self.bitmap = 0;
            }
            self.bitmap |= 1;
            self.last_seq = packet_id;
        } else {
            const diff = self.last_seq - packet_id;
            if (diff < window_size) {
                self.bitmap |= @as(u128, 1) << @intCast(diff);
            }
        }
    }
};

test "timestamp validation" {
    const now: u64 = 1000;
    try std.testing.expect(validateTimestamp(1000, now));
    try std.testing.expect(validateTimestamp(970, now));
    try std.testing.expect(validateTimestamp(1030, now));
    try std.testing.expect(!validateTimestamp(969, now));
    try std.testing.expect(!validateTimestamp(1031, now));

    const now_ts = Timestamp.fromNanoseconds(1000 * std.time.ns_per_s);
    try std.testing.expect(validateTimestampTs(Timestamp.fromNanoseconds(1000 * std.time.ns_per_s), now_ts));
    try std.testing.expect(validateTimestampTs(Timestamp.fromNanoseconds(970 * std.time.ns_per_s), now_ts));
    try std.testing.expect(validateTimestampTs(Timestamp.fromNanoseconds(1030 * std.time.ns_per_s), now_ts));
    try std.testing.expect(!validateTimestampTs(Timestamp.fromNanoseconds(969 * std.time.ns_per_s), now_ts));
    try std.testing.expect(!validateTimestampTs(Timestamp.fromNanoseconds(1031 * std.time.ns_per_s), now_ts));
}

test "salt cache replay prevention" {
    var cache = SaltCache.init();
    const salt1 = [_]u8{1} ** 16;
    const salt2 = [_]u8{2} ** 16;

    try std.testing.expect(cache.checkAndAdd(&salt1, 100));
    try std.testing.expect(cache.checkAndAdd(&salt2, 100));

    // Duplicate rejection
    try std.testing.expect(!cache.checkAndAdd(&salt1, 100));
    try std.testing.expect(!cache.checkAndAdd(&salt2, 110));

    // After expiration (TTL 60 seconds)
    try std.testing.expect(cache.checkAndAdd(&salt1, 161));
}

test "sliding window replay filter" {
    var filter = SlidingWindow.init();

    // First packet
    try std.testing.expect(filter.check(10));
    filter.commit(10);
    try std.testing.expect(!filter.check(10)); // Duplicate

    // Forward progression
    try std.testing.expect(filter.check(11));
    filter.commit(11);
    try std.testing.expect(!filter.check(11));

    // In-window out-of-order packet
    try std.testing.expect(filter.check(9));
    filter.commit(9);
    try std.testing.expect(!filter.check(9));

    // Big jump forward
    try std.testing.expect(filter.check(150));
    filter.commit(150);

    // Old packet now outside 128 window (150 - 10 = 140 >= 128)
    try std.testing.expect(!filter.check(10));

    // In-window packet (150 - 30 = 120 < 128)
    try std.testing.expect(filter.check(120));
    filter.commit(120);
    try std.testing.expect(!filter.check(120));
}
