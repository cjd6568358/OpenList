//! 日历算术与两种上游要的日期格式。
//!
//! `std` 里没有日历格式化也没有 `strftime`，而这个工程有**三个**驱动需要它：
//!
//!   * `115_open` —— OSS 的 `Date` 头是 V1 签名材料的一部分，必须精确按
//!     Go 的 `http.TimeFormat` 输出；
//!   * `aliyundrive_open` —— `local_modified_at` / `local_created_at` 要
//!     `2006-01-02T15:04:05.000Z`；
//!   * `123_open` —— 反过来，要**解析** `2006-01-02 15:04:05`。
//!
//! 三处共用同一份 `daysFromCivil` / `civilFromDays`（Howard Hinnant 的
//! `chrono` 算法），所以放在这里而不是各驱动抄一遍 —— 抄一遍就多一份
//! 出错的机会，而且 xz 之后体积也是实打实的两份。

const std = @import("std");
const Buf = @import("buf.zig").Buf;

pub const SECONDS_PER_DAY: i64 = 86400;

/// 民用历 → Unix 日数。对 1970 年之前也成立（虽然这里用不到）。
pub fn daysFromCivil(y_in: i64, m: i64, d: i64) i64 {
    const y = if (m <= 2) y_in - 1 else y_in;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const doy = @divTrunc(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + d - 1; // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return era * 146097 + doe - 719468;
}

pub const Civil = struct { y: i64, m: i64, d: i64 };

/// Unix 日数 → 民用历（`daysFromCivil` 的逆）。
pub fn civilFromDays(z_in: i64) Civil {
    const z = z_in + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097; // [0, 146096]
    const yoe = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36524) - @divTrunc(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp = @divTrunc(5 * doy + 2, 153);
    const d = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    return .{ .y = if (m <= 2) y + 1 else y, .m = m, .d = d };
}

pub fn isLeap(y: i64) bool {
    return (@mod(y, 4) == 0 and @mod(y, 100) != 0) or @mod(y, 400) == 0;
}

pub fn daysInMonth(y: i64, m: i64) i64 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeap(y)) 29 else 28,
        else => 0,
    };
}

/// 把一天内的秒数拆成 (时, 分, 秒)。
const Hms = struct { h: i64, m: i64, s: i64 };

fn splitSeconds(secs_in_day: i64) Hms {
    return .{
        .h = @divTrunc(secs_in_day, 3600),
        .m = @divTrunc(@mod(secs_in_day, 3600), 60),
        .s = @mod(secs_in_day, 60),
    };
}

/// 把 0..7 的星期序号映射成名字，1970-01-01 是星期四。
const weekday_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
const month_names = [_][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

/// Go 的 `time.Time.UTC().Format(http.TimeFormat)`，
/// 即 `Mon, 02 Jan 2006 15:04:05 GMT`。
///
/// 注意：`{d:0>2}` 对**有符号**整数会把符号位算进宽度，打出 `+1` 而不是 `01`
/// —— 所以每个数字都要先转成无符号。
pub fn formatHttpDate(b: *Buf, unix_s: i64) !void {
    const days = @divFloor(unix_s, SECONDS_PER_DAY);
    const c = civilFromDays(days);
    const t = splitSeconds(@mod(unix_s, SECONDS_PER_DAY));
    const wd: usize = @intCast(@mod(days, 7));
    try b.print("{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        weekday_names[wd],
        @as(u32, @intCast(c.d)),
        month_names[@intCast(c.m - 1)],
        @as(u32, @intCast(c.y)),
        @as(u32, @intCast(t.h)),
        @as(u32, @intCast(t.m)),
        @as(u32, @intCast(t.s)),
    });
}

/// 阿里云盘要的 `2006-01-02T15:04:05.000Z` 形状（UTC，毫秒恒为 `000`）。
///
/// 上游用 Go 的 `time.Format`，`.000` 是**字面量**而不是"截断到毫秒"——
/// 秒后面固定跟三个 0。这里照抄，不引入毫秒参数。
pub fn formatIsoMillisZ(b: *Buf, unix_s: i64) !void {
    const days = @divFloor(unix_s, SECONDS_PER_DAY);
    const c = civilFromDays(days);
    const t = splitSeconds(@mod(unix_s, SECONDS_PER_DAY));
    try b.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.000Z", .{
        @as(u32, @intCast(c.y)),
        @as(u32, @intCast(c.m)),
        @as(u32, @intCast(c.d)),
        @as(u32, @intCast(t.h)),
        @as(u32, @intCast(t.m)),
        @as(u32, @intCast(t.s)),
    });
}

/// 解析 RFC3339（`2026-10-10T12:34:56Z` / `+08:00` / 带小数秒），返回 Unix 秒。
///
/// 123pan 的 `data.expiredAt` 与阿里云盘的 `created_at`/`updated_at` 都是这个
/// 形状。**没有时区标记的一律拒绝** —— Go 的 `time.Parse(time.RFC3339, ...)`
/// 也是这么做的，猜一个时区只会把时间算错而不报错。
pub fn parseRfc3339(s: []const u8) ?i64 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len < 20) return null;
    if (t[4] != '-' or t[7] != '-' or (t[10] != 'T' and t[10] != ' ')) return null;
    if (t[13] != ':' or t[16] != ':') return null;

    const y = std.fmt.parseInt(i64, t[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(i64, t[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, t[8..10], 10) catch return null;
    const h = std.fmt.parseInt(i64, t[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, t[14..16], 10) catch return null;
    const se = std.fmt.parseInt(i64, t[17..19], 10) catch return null;
    if (mo < 1 or mo > 12) return null;
    if (d < 1 or d > daysInMonth(y, mo)) return null;
    if (h > 23 or mi > 59 or se > 60) return null;

    // 跳过小数秒。
    var i: usize = 19;
    if (i < t.len and t[i] == '.') {
        i += 1;
        while (i < t.len and std.ascii.isDigit(t[i])) i += 1;
    }
    if (i >= t.len) return null;

    var offset: i64 = 0;
    switch (t[i]) {
        'Z', 'z' => {
            if (i + 1 != t.len) return null;
        },
        '+', '-' => {
            const sign: i64 = if (t[i] == '+') 1 else -1;
            if (i + 6 > t.len) return null;
            if (t[i + 3] != ':') return null;
            const oh = std.fmt.parseInt(i64, t[i + 1 .. i + 3], 10) catch return null;
            const om = std.fmt.parseInt(i64, t[i + 4 .. i + 6], 10) catch return null;
            if (oh > 23 or om > 59) return null;
            offset = sign * (oh * 3600 + om * 60);
            if (i + 6 != t.len) return null;
        },
        else => return null,
    }

    return daysFromCivil(y, mo, d) * SECONDS_PER_DAY + h * 3600 + mi * 60 + se - offset;
}

/// 解析 `2006-01-02 15:04:05`（**无时区**），按 UTC+8 解释。
///
/// 语义等同 OpenList 的 `utils.MustParseCNTime`：把 `str + " +08"` 用
/// `2006-01-02 15:04:05 -07` 在 `CNLoc`（+08 固定区）里解析 —— 结果就是把
/// 本地读数直接减 8 小时。时区是**硬编码**的，不是"本地时区"：光猫的 TZ 可能
/// 是任何值，跟着走会算错。
///
/// 123pan 的 `createAt`/`updateAt` 和天翼云盘的 `lastOpTime` 都是这个形状。
pub fn parseCnTime(s: []const u8) ?i64 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len < 19) return null;
    if (t[4] != '-' or t[7] != '-' or (t[10] != ' ' and t[10] != 'T')) return null;
    if (t[13] != ':' or t[16] != ':') return null;

    const y = std.fmt.parseInt(i64, t[0..4], 10) catch return null;
    const mo = std.fmt.parseInt(i64, t[5..7], 10) catch return null;
    const d = std.fmt.parseInt(i64, t[8..10], 10) catch return null;
    const h = std.fmt.parseInt(i64, t[11..13], 10) catch return null;
    const mi = std.fmt.parseInt(i64, t[14..16], 10) catch return null;
    const se = std.fmt.parseInt(i64, t[17..19], 10) catch return null;
    if (mo < 1 or mo > 12) return null;
    if (d < 1 or d > daysInMonth(y, mo)) return null;
    if (h > 23 or mi > 59 or se > 60) return null;

    return daysFromCivil(y, mo, d) * SECONDS_PER_DAY + h * 3600 + mi * 60 + se - 8 * 3600;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

test "daysFromCivil / civilFromDays round-trip" {
    try testing.expectEqual(@as(i64, 0), daysFromCivil(1970, 1, 1));
    try testing.expectEqual(@as(i64, 1), daysFromCivil(1970, 1, 2));
    try testing.expectEqual(@as(i64, -1), daysFromCivil(1969, 12, 31));
    try testing.expectEqual(@as(i64, 11017), daysFromCivil(2000, 3, 1));
    try testing.expectEqual(@as(i64, 20736), daysFromCivil(2026, 10, 10));

    const samples = [_]i64{ -719468, -1, 0, 1, 11017, 20736, 2932896 };
    for (samples) |z| {
        const c = civilFromDays(z);
        try testing.expectEqual(z, daysFromCivil(c.y, c.m, c.d));
    }
}

test "formatHttpDate matches Go's http.TimeFormat" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // 向量由 Python 的 datetime.strftime 独立算出。
    const cases = [_]struct { ts: i64, want: []const u8 }{
        .{ .ts = 0, .want = "Thu, 01 Jan 1970 00:00:00 GMT" },
        .{ .ts = 1_791_604_800, .want = "Sat, 10 Oct 2026 04:00:00 GMT" },
        .{ .ts = 1_800_000_000, .want = "Fri, 15 Jan 2027 08:00:00 GMT" },
    };
    for (cases) |c| {
        var b = Buf.init(a);
        try formatHttpDate(&b, c.ts);
        try testing.expectEqualStrings(c.want, b.slice());
    }

    // 星期几必须跟着日期滚动；+1 天是周五，+7 天仍是周四。
    var b = Buf.init(a);
    try formatHttpDate(&b, 86400);
    try testing.expectEqualStrings("Fri, 02 Jan 1970 00:00:00 GMT", b.slice());
    var b2 = Buf.init(a);
    try formatHttpDate(&b2, 7 * SECONDS_PER_DAY);
    try testing.expectEqualStrings("Thu, 08 Jan 1970 00:00:00 GMT", b2.slice());
}

test "formatIsoMillisZ matches Go's 2006-01-02T15:04:05.000Z layout" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var b = Buf.init(a);
    try formatIsoMillisZ(&b, 1_791_604_800);
    try testing.expectEqualStrings("2026-10-10T04:00:00.000Z", b.slice());

    var b2 = Buf.init(a);
    try formatIsoMillisZ(&b2, 0);
    try testing.expectEqualStrings("1970-01-01T00:00:00.000Z", b2.slice());

    // 秒不补零 / 月份补零 —— 这两条是 `{d:0>2}` 的经典翻车点。
    var b3 = Buf.init(a);
    try formatIsoMillisZ(&b3, 1_800_000_000);
    try testing.expectEqualStrings("2027-01-15T08:00:00.000Z", b3.slice());
}

test "isLeap and daysInMonth" {
    try testing.expect(isLeap(2000));
    try testing.expect(!isLeap(1900));
    try testing.expect(isLeap(2024));
    try testing.expect(!isLeap(2026));
    try testing.expectEqual(@as(i64, 29), daysInMonth(2024, 2));
    try testing.expectEqual(@as(i64, 28), daysInMonth(2026, 2));
    try testing.expectEqual(@as(i64, 31), daysInMonth(2026, 1));
    try testing.expectEqual(@as(i64, 30), daysInMonth(2026, 4));
    try testing.expectEqual(@as(i64, 0), daysInMonth(2026, 13));
}

test "parseCnTime reads a timezone-less stamp as UTC+8" {
    // 2026-10-10 12:00:00 UTC+8 == 2026-10-10 04:00:00 UTC == 1791604800
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseCnTime("2026-10-10 12:00:00"));
    // 同一时刻用 UTC 表示，两者必须相等 —— 这正是"硬编码 UTC+8"的意义。
    try testing.expectEqual(parseRfc3339("2026-10-10T04:00:00Z"), parseCnTime("2026-10-10 12:00:00"));
    // 纪元。
    try testing.expectEqual(@as(?i64, -8 * 3600), parseCnTime("1970-01-01 00:00:00"));
    // `T` 分隔符也认（123pan 的两种形状）。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseCnTime("2026-10-10T12:00:00"));
    // 首尾空白被 trim。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseCnTime("  2026-10-10 12:00:00  "));

    // 闰日。
    try testing.expect(parseCnTime("2024-02-29 00:00:00") != null);
    try testing.expect(parseCnTime("2023-02-29 00:00:00") == null);
    try testing.expect(parseCnTime("1900-02-29 00:00:00") == null);
    try testing.expect(parseCnTime("2000-02-29 00:00:00") != null);

    // 垃圾输入。
    try testing.expect(parseCnTime("") == null);
    try testing.expect(parseCnTime("2026-10-10") == null);
    try testing.expect(parseCnTime("2026-13-01 00:00:00") == null);
    try testing.expect(parseCnTime("2026-10-32 00:00:00") == null);
    try testing.expect(parseCnTime("2026-10-10 25:00:00") == null);
    try testing.expect(parseCnTime("not a time at all!!") == null);
}

test "parseRfc3339 accepts the shapes the drivers actually see" {
    try testing.expectEqual(@as(?i64, 0), parseRfc3339("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("2026-10-10T04:00:00Z"));
    // +08:00 → UTC 减 8 小时。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("2026-10-10T12:00:00+08:00"));
    // -05:00 → UTC 加 5 小时。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("2026-10-09T23:00:00-05:00"));
    // 小数秒被吞掉，不影响秒。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("2026-10-10T04:00:00.123Z"));
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("2026-10-10T04:00:00.123456789Z"));
    // 空白被 trim。
    try testing.expectEqual(@as(?i64, 1_791_604_800), parseRfc3339("  2026-10-10T04:00:00Z  "));

    // 拒绝：没有时区标记（Go 的 time.RFC3339 也拒绝）。
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-10T04:00:00"));
    // 拒绝：日期越界 / 字段错位 / 太短 / 垃圾。
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-13-10T04:00:00Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-02-30T04:00:00Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026/10/10T04:00:00Z"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-10"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339(""));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("not a time at all!!"));
    // 拒绝：Z 后面还跟着东西 / 偏移量后面还跟着东西。
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-10T04:00:00Zx"));
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-10T04:00:00+08:00x"));
    // 拒绝：偏移量里的小时越界。
    try testing.expectEqual(@as(?i64, null), parseRfc3339("2026-10-10T04:00:00+24:00"));
}
