//! HTML 实体解码（`html.UnescapeString` 的等价物）。
//!
//! 用途：好几个网盘在**列表接口**里返回的是 HTML 转义过的文件名
//! （夸克 `/file/sort` 的 `file_name` 就是典型）。要按名字匹配路径，就得先还原。
//!
//! 覆盖范围：
//!   * 数字实体 `&#39;` / `&#x27;`（含 HTML5 允许的省略分号形态）；
//!   * 约 200 个常用命名实体，**要求分号**；
//!   * HTML5 的「legacy 无分号」集合里最常用的那几个（`&amp` `&lt` `&gt`
//!     `&quot` `&nbsp` `&copy` `&reg`），因为历史上确实有人这么写。
//!
//! 不覆盖 Go 那份 ~2200 条的完整表 —— 云端文件名里出现生僻实体的概率极低，
//! 而把整张表搬进来会让二进制明显变大（这是给光猫用的）。未识别的实体**原样
//! 保留**（和 Go 一样：认不出来就不动它）。

const std = @import("std");
const Buf = @import("buf.zig").Buf;

/// 命名实体表。值一律是 UTF-8 字节串。
const named = [_][2][]const u8{
    // 基本
    .{ "quot", "\"" },     .{ "amp", "&" },      .{ "apos", "'" },     .{ "lt", "<" },
    .{ "gt", ">" },        .{ "nbsp", "\u{00A0}" },
    // Latin-1 符号
    .{ "iexcl", "\u{00A1}" }, .{ "cent", "\u{00A2}" }, .{ "pound", "\u{00A3}" }, .{ "curren", "\u{00A4}" },
    .{ "yen", "\u{00A5}" },   .{ "brvbar", "\u{00A6}" }, .{ "sect", "\u{00A7}" }, .{ "uml", "\u{00A8}" },
    .{ "copy", "\u{00A9}" },  .{ "ordf", "\u{00AA}" }, .{ "laquo", "\u{00AB}" }, .{ "not", "\u{00AC}" },
    .{ "shy", "\u{00AD}" },   .{ "reg", "\u{00AE}" },  .{ "macr", "\u{00AF}" }, .{ "deg", "\u{00B0}" },
    .{ "plusmn", "\u{00B1}" }, .{ "sup2", "\u{00B2}" }, .{ "sup3", "\u{00B3}" }, .{ "acute", "\u{00B4}" },
    .{ "micro", "\u{00B5}" }, .{ "para", "\u{00B6}" }, .{ "middot", "\u{00B7}" }, .{ "cedil", "\u{00B8}" },
    .{ "sup1", "\u{00B9}" },  .{ "ordm", "\u{00BA}" }, .{ "raquo", "\u{00BB}" }, .{ "frac14", "\u{00BC}" },
    .{ "frac12", "\u{00BD}" }, .{ "frac34", "\u{00BE}" }, .{ "iquest", "\u{00BF}" },
    .{ "Agrave", "\u{00C0}" }, .{ "Aacute", "\u{00C1}" }, .{ "Acirc", "\u{00C2}" }, .{ "Atilde", "\u{00C3}" },
    .{ "Auml", "\u{00C4}" },  .{ "Aring", "\u{00C5}" }, .{ "AElig", "\u{00C6}" }, .{ "Ccedil", "\u{00C7}" },
    .{ "Egrave", "\u{00C8}" }, .{ "Eacute", "\u{00C9}" }, .{ "Ecirc", "\u{00CA}" }, .{ "Euml", "\u{00CB}" },
    .{ "Igrave", "\u{00CC}" }, .{ "Iacute", "\u{00CD}" }, .{ "Icirc", "\u{00CE}" }, .{ "Iuml", "\u{00CF}" },
    .{ "ETH", "\u{00D0}" },   .{ "Ntilde", "\u{00D1}" }, .{ "Ograve", "\u{00D2}" }, .{ "Oacute", "\u{00D3}" },
    .{ "Ocirc", "\u{00D4}" }, .{ "Otilde", "\u{00D5}" }, .{ "Ouml", "\u{00D6}" }, .{ "times", "\u{00D7}" },
    .{ "Oslash", "\u{00D8}" }, .{ "Ugrave", "\u{00D9}" }, .{ "Uacute", "\u{00DA}" }, .{ "Ucirc", "\u{00DB}" },
    .{ "Uuml", "\u{00DC}" },  .{ "Yacute", "\u{00DD}" }, .{ "THORN", "\u{00DE}" }, .{ "szlig", "\u{00DF}" },
    .{ "agrave", "\u{00E0}" }, .{ "aacute", "\u{00E1}" }, .{ "acirc", "\u{00E2}" }, .{ "atilde", "\u{00E3}" },
    .{ "auml", "\u{00E4}" },  .{ "aring", "\u{00E5}" }, .{ "aelig", "\u{00E6}" }, .{ "ccedil", "\u{00E7}" },
    .{ "egrave", "\u{00E8}" }, .{ "eacute", "\u{00E9}" }, .{ "ecirc", "\u{00EA}" }, .{ "euml", "\u{00EB}" },
    .{ "igrave", "\u{00EC}" }, .{ "iacute", "\u{00ED}" }, .{ "icirc", "\u{00EE}" }, .{ "iuml", "\u{00EF}" },
    .{ "eth", "\u{00F0}" },   .{ "ntilde", "\u{00F1}" }, .{ "ograve", "\u{00F2}" }, .{ "oacute", "\u{00F3}" },
    .{ "ocirc", "\u{00F4}" }, .{ "otilde", "\u{00F5}" }, .{ "ouml", "\u{00F6}" }, .{ "divide", "\u{00F7}" },
    .{ "oslash", "\u{00F8}" }, .{ "ugrave", "\u{00F9}" }, .{ "uacute", "\u{00FA}" }, .{ "ucirc", "\u{00FB}" },
    .{ "uuml", "\u{00FC}" },  .{ "yacute", "\u{00FD}" }, .{ "thorn", "\u{00FE}" }, .{ "yuml", "\u{00FF}" },
    // 拉丁扩展 / 标点
    .{ "OElig", "\u{0152}" }, .{ "oelig", "\u{0153}" }, .{ "Scaron", "\u{0160}" }, .{ "scaron", "\u{0161}" },
    .{ "Yuml", "\u{0178}" },  .{ "fnof", "\u{0192}" },  .{ "circ", "\u{02C6}" },  .{ "tilde", "\u{02DC}" },
    .{ "ensp", "\u{2002}" },  .{ "emsp", "\u{2003}" },  .{ "thinsp", "\u{2009}" }, .{ "zwnj", "\u{200C}" },
    .{ "zwj", "\u{200D}" },   .{ "lrm", "\u{200E}" },   .{ "rlm", "\u{200F}" },   .{ "ndash", "\u{2013}" },
    .{ "mdash", "\u{2014}" }, .{ "lsquo", "\u{2018}" }, .{ "rsquo", "\u{2019}" }, .{ "sbquo", "\u{201A}" },
    .{ "ldquo", "\u{201C}" }, .{ "rdquo", "\u{201D}" }, .{ "bdquo", "\u{201E}" }, .{ "dagger", "\u{2020}" },
    .{ "Dagger", "\u{2021}" }, .{ "bull", "\u{2022}" }, .{ "hellip", "\u{2026}" }, .{ "permil", "\u{2030}" },
    .{ "prime", "\u{2032}" }, .{ "Prime", "\u{2033}" }, .{ "lsaquo", "\u{2039}" }, .{ "rsaquo", "\u{203A}" },
    .{ "oline", "\u{203E}" }, .{ "frasl", "\u{2044}" }, .{ "euro", "\u{20AC}" },  .{ "trade", "\u{2122}" },
    // 希腊字母
    .{ "Alpha", "\u{0391}" }, .{ "Beta", "\u{0392}" }, .{ "Gamma", "\u{0393}" }, .{ "Delta", "\u{0394}" },
    .{ "Epsilon", "\u{0395}" }, .{ "Zeta", "\u{0396}" }, .{ "Eta", "\u{0397}" }, .{ "Theta", "\u{0398}" },
    .{ "Iota", "\u{0399}" }, .{ "Kappa", "\u{039A}" }, .{ "Lambda", "\u{039B}" }, .{ "Mu", "\u{039C}" },
    .{ "Nu", "\u{039D}" },   .{ "Xi", "\u{039E}" },    .{ "Omicron", "\u{039F}" }, .{ "Pi", "\u{03A0}" },
    .{ "Rho", "\u{03A1}" },  .{ "Sigma", "\u{03A3}" }, .{ "Tau", "\u{03A4}" },   .{ "Upsilon", "\u{03A5}" },
    .{ "Phi", "\u{03A6}" },  .{ "Chi", "\u{03A7}" },   .{ "Psi", "\u{03A8}" },   .{ "Omega", "\u{03A9}" },
    .{ "alpha", "\u{03B1}" }, .{ "beta", "\u{03B2}" }, .{ "gamma", "\u{03B3}" }, .{ "delta", "\u{03B4}" },
    .{ "epsilon", "\u{03B5}" }, .{ "zeta", "\u{03B6}" }, .{ "eta", "\u{03B7}" }, .{ "theta", "\u{03B8}" },
    .{ "iota", "\u{03B9}" }, .{ "kappa", "\u{03BA}" }, .{ "lambda", "\u{03BB}" }, .{ "mu", "\u{03BC}" },
    .{ "nu", "\u{03BD}" },   .{ "xi", "\u{03BE}" },    .{ "omicron", "\u{03BF}" }, .{ "pi", "\u{03C0}" },
    .{ "rho", "\u{03C1}" },  .{ "sigmaf", "\u{03C2}" }, .{ "sigma", "\u{03C3}" }, .{ "tau", "\u{03C4}" },
    .{ "upsilon", "\u{03C5}" }, .{ "phi", "\u{03C6}" }, .{ "chi", "\u{03C7}" }, .{ "psi", "\u{03C8}" },
    .{ "omega", "\u{03C9}" }, .{ "thetasym", "\u{03D1}" }, .{ "upsih", "\u{03D2}" }, .{ "piv", "\u{03D6}" },
    // 数学 / 箭头 / 其他
    .{ "larr", "\u{2190}" }, .{ "uarr", "\u{2191}" }, .{ "rarr", "\u{2192}" }, .{ "darr", "\u{2193}" },
    .{ "harr", "\u{2194}" }, .{ "crarr", "\u{21B5}" }, .{ "lArr", "\u{21D0}" }, .{ "uArr", "\u{21D1}" },
    .{ "rArr", "\u{21D2}" }, .{ "dArr", "\u{21D3}" }, .{ "hArr", "\u{21D4}" },
    .{ "forall", "\u{2200}" }, .{ "part", "\u{2202}" }, .{ "exist", "\u{2203}" }, .{ "empty", "\u{2205}" },
    .{ "nabla", "\u{2207}" }, .{ "isin", "\u{2208}" }, .{ "notin", "\u{2209}" }, .{ "ni", "\u{220B}" },
    .{ "prod", "\u{220F}" }, .{ "sum", "\u{2211}" },  .{ "minus", "\u{2212}" }, .{ "lowast", "\u{2217}" },
    .{ "radic", "\u{221A}" }, .{ "prop", "\u{221D}" }, .{ "infin", "\u{221E}" }, .{ "ang", "\u{2220}" },
    .{ "and", "\u{2227}" },  .{ "or", "\u{2228}" },   .{ "cap", "\u{2229}" },   .{ "cup", "\u{222A}" },
    .{ "int", "\u{222B}" },  .{ "there4", "\u{2234}" }, .{ "sim", "\u{223C}" }, .{ "cong", "\u{2245}" },
    .{ "asymp", "\u{2248}" }, .{ "ne", "\u{2260}" },  .{ "equiv", "\u{2261}" }, .{ "le", "\u{2264}" },
    .{ "ge", "\u{2265}" },   .{ "sub", "\u{2282}" },  .{ "sup", "\u{2283}" },   .{ "nsub", "\u{2284}" },
    .{ "sube", "\u{2286}" }, .{ "supe", "\u{2287}" }, .{ "oplus", "\u{2295}" }, .{ "otimes", "\u{2297}" },
    .{ "perp", "\u{22A5}" }, .{ "sdot", "\u{22C5}" }, .{ "lceil", "\u{2308}" }, .{ "rceil", "\u{2309}" },
    .{ "lfloor", "\u{230A}" }, .{ "rfloor", "\u{230B}" }, .{ "lang", "\u{2329}" }, .{ "rang", "\u{232A}" },
    .{ "loz", "\u{25CA}" },  .{ "spades", "\u{2660}" }, .{ "clubs", "\u{2663}" }, .{ "hearts", "\u{2665}" },
    .{ "diams", "\u{2666}" },
};

/// HTML5 允许**省略分号**的那一小撮里最常用的几个。
fn legacyNoSemi(name: []const u8) ?[]const u8 {
    const t = [_][2][]const u8{
        .{ "amp", "&" },  .{ "lt", "<" },   .{ "gt", ">" },   .{ "quot", "\"" },
        .{ "nbsp", "\u{00A0}" }, .{ "copy", "\u{00A9}" }, .{ "reg", "\u{00AE}" },
    };
    for (t) |e| {
        if (std.mem.eql(u8, name, e[0])) return e[1];
    }
    return null;
}

fn lookup(name: []const u8) ?[]const u8 {
    inline for (named) |e| {
        if (std.mem.eql(u8, name, e[0])) return e[1];
    }
    return null;
}

fn appendCodepoint(b: *Buf, cp: u21) !void {
    // 无效码点（surrogate / 越界）按 U+FFFD 处理，与 HTML5 一致。
    const c: u21 = if (cp == 0 or cp > 0x10FFFF or (cp >= 0xD800 and cp <= 0xDFFF)) 0xFFFD else cp;
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(c, &buf) catch {
        try b.append("\u{FFFD}");
        return;
    };
    try b.append(buf[0..n]);
}

/// `html.UnescapeString`。未识别的实体原样保留（连 `&` 一起）。
pub fn unescape(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, s, '&') == null) return alloc.dupe(u8, s);

    var b = Buf.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] != '&') {
            try b.appendByte(s[i]);
            i += 1;
            continue;
        }
        const start = i;
        i += 1; // 跳过 '&'
        if (i >= s.len) {
            try b.appendByte('&');
            break;
        }

        if (s[i] == '#') {
            // 数字实体：`&#123;` 或 `&#x1F;`
            i += 1;
            var base: u8 = 10;
            if (i < s.len and (s[i] == 'x' or s[i] == 'X')) {
                base = 16;
                i += 1;
            }
            const digits_start = i;
            while (i < s.len and (std.ascii.isDigit(s[i]) or
                (base == 16 and std.ascii.isHex(s[i])))) : (i += 1)
            {}
            if (i == digits_start) {
                try b.append(s[start..i]); // 不是合法数字实体，原样
                continue;
            }
            const cp = std.fmt.parseInt(u21, s[digits_start..i], base) catch {
                try b.append(s[start..i]);
                continue;
            };
            try appendCodepoint(&b, cp);
            if (i < s.len and s[i] == ';') i += 1;
            continue;
        }

        // 命名实体：取到 ';' 或最长的字母数字串
        const name_start = i;
        while (i < s.len and (std.ascii.isAlphanumeric(s[i]))) : (i += 1) {}
        const name = s[name_start..i];
        if (name.len == 0) {
            try b.appendByte('&');
            continue;
        }
        if (i < s.len and s[i] == ';') {
            if (lookup(name)) |rep| {
                try b.append(rep);
                i += 1;
                continue;
            }
        }
        // 没有分号（或带分号但查不到）：只认 legacy 集合，且取**最长匹配前缀**
        // —— Go 把 `a&ampb` 解成 `a&b`，不是原样保留。
        var matched = false;
        var plen = name.len;
        while (plen > 0) : (plen -= 1) {
            if (legacyNoSemi(name[0..plen])) |rep| {
                try b.append(rep);
                i = name_start + plen;
                matched = true;
                break;
            }
        }
        if (!matched) try b.append(s[start..i]);
    }
    return b.toOwned();
}

const testing = std.testing;

test "html unescape: named entities with semicolon" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "a&amp;b", "a&b" },
        .{ "a&lt;b&gt;c", "a<b>c" },
        .{ "&quot;x&quot;", "\"x\"" },
        .{ "it&apos;s", "it's" },
        .{ "&copy;2024", "\u{00A9}2024" },
        .{ "&mdash;", "\u{2014}" },
        .{ "&alpha;&beta;", "\u{03B1}\u{03B2}" },
    };
    for (cases) |c| {
        const got = try unescape(a, c[0]);
        defer a.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "html unescape: numeric entities (decimal, hex, no semicolon)" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "&#39;", "'" },
        .{ "&#x27;", "'" },
        .{ "&#X27;", "'" },
        .{ "&#20013;&#25991;", "中文" },
        .{ "&#x1F600;", "\u{1F600}" },
        .{ "&#65", "A" }, // HTML5 允许省略分号
        .{ "&#x41", "A" },
    };
    for (cases) |c| {
        const got = try unescape(a, c[0]);
        defer a.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "html unescape: legacy no-semicolon names and unknown passthrough" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "a&ampb", "a&b" },
        .{ "x&nbsptail", "x\u{00A0}tail" },
        .{ "&notarealentity;", "&notarealentity;" }, // 查不到 → 原样
        .{ "100% & more", "100% & more" },
        .{ "&", "&" },
        .{ "&;", "&;" },
        .{ "&#;", "&#;" },
    };
    for (cases) |c| {
        const got = try unescape(a, c[0]);
        defer a.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "html unescape: invalid codepoints become U+FFFD" {
    const a = testing.allocator;
    const got = try unescape(a, "&#xD800;&#0;&#x110000;");
    defer a.free(got);
    try testing.expectEqualStrings("\u{FFFD}\u{FFFD}\u{FFFD}", got);
}
