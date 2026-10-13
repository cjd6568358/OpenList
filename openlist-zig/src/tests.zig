//! Test aggregator.
//!
//! `zig build test` builds this file, and merely *referencing* a module from
//! inside a `test` block pulls that module's own tests into the binary. That
//! keeps every test next to the code it exercises while still giving one
//! command that runs all of them.
//!
//! Modules that need the network or a live upstream (client.zig, the itvsh
//! driver's HTTP paths) are included too — their tests cover the pure
//! functions around the I/O, not the I/O itself.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());

    // Foundation
    _ = @import("util/buf.zig");
    _ = @import("util/hash.zig");
    _ = @import("util/json.zig");
    _ = @import("util/url.zig");
    _ = @import("util/aes.zig");
    _ = @import("util/rsa.zig");
    _ = @import("util/m115.zig");
    _ = @import("util/ec115.zig");
    _ = @import("util/mime.zig");
    _ = @import("util/html.zig");
    _ = @import("util/xml.zig");
    _ = @import("util/time.zig");
    _ = @import("cookiejar.zig");
    _ = @import("log.zig");

    // Core
    _ = @import("model.zig");
    _ = @import("driver.zig");
    _ = @import("config.zig");
    _ = @import("http.zig");
    _ = @import("client.zig");
    _ = @import("frontend.zig");
    _ = @import("archive.zig");

    // Drivers
    _ = @import("drivers/local.zig");
    _ = @import("drivers/webdav.zig");
    _ = @import("drivers/itvsh.zig");
    _ = @import("drivers/123open.zig");
    _ = @import("drivers/aliyundrive.zig");
    _ = @import("drivers/quark.zig");
    _ = @import("drivers/115open.zig");
    _ = @import("drivers/cloud189.zig");
    _ = @import("drivers/cloud189pc.zig");
    // T2：三个正确变体（2026-10-12 补课）
    _ = @import("drivers/pan123.zig");
    _ = @import("drivers/quarkuc.zig");
    _ = @import("drivers/pan115.zig");
    _ = @import("drivers/wopan.zig");

    // App
    _ = @import("api.zig");
    _ = @import("webdav.zig");
    _ = @import("main.zig");
}
