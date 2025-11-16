const std = @import("std");
const builtin = @import("builtin");

const Role = enum { initiator, responder };

pub const MessageToken = enum {
    e,
    s,
    ee,
    es,
    se,
    ss,
    psk,
};

pub const MessagePatternArray = struct {
    buffer: []MessageToken,
    pattern_lens: []usize,
    pattern_index: usize = 0,
    token_index: usize = 0,

    pub fn fromTokens(allocator: std.mem.Allocator, token_arrs: []const []MessageToken) !MessagePatternArray {
        var pattern_lens = try allocator.alloc(usize, token_arrs.len);
        var num_tokens: usize = 0;

        for (token_arrs, 0..) |a, i| {
            num_tokens += a.len;
            pattern_lens[i] = a.len;
        }

        var buffer = try allocator.alloc(MessageToken, num_tokens);

        var i: usize = 0;
        for (token_arrs) |a| {
            for (a, 0..) |t, j| {
                buffer[i + j] = t;
            }
            i += a.len;
        }

        return .{
            .buffer = buffer,
            .pattern_lens = pattern_lens,
        };
    }

    pub fn next(self: *MessagePatternArray) ?[]const MessageToken {
        if (self.isFinished()) return null;

        const len = self.pattern_lens[self.pattern_index];
        const slice = self.buffer[self.token_index .. self.token_index + len];
        self.pattern_index += 1;
        self.token_index += len;

        return slice;
    }

    pub fn isFinished(self: *MessagePatternArray) bool {
        return self.pattern_index >= self.pattern_lens.len;
    }

    pub fn deinit(self: *MessagePatternArray, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
        allocator.free(self.pattern_lens);
    }
};

pub const SymmetricState = struct {
    const Self = @This();

    h: [32]u8, // sha256 = 32bytes
    ck: [32]u8, // chain key = 32 bytes
    buffer: [1024]u8,
    writer: std.Io.Writer,

    pub fn init(self: *Self, protocol: []const u8) *SymmetricState {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(protocol);

        const hash = hasher.finalResult();

        self.* = .{
            .h = hash,
            .ck = hash,
            .buffer = undefined,
            .writer = .fixed(&self.buffer),
        };

        return self;
    }

    pub fn deinit() void {}

    /// Mix hash with a variable-length `data` input.
    ///
    /// This is for use in (1) mixing prologue or (2) encryption/decryption, since
    /// the payloads are of variable-length.
    ///
    /// For mixing with cipher keys or hash digests, we use `mixHashBounded`.
    pub fn mixHash(self: *Self, data: []const u8) !void {
        var hasher = std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256).init(&self.buffer);

        try hasher.writer.writeAll(&self.h);
        try hasher.writer.writeAll(data);

        self.h = hasher.hasher.finalResult();
    }

    pub fn mixKey(self: *Self, input_key_material: []const u8) !void {
        var out: [64]u8 = undefined;
        std.crypto.kdf.hkdf.HkdfSha256.expand(&out, input_key_material, self.ck);
        self.ck = out[0..32].*;

        // self.cipher_state = .init(choice, out[32..64]);
    }
};

const HandshakeState = struct {
    allocator: std.mem.Allocator,
    role: Role,

    /// The local static key pair
    s: ?std.crypto.dh.X25519.KeyPair = null,

    /// The local ephemeral key pair
    e: ?std.crypto.dh.X25519.KeyPair = null,

    /// rs: The remote party's static public key
    rs: ?[std.crypto.dh.X25519.public_length]u8,

    /// re: The remote party's ephemeral public key
    re: ?[std.crypto.dh.X25519.public_length]u8,

    message_patterns: MessagePatternArray,
    symmetric_state: *SymmetricState,

    const Keys = struct {
        /// The local static key pair
        s: ?std.crypto.dh.X25519.KeyPair = null,

        /// The local ephemeral key pair
        e: ?std.crypto.dh.X25519.KeyPair = null,

        /// rs: The remote party's static public key
        rs: ?[std.crypto.dh.X25519.public_length]u8 = null,

        /// re: The remote party's ephemeral public key
        re: ?[std.crypto.dh.X25519.public_length]u8 = null,
    };

    const Protocol = enum {
        XX,

        const MessagePatterns = std.array_list.Managed([]MessageToken);

        const UnmanagedTokenArray = std.ArrayList(MessageToken);

        fn messagePatterns(self: Protocol, allocator: std.mem.Allocator) !MessagePatternArray {
            var message_pattern: MessagePatterns = .init(allocator);
            defer {
                for (message_pattern.items) |pattern| {
                    allocator.free(pattern);
                }
                message_pattern.deinit();
            }

            switch (self) {
                .XX => {
                    try message_pattern.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_pattern.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                    try message_pattern.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .s, .se }));
                },
            }

            return MessagePatternArray.fromTokens(allocator, message_pattern.items);
        }
    };

    pub fn init(allocator: std.mem.Allocator, role: Role, protocol: Protocol, keys: Keys) !HandshakeState {
        var symmetric_state = try allocator.create(SymmetricState);
        return .{
            .allocator = allocator,
            .message_patterns = try protocol.messagePatterns(allocator),
            .symmetric_state = symmetric_state.init("test"),
            .s = keys.s,
            .e = keys.e,
            .rs = keys.rs,
            .re = keys.re,
            .role = role,
        };
    }

    pub fn deinit(self: *HandshakeState) void {
        self.message_patterns.deinit(self.allocator);
        self.allocator.destroy(self.symmetric_state);
    }

    pub fn write(self: *HandshakeState, writer: *std.Io.Writer, payload: []u8) !void {
        _ = payload; // autofix
        const pattern = self.message_patterns.next();
        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) {
                            const kp = std.crypto.dh.X25519.KeyPair.generate();
                            self.e = kp;
                        }

                        const public_key = self.e.?.public_key;
                        try writer.writeAll(&public_key);
                        try self.symmetric_state.mixHash(&public_key);
                    },
                    else => return error.UnknownToken,
                }
            }
        }
    }

    pub fn read(self: *HandshakeState, reader: *std.Io.Reader) !void {
        const pattern = self.message_patterns.next();
        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) std.debug.assert(self.re == null);

                        self.re = (try reader.takeArray(std.crypto.dh.X25519.public_length)).*;
                        try self.symmetric_state.mixHash(&self.re.?);
                    },
                    .ee => try self.symmetric_state.mixKey(&try std.crypto.dh.X25519.scalarmult(self.e.?.secret_key, self.re.?)),
                    .s => {}, // TODO
                    .es => {}, // TODO
                    else => return error.UnkownToken,
                }
            }
        }
    }
};

test "Handhsake state" {
    std.testing.log_level = .debug;

    var alice_send_buffer: [4096]u8 = undefined;
    var alice_writer = std.Io.Writer.fixed(&alice_send_buffer);

    var alice: HandshakeState = try .init(std.testing.allocator, .initiator, .XX, .{});
    defer alice.deinit();

    var bob_reader = std.Io.Reader.fixed(&alice_send_buffer);
    var bob: HandshakeState = try .init(std.testing.allocator, .responder, .XX, .{});
    defer bob.deinit();

    alice.e = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{0} ** 32);
    bob.e = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{1} ** 32);

    try alice.write(&alice_writer, &.{});
    std.log.info("alice pattern: {any}", .{alice.message_patterns});
    std.log.info("alice: {any}", .{alice_writer.buffered()});

    std.log.info("bob pattern: {any}", .{bob.message_patterns});
    try bob.read(&bob_reader);

    std.log.info("alice e: {x}", .{&alice.e.?.public_key});
    std.log.info("bob re: {x}", .{&bob.re.?});
}
