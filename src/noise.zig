const std = @import("std");
const builtin = @import("builtin");

///The max message length in bytes.
///
///See: http://www.noiseprotocol.org/noise.html#message-format
pub const MAX_MESSAGE_LEN = 65535;

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

/// Choice of cipher in a noise protocol. These must be stylized like in the [protocol specification]
/// for `std.meta.stringToEnum` to work as intended.
///
/// [protocol specification]: https://noiseprotocol.org/noise.html#protocol-names-and-modifiers
pub const CipherChoice = enum {
    ChaChaPoly,
    AESGCM,
};
/// Choice of hash in a noise protocol. These must be stylized like in the [protocol specification]
/// for `std.meta.stringToEnum` to work as intended.
///
/// [protocl specification] http://www.noiseprotocol.org/noise.html#hash-functions
pub const HashChoice = enum {
    SHA256,
    SHA512,
    BLAKE2s,
    BLAKE2b,
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

pub const CipherState = union(enum) {
    chacha: cipherState(std.crypto.aead.chacha_poly.ChaCha20Poly1305),
    aesgcm: cipherState(std.crypto.aead.aes_gcm.Aes256Gcm),

    const nonce_length = 12;

    pub fn init(cipher_choice: CipherChoice, key: [32]u8) !CipherState {
        return switch (cipher_choice) {
            .ChaChaPoly => CipherState{ .chacha = cipherState(std.crypto.aead.chacha_poly.ChaCha20Poly1305).init(key) },
            .AESGCM => CipherState{ .aesgcm = cipherState(std.crypto.aead.aes_gcm.Aes256Gcm).init(key) },
        };
    }

    pub fn encryptWithAd(self: *CipherState, ciphertext: []u8, ad: []const u8, plaintext: []const u8) ![]const u8 {
        var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;

        switch (self.*) {
            .chacha => {
                const n_bytes: [8]u8 = @bitCast(std.mem.nativeToLittle(u64, self.chacha.n));
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);

                return self.chacha.encryptWithAd(ciphertext, ad, plaintext, nonce);
            },
            .aesgcm => {
                const n_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, self.aesgcm.n));
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);

                return self.aesgcm.encryptWithAd(ciphertext, ad, plaintext, nonce);
            },
        }
    }

    pub fn decryptWithAd(self: *CipherState, plaintext: []u8, ad: []const u8, ciphertext: []const u8) ![]const u8 {
        var nonce: [nonce_length]u8 = [_]u8{0} ** nonce_length;

        switch (self.*) {
            .chacha => {
                const n_bytes: [8]u8 = @bitCast(self.chacha.n);
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);

                return self.chacha.decryptWithAd(plaintext, ad, ciphertext, nonce);
            },
            .aesgcm => {
                const n_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, self.aesgcm.n));
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);

                return self.aesgcm.decryptWithAd(plaintext, ad, ciphertext, nonce);
            },
        }
    }

    /// Returns true if `k` is non-empty, false otherwise.
    pub fn hasKey(self: *CipherState) bool {
        switch (self.*) {
            .chacha => return self.chacha.hasKey(),
            .aesgcm => return self.aesgcm.hasKey(),
        }
    }

    pub fn rekey(self: *CipherState) !void {
        return switch (self.*) {
            .chacha => try self.chacha.rekey(),
            .aesgcm => try self.aesgcm.rekey(),
        };
    }

    fn cipherState(comptime C: type) type {
        const cipher = Cipher(C);

        return struct {
            const Self = @This();
            const empty_key = [_]u8{0} ** cipher.key_length;
            /// A cipher key of 32 bytes (which may be empty).
            ///
            /// Empty is a special value which indicates `k` has not yet been initialized.
            k: [cipher.key_length]u8 = empty_key,

            /// An 8-byte (64-bit) unsigned integer nonce.
            n: u64,

            nonce_length: usize = cipher.nonce_length,

            /// Sets `k` = `key` and `n` = 0.
            fn init(key: [32]u8) Self {
                return .{ .k = key, .n = 0 };
            }

            /// Returns true if `k` is non-empty, false otherwise.
            fn hasKey(self: *Self) bool {
                return !std.mem.eql(u8, &self.k, &empty_key);
            }

            /// Sets `n` = `nonce`. This i used for handling out-of-order transport messages.
            /// See: https://noiseprotocol.org/noise.html#out-of-order-transport-messages
            fn setNonce(self: *Self, nonce: u64) void {
                self.n = nonce;
            }

            /// If `k` is non-empty returns `Cipher_.encrypt(k, n++, ad, plaintext). Otherwise return plaintext.
            fn encryptWithAd(self: *Self, ciphertext: []u8, ad: []const u8, plaintext: []const u8, nonce: [cipher.nonce_length]u8) ![]const u8 {
                if (!self.hasKey()) {
                    @memcpy(ciphertext[0..plaintext.len], plaintext);
                    return ciphertext[0..plaintext.len];
                }

                if (self.n == std.math.maxInt(u64)) return error.NonceExhaustion;

                const slice = cipher.encrypt(ciphertext, self.k, nonce, ad, plaintext) catch |err| {
                    // Nonce is still incremented if encryption fails.
                    // Reusing a nonce value for n with the same key k for encryption would be catastrophic.
                    // Nonces are not allowed to wrap back to zero due to integer overflow, and the maximum nonce value is reserved.
                    self.n += 1;
                    return err;
                };

                self.n += 1;
                return slice;
            }

            pub fn decryptWithAd(self: *Self, plaintext: []u8, ad: []const u8, ciphertext: []const u8, nonce: [cipher.nonce_length]u8) ![]const u8 {
                if (!self.hasKey()) {
                    @memcpy(plaintext[0..ciphertext.len], ciphertext);
                    return plaintext[0..ciphertext.len];
                }

                if (self.n == std.math.maxInt(u64)) return error.NonceExhaustion;

                // Nonce is NOT incremented if decryption fails.
                const slice = try cipher.decrypt(plaintext, self.k, nonce, ad, ciphertext);
                self.n += 1;

                return slice;
            }

            pub fn rekey(self: *Self) !void {
                self.k = try cipher.rekey(self.k);
            }
        };
    }
};

fn Cipher(comptime cipher: type) type {
    comptime switch (cipher) {
        std.crypto.aead.aes_gcm.Aes256Gcm, std.crypto.aead.chacha_poly.ChaCha20Poly1305 => {},
        else => @compileError(std.fmt.comptimePrint("Unsupported cipher: {any}", .{cipher})),
    };

    return struct {
        const tag_length = cipher.tag_length;
        const nonce_length = cipher.nonce_length;
        const key_length = cipher.key_length;

        /// Encrypts `plaintext` using the cipher key `k` of 32 bytes and an 8-byte unsigned integer nonce `n` which must be unique for the key `k`.
        ///
        /// Returns the ciphertext that is the same length as the plaintext with the 16-byte authentication tag appended.
        fn encrypt(
            ciphertext: []u8,
            k: [key_length]u8,
            nonce: [nonce_length]u8,
            ad: []const u8,
            plaintext: []const u8,
        ) ![]const u8 {
            std.debug.assert(ciphertext.len >= plaintext.len + tag_length);

            var tag: [tag_length]u8 = undefined;
            cipher.encrypt(ciphertext[0..plaintext.len], tag[0..], plaintext, ad, nonce, k);

            @memcpy(ciphertext[plaintext.len .. plaintext.len + tag_length], &tag);
            return ciphertext[0 .. plaintext.len + tag_length];
        }

        /// Decrypts `ciphertext` using a cipher key `k` of 32-bytes, an 8-byte unsigned integer nonce `n`, and associated data `ad`.
        ///
        /// Returns the plaintext, unless authentication fails, in which case an error is signaled to the caller.
        fn decrypt(
            plaintext: []u8,
            k: [key_length]u8,
            nonce: [nonce_length]u8,
            ad: []const u8,
            ciphertext: []const u8,
        ) ![]const u8 {
            var tag: [tag_length]u8 = undefined;
            @memcpy(tag[0..], ciphertext[ciphertext.len - tag_length .. ciphertext.len]);
            try cipher.decrypt(plaintext[0 .. ciphertext.len - tag_length], ciphertext[0 .. ciphertext.len - tag_length], tag, ad, nonce, k);

            return plaintext[0 .. ciphertext.len - tag_length];
        }

        fn rekey(k: [key_length]u8) ![key_length]u8 {
            var plaintext: [key_length]u8 = undefined;
            var cipher_text: [key_length + tag_length]u8 = undefined;

            _ = try encrypt(
                &cipher_text,
                k,
                [_]u8{std.math.maxInt(u8)} ** nonce_length,
                &[_]u8{},
                &[_]u8{0} ** key_length,
            );

            @memcpy(&plaintext, cipher_text[0..key_length]);
            return plaintext;
        }
    };
}

// const Protocol = struct {
//     const Self = @This();

//     pattern: []const u8,
//     dh: []const u8,
//     cipher: CipherChoice,
//     hash: HashChoice,
// };

// /// Constructs a `Protocol` from a `protocol_name` byte sequence.
// ///
// /// This `Protocol` will be used to instantiate a `SymmetricState`.
// pub fn protocolFromName(protocol_name: []const u8) Protocol {
//     var split_it = std.mem.splitScalar(u8, protocol_name, '_');
//     _ = split_it.next().?;
//     const pattern = split_it.next().?;
//     const dh = split_it.next().?;
//     const cipher_ = std.meta.stringToEnum(CipherChoice, split_it.next().?).?;
//     const hash_ = std.meta.stringToEnum(HashChoice, split_it.next().?).?;
//     std.debug.assert(split_it.next() == null);

//     return .{
//         .pattern = pattern,
//         .dh = dh,
//         .cipher = cipher_,
//         .hash = hash_,
//     };
// }

pub const SymmetricState = struct {
    const Self = @This();
    const hash = std.crypto.hash.sha2.Sha256;

    h: [32]u8, // sha256 = 32bytes
    ck: [32]u8, // chain key = 32 bytes
    buffer: [MAX_MESSAGE_LEN]u8,
    writer: std.Io.Writer,
    cipher_state: CipherState,
    cipher_choice: CipherChoice,

    pub fn init(self: *Self, protocol: []const u8) !*SymmetricState {
        var hasher = hash.init(.{});

        // If protocol_name is less than or equal to HASHLEN bytes in length,
        // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
        // Otherwise sets h = HASH(protocol_name).
        var h: [hash.digest_length]u8 = undefined;
        const cipher_choice = CipherChoice.AESGCM;
        if (protocol.len <= h.len) {
            @memcpy(h[0..protocol.len], protocol);
            for (protocol.len..h.len) |i| {
                h[i] = 0;
            }
        } else {
            hasher.update(protocol);
            h = hasher.finalResult();
        }

        self.* = .{
            .h = h,
            .ck = h,
            .buffer = undefined,
            .writer = .fixed(&self.buffer),
            .cipher_state = try .init(cipher_choice, [_]u8{0} ** 32),
            .cipher_choice = cipher_choice,
        };

        return self;
    }

    pub fn deinit() void {}

    pub fn mixKey(self: *Self, input_key_material: []const u8) !void {
        var out: [64]u8 = undefined;
        std.crypto.kdf.hkdf.HkdfSha256.expand(&out, input_key_material, self.ck);
        self.ck = out[0..32].*;

        self.cipher_state = try .init(self.cipher_choice, out[32..64].*);
    }

    pub fn mixHash(self: *Self, data: []const u8) !void {
        var hasher = std.Io.Writer.Hashing(hash).init(&self.buffer);

        try hasher.writer.writeAll(&self.h);
        try hasher.writer.writeAll(data);

        self.h = hasher.hasher.finalResult();
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn encryptAndHash(self: *Self, ciphertext: []u8, plaintext: []const u8) ![]const u8 {
        const slice = try self.cipher_state.encryptWithAd(ciphertext, &self.h, plaintext);
        try self.mixHash(slice);
        return slice;
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn decryptAndHash(self: *Self, plaintext: []u8, ciphertext: []const u8) ![]const u8 {
        const decrypted = try self.cipher_state.decryptWithAd(plaintext, &self.h, ciphertext);
        try self.mixHash(ciphertext);
        return decrypted;
    }

    pub fn split(self: *Self) !struct { CipherState, CipherState } {
        var out: [64]u8 = undefined;
        std.crypto.kdf.hkdf.HkdfSha256.expand(&out, &.{}, self.ck);
        const temp_k1 = out[0..32].*;
        const temp_k2 = out[32..64].*;

        const c1 = try CipherState.init(self.cipher_choice, temp_k1);
        const c2 = try CipherState.init(self.cipher_choice, temp_k2);

        return .{ c1, c2 };
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
            .symmetric_state = try symmetric_state.init("test"),
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

    pub fn write(self: *HandshakeState, writer: *std.Io.Writer, payload: []u8) !?struct { CipherState, CipherState } {
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
                    .s => {
                        var cipher_text: [48]u8 = undefined; // pub_key + tag len
                        _ = try self.symmetric_state.encryptAndHash(&cipher_text, &self.s.?.public_key);
                        try writer.writeAll(&cipher_text);
                    },
                    .ee => {
                        const key = try std.crypto.dh.X25519.scalarmult(self.e.?.secret_key, self.re.?);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .es => {
                        const kp, const public_key = if (self.role == .initiator) .{ self.e.?, self.rs.? } else .{ self.s.?, self.re.? };
                        const key = try std.crypto.dh.X25519.scalarmult(kp.secret_key, public_key);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .se => {
                        const kp, const public_key = if (self.role == .initiator) .{ self.s.?, self.re.? } else .{ self.e.?, self.rs.? };
                        const key = try std.crypto.dh.X25519.scalarmult(kp.secret_key, public_key);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .ss => {
                        const key = try std.crypto.dh.X25519.scalarmult(self.s.?.secret_key, self.rs.?);

                        try self.symmetric_state.mixKey(&key);
                    },
                    else => return error.UnknownToken,
                }
            }
        }

        var cipher_text: [MAX_MESSAGE_LEN]u8 = undefined;
        const data = try self.symmetric_state.encryptAndHash(&cipher_text, payload);

        try writer.writeAll(data);

        if (self.message_patterns.isFinished()) {
            return try self.symmetric_state.split();
        }

        return null;
    }

    pub fn read(self: *HandshakeState, reader: *std.Io.Reader) !struct { []const u8, ?CipherState, ?CipherState } {
        const pattern = self.message_patterns.next();
        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) std.debug.assert(self.re == null);

                        self.re = (try reader.takeArray(std.crypto.dh.X25519.public_length)).*;
                        try self.symmetric_state.mixHash(&self.re.?);
                    },
                    .s => {
                        const len: u8 = if (self.symmetric_state.cipher_state.hasKey()) 48 else 32;
                        if (!builtin.is_test) {
                            std.debug.assert(self.rs == null);
                            self.rs = undefined;
                        }

                        const key = try reader.take(len);
                        _ = try self.symmetric_state.decryptAndHash(&self.rs.?, key);
                    },
                    .ee => {
                        const key = try std.crypto.dh.X25519.scalarmult(self.e.?.secret_key, self.re.?);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .es => {
                        const kp, const public_key = if (self.role == .initiator) .{ self.e.?, self.rs.? } else .{ self.s.?, self.re.? };
                        const key = try std.crypto.dh.X25519.scalarmult(kp.secret_key, public_key);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .se => {
                        const kp, const public_key = if (self.role == .initiator) .{ self.s.?, self.re.? } else .{ self.e.?, self.rs.? };
                        const key = try std.crypto.dh.X25519.scalarmult(kp.secret_key, public_key);

                        try self.symmetric_state.mixKey(&key);
                    },
                    .ss => {
                        const key = try std.crypto.dh.X25519.scalarmult(self.s.?.secret_key, self.rs.?);

                        try self.symmetric_state.mixKey(&key);
                    },
                    else => {
                        std.log.warn("Unknown token: {}", .{token});
                        return error.UnkownToken;
                    },
                }
            }
        }

        var plaintext: [MAX_MESSAGE_LEN]u8 = undefined;
        const payload = try self.symmetric_state.decryptAndHash(&plaintext, reader.buffered());

        const c1, const c2 = if (self.message_patterns.isFinished()) try self.symmetric_state.split() else .{ null, null };

        return .{ payload, c1, c2 };
    }
};

test "Handhsake state" {
    std.testing.log_level = .debug;

    var transport_buffer: [MAX_MESSAGE_LEN]u8 = undefined;

    var alice: HandshakeState = try .init(std.testing.allocator, .initiator, .XX, .{});
    defer alice.deinit();

    var bob: HandshakeState = try .init(std.testing.allocator, .responder, .XX, .{});
    defer bob.deinit();

    alice.e = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{0} ** 32);
    bob.e = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{1} ** 32);

    alice.s = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{2} ** 32);
    bob.s = try std.crypto.dh.X25519.KeyPair.generateDeterministic([_]u8{3} ** 32);

    alice.rs = undefined;
    bob.rs = undefined;

    while (!alice.message_patterns.isFinished()) {
        var bob_reader = std.Io.Reader.fixed(&transport_buffer);
        var bob_writer = std.Io.Writer.fixed(&transport_buffer);
        var alice_writer = std.Io.Writer.fixed(&transport_buffer);
        var alice_reader = std.Io.Reader.fixed(&transport_buffer);

        // Write alice message
        _ = try alice.write(&alice_writer, &.{});
        std.log.info("-> alice: {any}", .{alice_writer.buffered()});
        bob_reader.end = alice_writer.end;

        // Read alice message
        std.log.info("<- bob: {any}", .{bob_reader.buffered()});
        const payload, _, _ = try bob.read(&bob_reader);
        try std.testing.expect(payload.len == 0);

        std.log.info("", .{});

        if (bob.message_patterns.isFinished())
            break;

        bob_reader = std.Io.Reader.fixed(&transport_buffer);
        bob_writer = std.Io.Writer.fixed(&transport_buffer);
        alice_writer = std.Io.Writer.fixed(&transport_buffer);
        alice_reader = std.Io.Reader.fixed(&transport_buffer);

        // Write bob message
        _ = try bob.write(&bob_writer, &.{});
        std.log.info("-> bob: {any}", .{bob_writer.buffered()});
        alice_reader.end = bob_writer.end;

        // Read bob message
        std.log.info("<- alice: {any}", .{alice_reader.buffered()});
        const payload_2, _, _ = try alice.read(&alice_reader);
        try std.testing.expect(payload_2.len == 0);

        std.log.info("", .{});
        std.log.info("", .{});
    }

    try std.testing.expectEqual(bob.symmetric_state.h, alice.symmetric_state.h);
    std.log.debug("handshake hash ok: {x}", .{&bob.symmetric_state.h});

    var a_receive, var a_send = try alice.symmetric_state.split();
    var b_send, var b_receive = try bob.symmetric_state.split();

    const alice_sent_msg = try a_send.encryptWithAd(&transport_buffer, &.{}, "hello bob!");
    const bob_recv_msg = try b_receive.decryptWithAd(&transport_buffer, &.{}, alice_sent_msg);
    try std.testing.expectEqualStrings(bob_recv_msg, "hello bob!");

    const bob_sent_msg = try b_send.encryptWithAd(&transport_buffer, &.{}, "hello alice!");
    const alice_recv_msg = try a_receive.decryptWithAd(&transport_buffer, &.{}, bob_sent_msg);
    try std.testing.expectEqualStrings(alice_recv_msg, "hello alice!");
}
