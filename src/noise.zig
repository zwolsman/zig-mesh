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

const PreMessagePattern = enum {
    e,
    s,
    es,
    empty,
};

/// The following handshake patterns represent interactive protocols. These 12 patterns are called the fundamental interactive handshake patterns.
// The fundamental interactive patterns are named with two characters, which indicate the status of the initiator and responder's static keys. The first and second characters refer to the initiator's and responder's static key respectively.
pub const HandshakePatternName = enum {
    /// N = **N**o static key for recipient
    N,
    /// K = Static key for sender **K**nown to recipient
    K,
    /// X = Static key for sender **X**mitted (transmitted) to recipient
    X,
    /// N = **N**o static key for initiator
    /// N = **N**o static key for responder
    NN,
    /// N = **N**o static key for initiator
    /// K = Static key for responder **K**nown to initiator
    NK,
    /// N = **N**o static key for initiator
    /// K = Static key for responder **K**nown to initiator
    NK1,
    NX1,
    /// N = **N**o static key for initiator
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    NX,
    /// K = Static key for initiator **K**nown to responder
    /// N = **N**o static key for responder
    KN,
    /// K = Static key for initiator **K**nown to responder
    /// K = Static key for responder **K**nown to initiator
    KK,
    /// K = Static key for initiator **K**nown to responder
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    KX,
    K1N,
    K1K,
    KK1,
    K1K1,
    K1X,
    KX1,
    K1X1,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// N = **N**o static key for responder
    XN,
    X1N,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// K = Static key for responder **K**nown to initiator
    XK,
    X1K,
    XK1,
    X1K1,
    /// X = Static key for initiator **X**mitted (transmitted) to responder
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    XX,
    X1X,
    // XX1,
    XX1,
    X1X1,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IN,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// N = **N**o static key for responder
    IK,
    /// I = Static key for initiator **I**mmediately transmitted to responder, despite reduced or absent identity hiding
    /// X = Static key for responder **X**mitted (transmitted) to initiator
    IX,
    I1N,
    I1K,
    IK1,
    I1K1,
    I1X,
    IX1,
    I1X1,

    fn isOneWay(self: HandshakePatternName) bool {
        return switch (self) {
            .N, .X, .K => true,
            else => false,
        };
    }
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
                // std.log.debug("enc nonce: {any} ({x})", .{ nonce, nonce });

                return self.chacha.encryptWithAd(ciphertext, ad, plaintext, nonce);
            },
            .aesgcm => {
                const n_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, self.aesgcm.n));
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);
                // std.log.debug("enc nonce: {any} ({x})", .{ nonce, nonce });

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
                // std.log.debug("dec nonce: {any} ({x})", .{ nonce, nonce });

                return self.chacha.decryptWithAd(plaintext, ad, ciphertext, nonce);
            },
            .aesgcm => {
                const n_bytes: [8]u8 = @bitCast(std.mem.nativeToBig(u64, self.aesgcm.n));
                @memcpy(nonce[nonce_length - @sizeOf(@TypeOf(self.aesgcm.n)) .. nonce_length], &n_bytes);
                // std.log.debug("dec nonce: {any} ({x})", .{ nonce, nonce });

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
};

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

            const encrypted = cipher.encrypt(ciphertext, self.k, nonce, ad, plaintext) catch |err| {
                // Nonce is still incremented if encryption fails.
                // Reusing a nonce value for n with the same key k for encryption would be catastrophic.
                // Nonces are not allowed to wrap back to zero due to integer overflow, and the maximum nonce value is reserved.
                self.n += 1;
                return err;
            };

            self.n += 1;
            return encrypted;
        }

        pub fn decryptWithAd(self: *Self, plaintext: []u8, ad: []const u8, ciphertext: []const u8, nonce: [cipher.nonce_length]u8) ![]const u8 {
            if (!self.hasKey()) {
                @memcpy(plaintext[0..ciphertext.len], ciphertext);
                return plaintext[0..ciphertext.len];
            }

            if (self.n == std.math.maxInt(u64)) return error.NonceExhaustion;

            // Nonce is NOT incremented if decryption fails.
            const decrypted = try cipher.decrypt(plaintext, self.k, nonce, ad, ciphertext);
            self.n += 1;

            return decrypted;
        }

        pub fn rekey(self: *Self) !void {
            self.k = try cipher.rekey(self.k);
        }
    };
}

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

test "cipherstate consistency" {
    const testCipher = struct {
        pub fn run(cipher: CipherChoice) !void {
            const allocator = std.testing.allocator;

            const key = [_]u8{69} ** 32;
            var sender = try CipherState.init(cipher, key);
            var receiver = try CipherState.init(cipher, key);
            const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            const ad = "Additional data";

            var ciphertext = try allocator.alloc(u8, m.len + 16);
            _ = try sender.encryptWithAd(ciphertext, ad, m);
            defer allocator.free(ciphertext[0..]);

            var plaintext = try allocator.alloc(u8, m.len);
            _ = try receiver.decryptWithAd(plaintext, ad[0..], ciphertext);
            defer allocator.free(plaintext[0..]);

            try std.testing.expectEqualSlices(u8, plaintext[0..], m);
        }
    };

    _ = try testCipher.run(.ChaChaPoly);
    _ = try testCipher.run(.AESGCM);
}

test "failed encryption returns plaintext" {
    const testCipher = struct {
        pub fn run(cipher: CipherChoice) !void {
            const key = [_]u8{0} ** 32;
            var sender = try CipherState.init(cipher, key);
            const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            const ad = "Additional data";

            const ciphertext = try std.testing.allocator.alloc(u8, m.len + 16);
            defer std.testing.allocator.free(ciphertext);
            const retval = try sender.encryptWithAd(ciphertext, ad, m);
            try std.testing.expectEqualSlices(u8, m[0..], retval);
        }
    };
    try testCipher.run(.ChaChaPoly);
    try testCipher.run(.AESGCM);
}

test "encryption fails on max nonce" {
    const testCipher = struct {
        pub fn run(cipher: CipherChoice) !void {
            const key = [_]u8{1} ** 32;
            var sender = try CipherState.init(cipher, key);

            switch (cipher) {
                .ChaChaPoly => sender.chacha.n = std.math.maxInt(u64),
                .AESGCM => sender.aesgcm.n = std.math.maxInt(u64),
            }

            const retval = sender.encryptWithAd("", "", "");
            try std.testing.expectError(error.NonceExhaustion, retval);
        }
    };

    try testCipher.run(.ChaChaPoly);
    try testCipher.run(.AESGCM);
}

test "rekey" {
    const testCipher = struct {
        pub fn run(cipher: CipherChoice) !void {
            const allocator = std.testing.allocator;

            const key = [_]u8{1} ** 32;
            var sender = try CipherState.init(cipher, key);

            const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            const ad = "Additional data";

            const ciphertext = try std.testing.allocator.alloc(u8, m.len + 16);
            const ciphertext1 = try sender.encryptWithAd(ciphertext, ad, m);
            defer allocator.free(ciphertext1);

            try sender.rekey();
            const ciphertext2 = try std.testing.allocator.alloc(u8, m.len + 16);
            _ = try sender.encryptWithAd(ciphertext2, ad, m);
            defer allocator.free(ciphertext2);
            // rekeying actually changed keys
            try std.testing.expect(!std.mem.eql(u8, ciphertext1, ciphertext2));
        }
    };

    try testCipher.run(.ChaChaPoly);
    try testCipher.run(.AESGCM);
}

test "cipherState - encrypt aes" {
    const key: [std.crypto.aead.aes_gcm.Aes256Gcm.key_length]u8 = [_]u8{0x69} ** std.crypto.aead.aes_gcm.Aes256Gcm.key_length;
    var s = cipherState(std.crypto.aead.aes_gcm.Aes256Gcm).init(key);
    const nonce: [std.crypto.aead.aes_gcm.Aes256Gcm.nonce_length]u8 = [_]u8{0x42} ** std.crypto.aead.aes_gcm.Aes256Gcm.nonce_length;
    const m = "Test with message";
    const ad = "Test with associated data";
    var c: [m.len + 16]u8 = undefined;
    var m2: [m.len]u8 = undefined;

    const ciphertext = try s.encryptWithAd(&c, ad, m, nonce);

    _ = try s.decryptWithAd(&m2, ad, ciphertext, nonce);
    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
    const m_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{ciphertext[0 .. ciphertext.len - 16]});
    defer std.testing.allocator.free(m_hex);

    const t_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{ciphertext[ciphertext.len - 16 ..]});
    defer std.testing.allocator.free(t_hex);
    try std.testing.expectEqualSlices(u8, "5ca1642d90009fea33d01f78cf6eefaf01", m_hex);
    try std.testing.expectEqualSlices(u8, "64accec679d444e2373bd9f6796c0d2c", t_hex);
}

test "CipherState - encrypt aes" {
    std.testing.log_level = .debug;
    const key: [std.crypto.aead.aes_gcm.Aes256Gcm.key_length]u8 = [_]u8{0x69} ** std.crypto.aead.aes_gcm.Aes256Gcm.key_length;
    var s = try CipherState.init(.AESGCM, key);

    const m = "Test with message";
    const ad = "Test with associated data";
    var c: [m.len + 16]u8 = undefined;
    var m2: [m.len]u8 = undefined;

    s.aesgcm.setNonce(std.mem.readInt(u64, &[_]u8{0x69} ** 8, .big));

    const ciphertext = try s.encryptWithAd(&c, ad, m);
    s.aesgcm.setNonce(std.mem.readInt(u64, &[_]u8{0x69} ** 8, .big));

    _ = try s.decryptWithAd(&m2, ad, ciphertext);

    try std.testing.expectEqualSlices(u8, m[0..], m2[0..]);
    const m_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{ciphertext[0 .. ciphertext.len - 16]});
    defer std.testing.allocator.free(m_hex);

    const t_hex = try std.fmt.allocPrint(std.testing.allocator, "{x}", .{ciphertext[ciphertext.len - 16 ..]});
    defer std.testing.allocator.free(t_hex);
    // try std.testing.expectEqualSlices(u8, "5ca1642d90009fea33d01f78cf6eefaf01", m_hex);
    // try std.testing.expectEqualSlices(u8, "64accec679d444e2373bd9f6796c0d2c", t_hex);
}

pub const SymmetricState = struct {
    const Self = @This();

    _h: [MAX_HASH_LEN]u8,
    _ck: [MAX_HASH_LEN]u8,
    buffer: [MAX_MESSAGE_LEN]u8,
    writer: std.Io.Writer,
    cipher_state: CipherState,
    cipher_choice: CipherChoice,
    hasher: Hasher,

    pub fn init(self: *Self, protocol_name: []const u8) !void {
        const protocol = protocolFromName(protocol_name);
        const hash_len: usize = switch (protocol.hash) {
            .SHA256, .BLAKE2s => 32,
            .SHA512, .BLAKE2b => MAX_HASH_LEN,
        };

        var hasher = Hasher{
            .choice = protocol.hash,
            .len = hash_len,
        };

        // If protocol_name is less than or equal to HASHLEN bytes in length,
        // sets h equal to protocol_name with zero bytes appended to make HASHLEN bytes.
        // Otherwise sets h = HASH(protocol_name).
        var h_buf: [MAX_HASH_LEN]u8 = undefined;

        if (protocol_name.len <= hash_len) {
            @memcpy(h_buf[0..protocol_name.len], protocol_name);
            for (protocol_name.len..h_buf.len) |i| {
                h_buf[i] = 0;
            }
        } else {
            _ = try hasher.hash(h_buf[0..hash_len], protocol_name);
        }

        self.* = .{
            ._h = h_buf,
            ._ck = h_buf,
            .buffer = undefined,
            .writer = .fixed(&self.buffer),
            .cipher_state = try .init(protocol.cipher, [_]u8{0} ** 32),
            .cipher_choice = protocol.cipher,
            .hasher = hasher,
        };
    }

    const Hasher = struct {
        choice: HashChoice,
        len: usize,

        pub fn hash(self: *Hasher, output: []u8, input: []const u8) ![]u8 {
            switch (self.choice) {
                .SHA256 => {
                    const result = Sha256.hash(input);
                    @memcpy(output[0..result.len], &result);
                    return output[0..result.len];
                },
                .BLAKE2b => {
                    const result = Blake2b.hash(input);
                    @memcpy(output[0..result.len], &result);
                    return output[0..result.len];
                },
                .SHA512 => {
                    const result = Sha512.hash(input);
                    @memcpy(output[0..result.len], &result);
                    return output[0..result.len];
                },
                .BLAKE2s => {
                    const result = Blake2s.hash(input);
                    @memcpy(output[0..result.len], &result);
                    return output[0..result.len];
                },
            }
        }

        fn HKDF(
            self: *Hasher,
            output: []u8,
            chaining_key: []const u8,
            input_key_material: []const u8,
            num_outputs: u8,
        ) ![]u8 {
            std.debug.assert(chaining_key.len == self.len);
            std.debug.assert(input_key_material.len == 0 or input_key_material.len == 32);
            std.debug.assert(output.len >= num_outputs * self.len);

            var w = std.Io.Writer.fixed(output);
            if (self.choice == .SHA256 or self.choice == .BLAKE2s) {
                const result = switch (self.choice) {
                    .SHA256 => Sha256.HKDF(chaining_key, input_key_material, num_outputs),
                    .BLAKE2s => Blake2s.HKDF(chaining_key, input_key_material, num_outputs),
                    else => unreachable,
                };

                w.writeAll(&result.@"0") catch unreachable;
                w.writeAll(&result.@"1") catch unreachable;

                if (result.@"2") |o| {
                    w.writeAll(&o) catch unreachable;
                }
            }
            if (self.choice == .SHA512 or self.choice == .BLAKE2b) {
                const result = switch (self.choice) {
                    .SHA512 => Sha512.HKDF(chaining_key, input_key_material, num_outputs),

                    .BLAKE2b => Blake2b.HKDF(chaining_key, input_key_material, num_outputs),
                    else => unreachable,
                };
                try w.writeAll(&result.@"0");
                try w.writeAll(&result.@"1");

                if (result.@"2") |o| {
                    try w.writeAll(&o);
                }
            }

            return w.buffered();
        }
    };

    pub fn mixKey(self: *Self, input_key_material: []const u8) !void {
        const keys_data = try self.hasher.HKDF(&self.buffer, self.ck(), input_key_material, 2);
        var keys = std.Io.Reader.fixed(keys_data);

        @memcpy(self._ck[0..self.hasher.len], try keys.take(self.hasher.len));

        // If HASHLEN is 64, then truncates temp_k to 32 bytes.
        const temp_k: [32]u8 = (try keys.takeArray(32)).*;
        self.cipher_state = try .init(self.cipher_choice, temp_k);
    }

    pub fn mixHash(self: *Self, data: []const u8) !void {
        try self.writer.writeAll(self.h());
        try self.writer.writeAll(data);

        _ = try self.hasher.hash(&self._h, self.writer.buffered());

        _ = self.writer.consumeAll();
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn encryptAndHash(self: *Self, ciphertext: []u8, plaintext: []const u8) ![]const u8 {
        const encrypted = try self.cipher_state.encryptWithAd(ciphertext, self.h(), plaintext);
        try self.mixHash(encrypted);
        return encrypted;
    }

    /// Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    /// Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
    pub fn decryptAndHash(self: *Self, plaintext: []u8, ciphertext: []const u8) ![]const u8 {
        const decrypted = try self.cipher_state.decryptWithAd(plaintext, self.h(), ciphertext);
        try self.mixHash(ciphertext);
        return decrypted;
    }

    pub fn split(self: *Self) !struct { CipherState, CipherState } {
        const keys_data = try self.hasher.HKDF(&self.buffer, self.ck(), &.{}, 2);
        var keys = std.Io.Reader.fixed(keys_data);

        const temp_k1: [32]u8 = (try keys.takeArray(32)).*;
        keys.seek = self.hasher.len;

        const temp_k2: [32]u8 = (try keys.takeArray(32)).*;

        const c1 = try CipherState.init(self.cipher_choice, temp_k1);
        const c2 = try CipherState.init(self.cipher_choice, temp_k2);

        return .{ c1, c2 };
    }

    fn h(self: *Self) []u8 {
        return self._h[0..self.hasher.len];
    }

    fn ck(self: *Self) []u8 {
        return self._ck[0..self.hasher.len];
    }
};

const Sha256 = Hash(std.crypto.hash.sha2.Sha256);
const Sha512 = Hash(std.crypto.hash.sha2.Sha512);
const Blake2s = Hash(std.crypto.hash.blake2.Blake2s256);
const Blake2b = Hash(std.crypto.hash.blake2.Blake2b512);

/// The maximum `HASHLEN` that Noise hash functions output.
pub const MAX_HASH_LEN = 64;

/// Instantiates a Noise hash function.
///
/// Only these hash functions are supported in accordance with the spec: `Sha256`, `Sha512`, `Blake2s256`, `Blake2b512`.
///
/// See: https://noiseprotocol.org/noise.html#hash-functions
pub fn Hash(comptime H: type) type {
    const HASHLEN = comptime switch (H) {
        std.crypto.hash.sha2.Sha256, std.crypto.hash.blake2.Blake2s256 => 32,
        std.crypto.hash.sha2.Sha512, std.crypto.hash.blake2.Blake2b512 => MAX_HASH_LEN,
        else => @compileError(std.fmt.comptimePrint("Unsupported hash: {any}", .{H})),
    };

    return struct {
        const Self = @This();

        /// Hashes some arbitrary-length `input` with a collision-resistant cryptographic hash function.
        ///
        /// Returns an output of `HASHLEN` bytes.
        pub fn hash(input: []const u8) [HASHLEN]u8 {
            var out: [HASHLEN]u8 = undefined;
            H.hash(input, &out, .{});
            return out;
        }

        /// A mechanism for message authentication using cryptographic hash functions.
        ///
        /// See: https://www.ietf.org/rfc/rfc2104.txt
        fn hmacHash(key: []const u8, data: []const u8) [HASHLEN]u8 {
            var out: [HASHLEN]u8 = undefined;
            std.crypto.auth.hmac.Hmac(H).create(&out, data, key);
            return out;
        }

        /// The HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
        ///
        /// A key derivation function takes some source of initial keying material and derive from it one or more
        /// cryptographically strong secret keys.
        ///
        /// The `chaining_key` serves as the HKDF salt, and zero-length HKDF info.
        ///
        /// Returns a pair or triple of byte sequences each of length `HASHLEN`, depending on whether `num_outputs`
        /// is two or three.
        pub fn HKDF(
            chaining_key: []const u8,
            input_key_material: []const u8,
            num_outputs: u8,
        ) struct { [HASHLEN]u8, [HASHLEN]u8, ?[HASHLEN]u8 } {
            std.debug.assert(chaining_key.len == HASHLEN);
            std.debug.assert(input_key_material.len == 0 or input_key_material.len == 32 or input_key_material.len == HASHLEN);

            const temp_key = hmacHash(chaining_key, input_key_material);
            std.debug.assert(temp_key.len == HASHLEN);
            const output1 = hmacHash(&temp_key, &[_]u8{0x01});
            var data: [HASHLEN + 1]u8 = undefined;

            @memcpy(data[0..HASHLEN], output1[0..]);
            data[HASHLEN] = 0x02;

            const output2 = hmacHash(&temp_key, &data);
            if (num_outputs == 2) return .{ output1, output2, null };

            data = undefined;
            @memcpy(data[0..HASHLEN], output2[0..]);
            data[HASHLEN] = 0x03;
            const output3 = hmacHash(&temp_key, &data);

            return .{ output1, output2, output3 };
        }
    };
}

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

    psks: ?[]const u8,

    handshake_pattern: HandshakePattern,
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

    const HandshakePattern = struct {
        const MessagePatterns = std.array_list.Managed([]MessageToken);

        pre_message_pattern_initiator: ?PreMessagePattern = null,
        pre_message_pattern_responder: ?PreMessagePattern = null,
        message_patterns: MessagePatternArray,

        pub fn init(allocator: std.mem.Allocator, hs_pattern_name: []const u8) !HandshakePattern {
            var hs_pattern_name_enum = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name);

            var modifier_it: std.mem.SplitIterator(u8, .any) = undefined;

            // Exhaustively split pattern name string to get a valid pattern name. If none are found,
            // we return a `HandshakePatternError.UnrecognizedName` error.
            if (hs_pattern_name_enum == null) {
                var modifier_str: []const u8 = undefined;
                for (1..hs_pattern_name.len) |i| {
                    const pattern = std.meta.stringToEnum(HandshakePatternName, hs_pattern_name[0 .. hs_pattern_name.len - i]);

                    if (pattern) |_| {
                        modifier_str = hs_pattern_name[hs_pattern_name.len - i .. hs_pattern_name.len];
                        hs_pattern_name_enum = pattern;
                        break;
                    }
                }
                modifier_it = std.mem.splitAny(u8, modifier_str, "+");
            }

            if (hs_pattern_name_enum == null) return error.UnrecognizedName;
            var handshake_pattern: HandshakePattern = .{ .message_patterns = undefined };

            var message_patterns: MessagePatterns = .init(allocator);
            defer {
                for (message_patterns.items) |pattern| {
                    allocator.free(pattern);
                }
                message_patterns.deinit();
            }

            switch (hs_pattern_name_enum.?) {
                .N => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es }));
                },
                .NN => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                },
                .NK => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                },
                .NK1 => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .es }));
                },
                .NX => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                },
                .NX1 => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.es}));
                },

                .K => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es, .ss }));
                },
                .KN => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se }));
                },
                .KK => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es, .ss }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se }));
                },
                .KX => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .s, .es }));
                },
                .K1N => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .K1K => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .KK1 => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .es }));
                },
                .K1K1 => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .K1X => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .KX1 => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.es}));
                },
                .K1X1 => {
                    handshake_pattern.pre_message_pattern_initiator = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .se, .es }));
                },
                .X => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es, .s, .ss }));
                },
                .XN => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .s, .se }));
                },
                .X1N => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.s}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },

                .XK => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .s, .se }));
                },
                .X1K => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.s}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .XK1 => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .s, .se }));
                },
                .X1K1 => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.s}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },

                .XX => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .s, .se }));
                },
                .X1X => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.s}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .XX1 => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .es, .s, .se }));
                },
                .X1X1 => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.e}));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .es, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .IN => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se }));
                },
                .I1N => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },

                .IK => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es, .s, .ss }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se }));
                },
                .I1K => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .es, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .IK1 => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .es }));
                },
                .I1K1 => {
                    handshake_pattern.pre_message_pattern_responder = .s;
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .IX => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .s, .es }));
                },
                .I1X => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s, .es }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.se}));
                },
                .IX1 => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .se, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{.es}));
                },
                .I1X1 => {
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .e, .ee, .s }));
                    try message_patterns.append(try allocator.dupe(MessageToken, &[_]MessageToken{ .se, .es }));
                },
            }

            // TODO: add psk support
            // while (modifier_it.next()) |m| {
            //     if (std.mem.containsAtLeast(u8, m, 1, "psk")) {
            //         const num = try std.fmt.parseInt(usize, m["psk".len .. "psk".len + 1], 10);

            //         if (num == 0) {
            //             try message_patterns[0].insert(0, .psk);
            //         } else {
            //             try message_patterns.insert(num - 1, .psk);
            //         }
            //     }
            // }

            const patterns = try MessagePatternArray.fromTokens(allocator, message_patterns.items);
            handshake_pattern.message_patterns = patterns;

            return handshake_pattern;
        }

        pub fn deinit(self: *HandshakePattern, allocator: std.mem.Allocator) void {
            self.message_patterns.deinit(allocator);
        }
    };

    pub fn init(allocator: std.mem.Allocator, protocol_name: []const u8, role: Role, prologue: []const u8, psks: ?[]const u8, keys: Keys) !HandshakeState {
        const protocol = protocolFromName(protocol_name);
        var symmetric_state = try allocator.create(SymmetricState);
        try symmetric_state.init(protocol_name);
        try symmetric_state.mixHash(prologue);

        const pattern = try HandshakePattern.init(allocator, protocol.pattern);

        // Rules for hashing pre-messages:
        // 1) Initiator's public keys are always hashed first.
        // 2) If multiple public keys are listed, they are hashed in the order that they are listed.
        if (role == .initiator) {
            if (pattern.pre_message_pattern_initiator) |i| {
                switch (i) {
                    .s => if (keys.s) |s| try symmetric_state.mixHash(&s.public_key),
                    .e => if (keys.e) |e| try symmetric_state.mixHash(&e.public_key),
                    else => return error.InvalidPreMessagePattern,
                }
            }
            if (pattern.pre_message_pattern_responder) |r| {
                switch (r) {
                    .s => if (keys.rs) |rs| try symmetric_state.mixHash(&rs),
                    .e => if (keys.re) |re| try symmetric_state.mixHash(&re),
                    else => return error.InvalidPreMessagePattern,
                }
            }
        } else {
            if (pattern.pre_message_pattern_initiator) |i| {
                switch (i) {
                    .s => if (keys.rs) |rs| try symmetric_state.mixHash(&rs),
                    .e => if (keys.re) |re| try symmetric_state.mixHash(&re),
                    else => return error.InvalidPreMessagePattern,
                }
            }
            if (pattern.pre_message_pattern_responder) |r| {
                switch (r) {
                    .s => if (keys.s) |s| try symmetric_state.mixHash(&s.public_key),
                    .e => if (keys.e) |e| try symmetric_state.mixHash(&e.public_key),
                    else => return error.InvalidPreMessagePattern,
                }
            }
        }

        return .{
            .allocator = allocator,
            .handshake_pattern = pattern,
            .symmetric_state = symmetric_state,
            .s = keys.s,
            .e = keys.e,
            .rs = keys.rs,
            .re = keys.re,
            .role = role,
            .psks = psks,
        };
    }

    pub fn deinit(self: *HandshakeState) void {
        self.handshake_pattern.deinit(self.allocator);
        self.allocator.destroy(self.symmetric_state);
    }

    pub fn write(self: *HandshakeState, writer: *std.Io.Writer, payload: []u8) !?struct { CipherState, CipherState } {
        const pattern = self.handshake_pattern.message_patterns.next();
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
                        if (self.psks) |psks| if (psks.len > 0) try self.symmetric_state.mixKey(&public_key);
                    },
                    .s => {
                        var cipher_text: [48]u8 = std.mem.zeroes([48]u8); // pub_key + tag len
                        const key = try self.symmetric_state.encryptAndHash(&cipher_text, &self.s.?.public_key);

                        try writer.writeAll(key);
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
        const encrypted = try self.symmetric_state.encryptAndHash(&cipher_text, payload);

        try writer.writeAll(encrypted);

        if (self.handshake_pattern.message_patterns.isFinished()) {
            return try self.symmetric_state.split();
        }

        return null;
    }

    pub fn read(self: *HandshakeState, reader: *std.Io.Reader) !struct { []const u8, ?struct { CipherState, CipherState } } {
        const pattern = self.handshake_pattern.message_patterns.next();
        if (pattern) |p| {
            for (p) |token| {
                switch (token) {
                    .e => {
                        if (!builtin.is_test) std.debug.assert(self.re == null);

                        self.re = (try reader.takeArray(std.crypto.dh.X25519.public_length)).*;
                        try self.symmetric_state.mixHash(&self.re.?);

                        if (self.psks) |psks| if (psks.len > 0) try self.symmetric_state.mixKey(&self.re.?);
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

        const cipher_state = if (self.handshake_pattern.message_patterns.isFinished()) try self.symmetric_state.split() else null;

        return .{ payload, cipher_state };
    }

    pub fn handshakeHash(self: *HandshakeState) []u8 {
        return self.symmetric_state.h();
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

const Vectors = struct {
    vectors: []const Vector,
};

const Message = struct {
    payload: []const u8,
    ciphertext: []const u8,
};

/// Represents a cacophony test vector.
///
/// The members of a `Vector` struct correspond to a vector object found within cacophony.txt.
const Vector = struct {
    protocol_name: []const u8,
    init_prologue: []const u8,
    init_psks: ?[][]const u8 = null,
    init_ephemeral: []const u8,
    init_remote_static: ?[]const u8 = null,
    init_static: ?[]const u8 = null,
    resp_prologue: []const u8,
    resp_psks: ?[][]const u8 = null,
    resp_static: ?[]const u8 = null,
    resp_ephemeral: ?[]const u8 = null,
    resp_remote_static: ?[]const u8 = null,
    handshake_hash: []const u8,
    messages: []const Message,
};

/// Constructs a `Protocol` from a `protocol_name` byte sequence.
///
/// This `Protocol` will be used to instantiate a `SymmetricState`.
fn protocolFromName(protocol_name: []const u8) struct {
    pattern: []const u8,
    dh: []const u8,
    cipher: CipherChoice,
    hash: HashChoice,
} {
    var split_it = std.mem.splitScalar(u8, protocol_name, '_');
    _ = split_it.next().?;
    const pattern = split_it.next().?;
    const dh = split_it.next().?;
    const cipher_ = std.meta.stringToEnum(CipherChoice, split_it.next().?).?;
    const hash_ = std.meta.stringToEnum(HashChoice, split_it.next().?).?;
    std.debug.assert(split_it.next() == null);

    return .{
        .pattern = pattern,
        .dh = dh,
        .cipher = cipher_,
        .hash = hash_,
    };
}

fn keypairFromSecretKey(raw_secret_key: []const u8) !std.crypto.dh.X25519.KeyPair {
    var secret_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret_key, raw_secret_key);
    const public_key = try std.crypto.dh.X25519.recoverPublicKey(secret_key);
    return .{
        .public_key = public_key,
        .secret_key = secret_key,
    };
}

test "cacophony" {
    std.testing.log_level = .debug;
    const allocator = std.testing.allocator;

    const cacophony_txt = try std.fs.cwd().openFile("/Users/mzwolsman/Developer/zigio-mesh/vectors/cacophony.txt", .{});
    defer cacophony_txt.close();
    const buf: []u8 = try cacophony_txt.readToEndAlloc(allocator, 5_000_000);
    defer allocator.free(buf);

    // Validate .txt is loaded as json correctly
    try std.testing.expect(try std.json.validate(allocator, buf));
    const data = try std.json.parseFromSlice(Vectors, allocator, buf[0..], .{});
    defer data.deinit();

    const total_vector_count = data.value.vectors.len;
    var failed_vector_count: usize = 0;
    var ignored_vector_count: usize = 0;

    std.debug.print("Found {} total vectors.\n", .{total_vector_count});

    vector_test: for (data.value.vectors, 0..) |vector, vector_num| {
        const protocol = protocolFromName(vector.protocol_name);

        if (!std.mem.eql(u8, protocol.dh, "25519")) {
            ignored_vector_count += 1;
            continue;
        }

        std.debug.print("\n***** Testing: {s} *****\n", .{vector.protocol_name});
        const init_s = if (vector.init_static) |s| try keypairFromSecretKey(s) else null;
        const init_e = try keypairFromSecretKey(vector.init_ephemeral);

        var init_pk_rs: ?[32]u8 = undefined;
        if (vector.init_remote_static) |rs| {
            _ = try std.fmt.hexToBytes(&init_pk_rs.?, rs);
        }

        var init_prologue_buf: [100]u8 = undefined;
        const init_prologue = try std.fmt.hexToBytes(&init_prologue_buf, vector.init_prologue);

        var j: usize = 0;
        const init_psks = blk: {
            if (vector.init_psks) |psks| {
                var init_psk_buf = try allocator.alloc(u8, 32 * psks.len);
                // errdefer allocator.free(init_psk_buf); TODO: fix
                defer allocator.free(init_psk_buf);
                for (psks) |psk| {
                    _ = try std.fmt.hexToBytes(init_psk_buf[j * 32 .. (j + 1) * 32], psk);
                    j += 1;
                }

                break :blk init_psk_buf[0..];
            } else {
                break :blk null;
            }
        };

        var initiator = try HandshakeState.init(
            allocator,
            vector.protocol_name,
            .initiator,
            init_prologue,
            init_psks,
            .{
                .s = init_s,
                .e = init_e,
                .rs = if (init_pk_rs) |rs| rs else null,
            },
        );
        defer initiator.deinit();

        const resp_s = if (vector.resp_static) |s| try keypairFromSecretKey(s) else null;
        const resp_e = if (vector.resp_ephemeral) |e| try keypairFromSecretKey(e) else null;

        var resp_pk_rs: ?[32]u8 = undefined;
        if (vector.resp_remote_static) |rs| {
            _ = try std.fmt.hexToBytes(&resp_pk_rs.?, rs);
        }
        var resp_prologue_buf: [100]u8 = undefined;
        const resp_prologue = try std.fmt.hexToBytes(&resp_prologue_buf, vector.resp_prologue);

        j = 0;
        const resp_psks = blk: {
            if (vector.resp_psks) |psks| {
                var resp_psk_buf = try allocator.alloc(u8, 32 * psks.len);
                // errdefer allocator.free(resp_psk_buf); TODO: fix
                defer allocator.free(resp_psk_buf);
                for (psks) |psk| {
                    _ = try std.fmt.hexToBytes(resp_psk_buf[j * 32 .. (j + 1) * 32], psk);
                    j += 1;
                }

                break :blk resp_psk_buf[0..];
            } else {
                break :blk null;
            }
        };

        var responder = try HandshakeState.init(
            allocator,
            vector.protocol_name,
            .responder,
            resp_prologue,
            resp_psks,
            .{
                .s = resp_s,
                .e = resp_e,
                .rs = if (resp_pk_rs) |rs| rs else null,
            },
        );
        defer responder.deinit();

        var buffer: [MAX_MESSAGE_LEN]u8 = undefined;

        var c1init: CipherState = undefined;
        var c2init: CipherState = undefined;
        var c1resp: CipherState = undefined;
        var c2resp: CipherState = undefined;
        var msg_idx: usize = 0;

        // Test handshake phase
        handshake_phase: for (vector.messages, 0..) |m, k| {
            var send_writer = std.Io.Writer.fixed(&buffer);
            var receive_reader = std.Io.Reader.fixed(&buffer);

            var sender = if (k % 2 == 0) &initiator else &responder;
            var receiver = if (k % 2 == 0) &responder else &initiator;

            var payload_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            const payload = try std.fmt.hexToBytes(&payload_buf, m.payload);

            const sender_cipherstates = sender.write(&send_writer, payload) catch |e| {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at write for message {}\nErr = {any}", .{ vector.protocol_name, vector_num + 1, k, e });
                continue :vector_test;
            };

            var expected_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            var expected = try std.fmt.hexToBytes(&expected_buf, m.ciphertext);

            std.testing.expectEqualSlices(u8, expected, send_writer.buffered()) catch {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at write for message {}\n", .{ vector.protocol_name, vector_num + 1, k });
                continue :vector_test;
            };

            // TODO: check update reader
            receive_reader.end = send_writer.end;
            expected = try std.fmt.hexToBytes(&expected_buf, m.payload);
            const receive_payload, const receiver_cipherstates = receiver.read(&receive_reader) catch |e| {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at readMessage for message {}\nErr = {any}", .{ vector.protocol_name, vector_num + 1, k, e });
                continue :vector_test;
            };
            std.testing.expectEqualSlices(u8, expected, receive_payload) catch {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at read for message {}\n", .{ vector.protocol_name, vector_num + 1, k });
                continue :vector_test;
            };

            msg_idx += 1;

            if (sender_cipherstates != null and receiver_cipherstates != null) {
                if (k % 2 == 0) {
                    // current round sender is initiator
                    c1init = sender_cipherstates.?[0];
                    c2init = sender_cipherstates.?[1];
                    c2resp = receiver_cipherstates.?[0];
                    c1resp = receiver_cipherstates.?[1];
                } else {
                    // current round sender is responder
                    c1init = receiver_cipherstates.?[0];
                    c2init = receiver_cipherstates.?[1];
                    c2resp = sender_cipherstates.?[0];
                    c1resp = sender_cipherstates.?[1];
                }
                break :handshake_phase;
            }
            // std.debug.print("Vector \"{s}\" ({}) message {} OK\n", .{ vector.protocol_name, vector_num + 1, k });
        }

        try std.testing.expectEqualSlices(u8, initiator.handshakeHash(), responder.handshakeHash());
        var split = std.mem.splitSequence(u8, protocol.pattern, "psk");
        const is_one_way = if (std.meta.stringToEnum(HandshakePatternName, split.next().?)) |p|
            p.isOneWay()
        else
            false;

        // Transport phase
        for (msg_idx..vector.messages.len) |k| {
            const m = vector.messages[k];
            var sender: *CipherState = undefined;
            var receiver: *CipherState = undefined;
            if (is_one_way) {
                sender = &c1init;
                receiver = &c2resp;
            } else {
                const is_initiator = k % 2 == 0;
                sender = if (is_initiator) &c1init else &c1resp;
                receiver = if (is_initiator) &c2resp else &c2init;
            }
            var payload_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            const payload = try std.fmt.hexToBytes(&payload_buf, m.payload);

            const encrypted = sender.encryptWithAd(&buffer, &[_]u8{}, payload) catch |e| {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at encryptWithAd for message {}\nErr = {any}", .{ vector.protocol_name, vector_num + 1, k, e });
                continue :vector_test;
            };

            var expected_buf: [MAX_MESSAGE_LEN]u8 = undefined;
            var expected = try std.fmt.hexToBytes(&expected_buf, m.ciphertext);
            std.testing.expectEqualSlices(u8, expected, encrypted) catch {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed after encryptWithAd\n", .{ vector.protocol_name, vector_num + 1 });
                continue :vector_test;
            };

            expected = try std.fmt.hexToBytes(&expected_buf, m.payload);

            const decrypted = receiver.decryptWithAd(&buffer, &[_]u8{}, encrypted) catch |e| {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed at decryptWithAd for message {}\nErr = {any}", .{ vector.protocol_name, vector_num + 1, k, e });
                continue :vector_test;
            };
            std.testing.expectEqualSlices(u8, expected, decrypted) catch {
                failed_vector_count += 1;
                std.debug.print("Vector \"{s}\" ({}) failed after decryptWithAd\n", .{ vector.protocol_name, vector_num + 1 });
                continue :vector_test;
            };
            // std.debug.print("Vector \"{s}\" ({}) message {} OK\n", .{ vector.protocol_name, vector_num + 1, k });
        }
    }
    std.debug.print("***** {} out of {} vectors passed ({} ignored, {} failed). *****\n", .{ total_vector_count - failed_vector_count - ignored_vector_count, total_vector_count, ignored_vector_count, failed_vector_count });
}
