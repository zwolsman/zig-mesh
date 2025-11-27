const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

const Identity = union(enum) {
    full: Ed25519.KeyPair,
    public: Ed25519.PublicKey,

    pub fn generate() Identity {
        return .{
            .full = .generate(),
        };
    }

    pub fn generateDeterministic(seed: [Ed25519.seed_length]u8) !Identity {
        return .{
            .full = try .generateDeterministic(seed),
        };
    }

    fn initPublic(bytes: [32]u8) !Identity {
        return .{
            .public = try Ed25519.PublicKey.fromBytes(bytes),
        };
    }

    pub fn sign(self: *const Identity, msg: []const u8) [Ed25519.Signature.encoded_length]u8 {
        switch (self.*) {
            .full => |kp| {
                const sig = try kp.sign(msg, null);

                return sig.toBytes();
            },
            else => return error.MissingSecretKey,
        }
    }

    pub fn verify(self: *const Identity, sig_bytes: [Ed25519.Signature.encoded_length]u8, msg: []const u8) !void {
        const public_key = switch (self.*) {
            .full => |kp| kp.public_key,
            .public => |public_key| public_key,
        };

        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        try sig.verify(msg, public_key);
    }

    pub fn publicKeyBytes(self: *const Identity) [Ed25519.PublicKey.encoded_length]u8 {
        const public_key = switch (self.*) {
            .full => |kp| kp.public_key,
            .public => |public_key| public_key,
        };

        return public_key.toBytes();
    }
};

const PeerNode = struct {
    const Self = @This();

    identity: Identity,

    fn init() !Self {
        return .{
            .identity = .generate(),
        };
    }
};

test "peer" {
    std.testing.log_level = .debug;
    var node = try PeerNode.init();

    std.log.debug("node identity: {x}", .{&node.identity.publicKeyBytes()});
}
