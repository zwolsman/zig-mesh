# Packet Specification

## Overview

This document outlines the packet structure. The packets utilize big-endian encoding (network order) for all integer values.

## Packet Structure

Each packet comprises the following **header**:

| Field            | Type  | Description                              |
| ---------------- | ----- | ---------------------------------------- |
| `packet_version` | `u8`  | Currently set to "1"                     |
| `content_type`   | `u8`  | 0 = handshake, 1 = application_data      |
| `packet_length`  | `u16` | The number of bytes that need to be read |

> [!IMPORTANT]  
> Once the `content_type` is 1 (`application_data`) the content is encrypted. An authentication tag is appended after the packet body. This means you need to read `packet_length + 16` and decrypt accordingly.

### Handshake

The handshake uses the **Noise_XX_25519_ChaChaPoly_SHA256** protocol. Once encryption is established, a payload will be added, which includes:

- An **Ed25519** public key (peer id)
- A signature to prove ownership of the static key (**s**)

Handshake pattern:

```
XX:
  -> e
  <- e, ee, s, es
  -> s, se
```

## Types of Packets

There are two types of packets currently defined:

1. **Ping**
2. **Echo**
3. **Route**

### Common Packet Fields

Each packet contains the following fields:

| Field                            | Type     | Description                            |
| -------------------------------- | -------- | -------------------------------------- |
| `operation`                      | `u8`     | 0 = request, 1 = response, 2 = command |
| `id` (if op request or response) | `[16]u8` | 16-byte unique identifier              |
| `tag`                            | `u8`     | 0 = ping, 1 = echo                     |

## Packet Body Definitions

### Ping Packet

> [!NOTE]  
> Ping has an empty packet body

| Field | Type | Description |
| ----- | ---- | ----------- |
|       |      |             |

### Echo Packet

| Field | Type   | Description                |
| ----- | ------ | -------------------------- |
| len   | `u16`  | length of the payload body |
| bytes | `[]u8` | message                    |

### Route Packet

To route a packet to a destination through the mesh network the initiator starts an IK handshake with the destination node. Based on the ED25519 public key, a remote static (`rs`) X25519 public key can be derived. After a succesfull handshake the ciphers will be split. From the receiving point, the node identity key can be used to create a static key (`s`) and handle the handshake as responder.

When receiving a route packet decrypt the payload based on the Noise IK handshake. Once decrypted read it as a packet. Do note: **no** packet header will be present.

Handshake pattern:

```
 IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

This ensures e2e encryption between each hop and another layer of e2e encryption for the destination node.

| Field       | Type     | Description                                               |
| ----------- | -------- | --------------------------------------------------------- |
| destination | `[32]u8` | destination public key                                    |
| n           | `u8`     | number of hops (max 16)                                   |
| hop         | `[32]u8` | public key of hops. Index 0 = initiator, total tops = `n` |
| payload     | `[]u8`   | e2e encrypted payload for destination                     |

### What Each Party Can See

```
Node A (Source)          Node B (Relay)           Node C (Destination)
═══════════════         ════════════════         ════════════════════

Plaintext: "Secret"
    ↓
Encrypt (IK cipher)
    ↓
E2E encrypted
    ↓
Wrap in Route Payload
    ↓
Encode
    ↓
Encrypt (XX cipher A-B)
    ↓
Send → → → → → → →     Receive
                            ↓
                       Decrypt (XX cipher A-B)
                            ↓
                       Can see:
                       - hops: [A]
                       - destination: C
                       - n: 1
                       ✗ CANNOT see inner_payload
                         (still E2E encrypted!)
                            ↓
                       Forward decision
                            ↓
                       Encrypt (XX cipher B-C)
                            ↓
                       Send → → → → → →     Receive
                                                 ↓
                                            Decrypt (XX cipher B-C)
                                                 ↓
                                            Can see Route Payload
                                            dest == self!
                                                 ↓
                                            Decrypt inner_payload
                                            (IK cipher)
                                                 ↓
                                            Plaintext: "Secret"
```

## Encoding Details

- All integers are encoded in **big-endian** format (network order).
- Ensure to validate the `content_type` and `operation` fields to guarantee the packet format is adhered to.
