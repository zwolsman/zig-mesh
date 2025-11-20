# Packet Specification

## Overview

This document outlines the packet structure. The packets utilize big-endian encoding (network order) for all integer values.

## Packet Structure

Each packet comprises the following **header**:

| Field            | Type  | Description                                      |
| ---------------- | ----- | ------------------------------------------------ |
| `packet_version` | `u8`  | Currently set to "1"                             |
| `content_type`   | `u8`  | 0 = invalid, 1 = handshake, 2 = application_data |
| `packet_length`  | `u16` | The number of bytes that need to be read         |

> [!IMPORTANT]  
> Once the `content_type` is 2 (`application_data`) the content is encrypted. An authentication tag is appended after the packet body. This means you need to read `packet_length + 16` and decrypt accordingly.

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

### Echo Packet

| Field | Type | Description                |
| ----- | ---- | -------------------------- |
| len   | u16  | length of the payload body |
| bytes | []u8 | message                    |

## Encoding Details

- All integers are encoded in **big-endian** format (network order).
- Ensure to validate the `content_type` and `operation` fields to guarantee the packet format is adhered to.
