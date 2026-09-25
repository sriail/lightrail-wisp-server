# Wisp v1.2 - A Lightweight Multiplexing WebSocket Proxy Protocol

**Version 2.1** — Original protocol by [@ading2210](https://github.com/ading2210)  
**Modernization for Cloudflare Workers** — For Pooling and connections in minimal recourse enviroments

---

## About

Wisp v2.0 is a modernization of the original Wisp protocol (v1.2) optimized for **Cloudflare Python Workers**. It maintains backward compatibility with v1.2 while introducing structured server architecture, connection pooling with strict resource limits, and async-first design patterns suitable for serverless environments.

The protocol remains low-overhead and easy to implement, designed for proxying multiple TCP/UDP sockets over a single WebSocket connection with deterministic resource management.

---

## Packet Format

| Field Name  | Field Type | Notes                                         |
|-------------|------------|-----------------------------------------------|
| Packet Type | `uint8_t`  | The packet type, covered in the next section. |
| Stream ID   | `uint32_t` | Random stream ID assigned by the client.      |
| Payload     | `char[]`   | Payload takes up the rest of the packet.      |

Every packet must follow this format regardless of the type. **All data types are little-endian.**

---

## Packet Types

Each packet type has a different format for the payload, detailed below.

### `0x01` - CONNECT

#### Payload Format

| Field Name           | Field Type | Notes                                                  |
|----------------------|------------|--------------------------------------------------------|
| Stream Type          | `uint8_t`  | Whether the new stream should use a TCP or UDP socket. |
| Destination Port     | `uint16_t` | Destination TCP/UDP port for the new stream.           |
| Destination Hostname | `char[]`   | Destination hostname, in a UTF-8 string.               |

#### Behavior

The client sends a CONNECT packet to create a new stream under the same WebSocket. The stream ID chosen by the client is associated with this stream for all future messages. When the server receives this packet, it must validate the payload. If invalid, a CLOSE packet must be sent.

Once validated, the server attempts to establish a TCP/UDP socket to the specified hostname and port. If this fails, the server sends a CLOSE packet with the failure reason. To reduce latency, the client may begin sending DATA packets before receiving a CONTINUE packet from the server.

**Stream Type Field:**
- `0x01` = TCP
- `0x02` = UDP[^1]

---

### `0x02` - DATA

#### Payload Format

| Field Name     | Field Type | Notes                                                      |
|----------------|------------|------------------------------------------------------------|
| Stream Payload | `char[]`   | The data which is sent to and from the destination server. |

#### Behavior

DATA packets from the client to the server are proxied to the TCP/UDP socket associated with the stream ID. The server **must buffer** received payloads (before sending to the socket) to handle congestion. Buffer size is predetermined and identical for all streams.

DATA packets from the server to the client are interpreted as originating from the TCP/UDP socket associated with the stream ID.

For TCP streams, the server maintains a separate FIFO send buffer for each stream, as specified in the **Server Structure** section.

---

### `0x03` - CONTINUE

#### Payload Format

| Field Name       | Field Type | Notes                                                                    |
|------------------|------------|--------------------------------------------------------------------------|
| Buffer Remaining | `uint32_t` | The number of packets the server can buffer for the current stream.      |

#### Behavior

CONTINUE packets must **not** be sent for UDP sockets. Clients do not track buffers for UDP streams.

When the client receives a CONTINUE packet, it stores the buffer size. Before sending each DATA packet, the client decrements this value by 1. When buffer size reaches zero, the client stops sending DATA packets until a new CONTINUE packet is received.

The server sends a CONTINUE packet after processing the same number of packets as its maximum buffer size. Servers **should** send CONTINUE packets more frequently to minimize delays.

---

### `0x04` - CLOSE

#### Payload Format

| Field Name   | Field Type | Notes                                  |
|--------------|------------|----------------------------------------|
| Close Reason | `uint8_t`  | The reason for closing the connection. |

#### Behavior

CLOSE packets from either server or client immediately close the associated stream and TCP socket. The close reason provides debugging information.

#### Universal Close Reasons

- `0x01` — Reason unspecified or unknown (default fallback)
- `0x02` — Voluntary stream closure (connection reset by peer)
- `0x03` — Unexpected stream closure due to network error

#### Server-Only Close Reasons

- `0x41` — Stream creation failed (invalid destination hostname or port)
- `0x42` — Stream creation failed (unreachable destination host)
- `0x43` — Stream creation timed out (destination server not responding)
- `0x44` — Stream creation failed (destination server refused connection)
- `0x47` — TCP data transfer timed out
- `0x48` — Destination address/domain intentionally blocked by proxy server
- `0x49` — Connection throttled by the server

#### Client-Only Close Reasons

- `0x81` — Client encountered unexpected error and cannot receive more data

---

## HTTP/WebSocket Upgrade

### Server Architecture

The server must consist of an HTTP and WebSocket server conforming to respective standards. In Cloudflare Python Workers, this is provided by the `WorkerEntrypoint` class from the `cloudflare-workers` package.

### WebSocket URL Convention

To ensure compatibility with previous wsproxy implementations, WebSocket URLs must end with a trailing forward slash (`/`).

**Example - wsproxy endpoint:**
```
ws://example.com/customprefix/host:port
```

**Example - Wisp endpoint:**
```
ws://example.com/customprefix/
```

The server implementation may ignore the prefix or use it for gatekeeping and password-based authentication.

### Establishing a WebSocket Connection

The client performs a standard WebSocket handshake. The `Sec-WebSocket-Protocol` header is not required.

Immediately after the WebSocket connection is established, the server sends a **CONTINUE packet with stream ID 0** containing the initial buffer size for all streams. This packet signals the Wisp protocol version (0 = Wisp v1/v2).

The client **must wait** for this CONTINUE packet before sending any other messages. This reduces latency by allowing the client to avoid waiting for a CONTINUE packet per stream creation.

---

## Structure: Server Architecture for Cloudflare Python Workers

This section defines the optimal server structure for Cloudflare Python Workers implementations, addressing resource constraints and the 6 concurrent outbound connection limit.

### Connection Pool Management

Cloudflare Python Workers enforce a **maximum of 6 concurrent outbound connections** per Worker instance. The server must implement a connection pool with strict lifecycle management.

#### Pool Architecture

The worker will pool from 6 outward bound connection handling instances, with a limit of 8 Seconds per request. 2 of each worker will be provided. the types will be...
- `Get` — For any TCP connection running via port 443 or 80 which is HTTP Trafic
- `Connect (TCP)` — For any NON-HTTP port via TCP
- `Connect (UDP)` — For any UDP (Includes Http3)

### Stream Connection Lifecycle

Each stream has a defined lifecycle:

1. **CONNECT**: Attempt connection acquisition
2. **CONNECTING**: Slot acquired, establishing TCP/UDP connection
3. **CONNECTED**: Ready to send/receive DATA
4. **DRAINING**: Closing, pending DATA packets processed
5. **CLOSED**: Resource released, slot returned to pool


### Buffer Management

Each stream maintains a **send buffer** with predetermined size (recommended: 64 packets per stream):

- Client decrements `buffer_remaining` before sending DATA
- When `buffer_remaining == 0`, client waits for CONTINUE packet
- Server sends CONTINUE when `packets_received == buffer_max`
- Server sends CONTINUE proactively to minimize client wait time

**Recommended proactive CONTINUE frequency:** Every 32 packets received (50% of buffer max).

### Request/Response Loop

The server event loop processes three concurrent tasks per WebSocket:

### Error Handling & Resource Cleanup

- **Connection timeout:** 30 seconds per connection attempt
- **Read timeout:** 5 seconds per data read
- **Idle timeout:** 32 seconds of no packets → close stream
- **Pool exhaustion:** Queue pending CONNECT packets; reject if queue > 100

On any error:
1. Close the affected stream
2. Send CLOSE packet with appropriate reason code
3. Release connection slot for pending queue
4. Log error for debugging (respecting Cloudflare log limits)


## UDP Support Note

UDP support is retained in this specification for forward compatibility. However, **Cloudflare Python Workers currently do not support UDP socket creation**. 

[^1]: **UDP Support Status:** UDP socket operations (`socket.SOCK_DGRAM`) are not yet available in Cloudflare Python Workers runtime. Servers implementing this specification on Cloudflare Workers must:
    - Accept `0x02` (UDP) stream type values in CONNECT packets for protocol compliance
    - Immediately respond with a CLOSE packet (reason `0x42` - unreachable destination)
    - Expected availability: Q4 2026 or later per Cloudflare roadmap
