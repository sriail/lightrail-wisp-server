# Wisp-CF — Wisp v1.2 for Cloudflare Workers 

Based on Wisp v1.2 by [@ading2210](https://github.com/ading2210). Packet layouts, the WebSocket
transport and their semantics are unchanged unless listed below. All integers are little-endian.

## 1. Changes from Wisp v1.2

1. **UDP removed.** CONNECT with stream type `0x02` is answered with CLOSE `0x41`. The v1.2 sentence
   "UDP support is mandatory" does not apply to this profile.
2. **Inbound transport is WebSocket over TLS only (`wss://`)**, as in Wisp v1.2. Plain `ws://` is refused.
3. **Outbound is limited to raw TCP and HTTP GET.** The server never opens a WebSocket on a client's
   behalf; an HTTP-lane request carrying `Upgrade: websocket` is answered `501`.
4. **At most 6 simultaneous upstream operations per session** (Cloudflare per-invocation limit). Excess
   work is **queued** (section 3.5) instead of rejected.
5. **HTTP lane.** CONNECTs to ports 80 and 443 are served by GET fetches, not raw sockets (section 3.6).
6. **Bounded stream lifetime.** TCP streams are cut by idle and maximum-lifetime timers.
7. **Raw TCP** (all other ports, and the TLS fallback) never has TLS added or removed by the server. The
   client does TLS itself (as epoxy-tls and libcurl.js do) and the server forwards bytes unchanged.

## 2. Packet format (unchanged)

| Field Name  | Field Type | Notes |
|-------------|------------|-------|
| Packet Type | `uint8_t`  | `0x01` CONNECT, `0x02` DATA, `0x03` CONTINUE, `0x04` CLOSE |
| Stream ID   | `uint32_t` | Assigned by the client. `0` is reserved for the version/initial CONTINUE. |
| Payload     | `char[]`   | Rest of the packet. |

Each Wisp packet is carried in exactly one WebSocket **binary** message. No length prefix is used.

## 3. Packet types

### 3.1 `0x01` CONNECT (client → server)

| Field Name           | Field Type | Notes |
|----------------------|------------|-------|
| Stream Type          | `uint8_t`  | `0x01` TCP. `0x02` UDP is **not supported** → CLOSE `0x41`. Any other value → CLOSE `0x41`. |
| Destination Port     | `uint16_t` | 1–65535. `0` → CLOSE `0x41`. Port `25` → CLOSE `0x48`. |
| Destination Hostname | `char[]`   | UTF-8, 1–253 bytes, domain name or IP literal. Invalid → CLOSE `0x41`. |

Server behaviour:

* Validate the payload; on failure send CLOSE `0x41` for that stream ID.
* Apply the destination policy (section 7); a blocked destination → CLOSE `0x48`.
* If `MAX_OPEN_STREAMS` streams already exist (open, queued or connecting) → CLOSE `0x49`.
* A CONNECT for a stream ID that already exists is a protocol violation: CLOSE `0x41` for it and tear
  the existing stream down.
* Classify the stream by port (section 3.6): **HTTP lane** (ports 80, 443 by default) or **TCP lane**.
* TCP lane: queue a connect job (section 3.5). When a slot is free, open the socket with the platform
  `connect()` API, `secureTransport: "off"`. Connect timeout `CONNECT_TIMEOUT_MS` (default 8000) →
  CLOSE `0x43`.
* The client MAY send DATA right after CONNECT without waiting; the server buffers it (3.2).

### 3.2 `0x02` DATA (both directions)

Payload is the raw stream bytes.

* Client → server: appended to a per-stream FIFO of at most `BUFFER_SIZE` packets (default 128). TCP lane:
  drained into the socket once connected. HTTP lane: fed to the request parser. Overflow → CLOSE `0x49`
  for that stream.
* Server → client: split into DATA packets of at most `DATA_CHUNK` payload bytes (default 16384). Small
  consecutive chunks of one stream may be coalesced.
* DATA for an unknown or already-closed stream ID is ignored.

### 3.3 `0x03` CONTINUE (server → client)

| Field Name       | Field Type | Notes |
|------------------|------------|-------|
| Buffer Remaining | `uint32_t` | Packets the server can still buffer for this stream. |

* Immediately after the WebSocket is established, the server sends CONTINUE with Stream ID `0` and
  `BUFFER_SIZE`. Stream ID `0` means Wisp v1. Clients initialise each new stream's send budget to this
  value and must wait for this packet before sending.
* Per stream (TCP lane): after the writer has flushed at least `BUFFER_SIZE / 2` packets since the last
  CONTINUE, the server sends CONTINUE(stream, `BUFFER_SIZE − packets_still_queued`).
* HTTP lane: no per-stream CONTINUE is sent.
* The client decrements its budget per DATA packet sent and stops at zero until the next CONTINUE, exactly
  as in Wisp v1.2.

### 3.4 `0x04` CLOSE (both directions)

| Field Name  | Field Type | Notes |
|-------------|------------|-------|
| Close Reason | `uint8_t`  | See table. |

A CLOSE immediately ends the stream and its upstream operation. **Exactly one CLOSE is sent per stream
by the server; no DATA follows it.**

| Code | Sender | Meaning in this profile |
|------|--------|-------------------------|
| `0x01` | both | Unspecified. |
| `0x02` | both | Voluntary close; server uses it when the upstream closed cleanly (EOF) or a fetch finished normally. |
| `0x03` | both | Network error after the stream was established. |
| `0x41` | server | Invalid CONNECT (bad type/port/host, UDP requested, duplicate stream ID, unparsable request head). |
| `0x42` | server | Destination unreachable / does not resolve. |
| `0x43` | server | Connect or fetch timed out. |
| `0x44` | server | Connection refused. |
| `0x47` | server | Data transfer cut: stream idle timeout, maximum stream lifetime, byte cap reached. |
| `0x48` | server | Destination intentionally blocked (policy, Cloudflare address ranges, private/loopback, port 25, self). |
| `0x49` | server | Throttled: queue full, queue wait exceeded, too many streams, subrequest budget exhausted, or per-stream buffer overflow. |
| `0x81` | client | Client error, cannot receive more data. |

### 3.5 Queueing

* At most 6 upstream operations run at once per session (sockets plus in-flight fetches).
* Default split: 4 fetch slots (heads H0–H3) and 2 TCP slots (T0–T1). A lane may borrow idle slots of the
  other lane only while the other lane has nothing queued; borrowed slots are never preempted.
* Waiting jobs sit in a bounded queue (`QUEUE_MAX`, default 64) served round-robin per stream, so no stream
  can starve another.
* A job waiting longer than `QUEUE_WAIT_MS` (default 10000) or arriving at a full queue fails with CLOSE
  `0x49` (HTTP lane: preceded by a synthetic `503` response with `Retry-After: 1`).
* Every `fetch()` counts against `SUBREQUEST_MAX` (default 45) for the whole WebSocket session.
  Exhausted → CLOSE `0x49` for new HTTP jobs. With `ROTATE_ON_BUDGET` (default true) the server then drains
  in-flight streams for up to `DRAIN_MS` (default 5000) and closes the WebSocket with code `1001`; the
  client reconnects to get a fresh budget.

### 3.6 Lanes

| Lane | Ports | Upstream mechanism | Stream content |
|------|-------|--------------------|-----------------|
| HTTP | `HTTP_LANE_PORTS` (default 80, 443) | `fetch()` by a head | Client sends one HTTP/1.x request; server answers with a synthetic HTTP/1.1 response, then CLOSE `0x02`. One request per stream. |
| TCP  | all others | `connect()` in a TCP slot | Opaque bytes both ways. |

HTTP lane rules:

* No upstream connection is opened at CONNECT time. The server parses the request head (≤
  `HTTP_HEAD_MAX`, default 65536 bytes), strictly: origin-form request line only; reject requests with both
  `Content-Length` and `Transfer-Encoding`, conflicting lengths, obsolete folding, bare LF, control
  characters.
* Methods are limited to `HTTP_LANE_METHODS` (default `GET,HEAD`); others → synthetic `405`.
  `Upgrade: websocket` → synthetic `501`.
* The upstream URL is built from the **CONNECT hostname and port** (`https` for 443, `http` otherwise) and
  the request path. The `Host` header is ignored. Hop-by-hop headers are dropped.
* Redirects are not followed; 3xx responses go to the client unchanged.
* The response is a synthetic HTTP/1.1 response: the *decoded* body (no `Content-Encoding`,
  `Content-Length` or `Transfer-Encoding`), `Connection: close`, each `Set-Cookie` on its own line, values
  sanitised against CR/LF injection; the end of the body is signalled by CLOSE `0x02`, not by length. Body
  cap `HEAD_MAX_BYTES` (default 32 MiB) → CLOSE `0x47`. Fetch timeout `HEAD_TIMEOUT_MS` (default 15000).
* **Fallback:** if the first bytes are not an HTTP request (for example a TLS ClientHello `0x16 0x03`),
  `LANE_FALLBACK=tcp` (default) re-labels the stream as TCP lane and replays the bytes through
  `connect()`; `LANE_FALLBACK=reject` answers CLOSE `0x48`. TLS performed by the client cannot be
  converted to GET.

## 4. WebSocket transport

### 4.1 Endpoint

`wss://<host><WISP_PATH>` with `WISP_PATH` ending in `/` (default `/wisp/`). If the deployment sets a
secret, the endpoint is `wss://<host><WISP_PATH><secret>/`; the prefix is used for gatekeeping as the original
spec allows. wsproxy-style `host:port` paths are not supported (`404`). The `Sec-WebSocket-Protocol` header
is not required.

Failures before the upgrade use plain HTTP status: `426` request to the Wisp path without a WebSocket
upgrade, `403` non-TLS request or `Origin` not allowed, `404` unknown path or wrong secret, `405` wrong method.

### 4.2 Messages

* Binary messages only; one Wisp packet per message. A text message closes the WebSocket with `1003`.
* A message shorter than 5 bytes closes it with `1002`; a message larger than `MAX_FRAME_BYTES` (default
  1 MiB) closes it with `1009`.
* The first message sent by the server is the stream-0 CONTINUE.

### 4.3 Session lifetime

* One WebSocket connection is one session with its own slots, queue, stream table and subrequest budget.
* The session ends when either side closes the WebSocket, on `SESSION_MAX_MS` (default `0` = no limit; when
  set, the server closes with `1001` after draining for `DRAIN_MS`), or on budget rotation (3.5). On session
  end all streams are cancelled and all sockets closed.
* A TCP-lane stream with no bytes in either direction for `STREAM_IDLE_MS` (default 15000) is closed with
  `0x47`. A TCP-lane stream older than `STREAM_MAX_MS` (default 60000) is closed with `0x47`.
* The 6-operation limit is per WebSocket. A client wanting more parallelism opens another WebSocket.

## 5. Stream ID rules

Client-chosen, unique within a session. IDs from different sessions are unrelated.

## 6. Destination policy

Applies to every CONNECT hostname (both lanes). Deny (CLOSE `0x48`; HTTP lane: synthetic `403` first):

* loopback, private, link-local, CGNAT and metadata addresses (`127/8`, `10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, `100.64/10`, `::1`, `fc00::/7`, `fe80::/10`), `localhost`, `*.local`, `*.internal`;
* the Worker's own hostname (loop protection);
* port `25`;
* any host in `BLOCK_HOSTS` (comma list); if `ALLOW_HOSTS` is non-empty only those hosts (suffix match)
  are allowed.

The runtime also refuses `connect()` to Cloudflare IP ranges and to hostnames that resolve to private
addresses; map those errors to CLOSE `0x48`.

## 7. Platform limits this profile is built around

| Limit | Value |
|-------|-------|
| Simultaneous outbound connections per invocation (sockets + fetches awaiting headers) | 6 |
| Subrequests per invocation | 50 Free / 10 000 Paid (profile default budget 45) |
| CPU time per request | 10 ms Free / 30 s default, 5 min max Paid (check whether it accumulates across a WebSocket) |
| Memory | 128 MB per isolate |
| WebSocket message size (received) | 32 MiB (this profile caps at `MAX_FRAME_BYTES`) |
| Wall time | no hard limit while the client stays connected |

A relay that forwards many bytes will exceed 10 ms CPU on the Free plan; deploy on Workers Paid for real use.

## 8. Client compatibility

* **epoxy-tls:** connect to `wss://<host>/wisp/` with Wisp v2 disabled (this profile is v1 only).
* **libcurl.js:** set its WebSocket URL to `wss://<host>/wisp/`.
* **Plain HTTP (port 80) and cleartext-to-443:** served by the HTTP lane.
* **TLS inside the client:** passes through the TCP-lane fallback (section 3.6) and is limited by TCP slots
  and the stream timers; it cannot be converted to GET.
* **Subprotocol:** the server does not select a subprotocol. If a client refuses the connection because it
  offered one, echo the first offered subprotocol that is not `wisp-v2`.
* **Limits visible to clients:** `0x49` means back off and retry; `0x47` means the stream was cut by a
  timer; WebSocket close `1001` means reconnect (budget rotation or session limit).
