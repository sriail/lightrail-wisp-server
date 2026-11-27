<div align="center">
  <img src="./wisp-rs.svg" alt="wisp-rs logo" width="200" />
  <h1><strong>wisp-rs</strong></h1>
  <p><strong>Wisp v1.2 for Cloudflare Workers (WSS in, TCP + HTTP GET out, queued)</strong></p>
</div>

---

## Core Premise

**wisp-rs** is a Rust implementation of the **Wisp-CF** profile—an adaptation of the [Wisp v1.2 protocol](https://github.com/MercuryWorkshop/wisp-protocol) (originally by `@ading2210`) engineered specifically to operate within the architectural and runtime constraints of **Cloudflare Workers**.

Because Cloudflare Workers enforce strict per-invocation limits (such as a maximum of 6 simultaneous outbound connections, subrequest caps, and no raw UDP sockets), standard Wisp servers fail under real-world concurrency. **wisp-rs** solves this by splitting traffic into smart execution lanes, transparently queueing excess connections instead of dropping them, and managing subrequest budgets gracefully.

### Architectural Adaptations Compared to Alternative Projects
* **WSS-Only Inbound:** Accepts connections strictly over WebSocket over TLS (`wss://`).
* **Dual-Lane Routing:** 
  * **HTTP Lane (Ports 80 & 443):** Intercepts plain HTTP `GET`/`HEAD` requests and serves them via native Worker `fetch()` calls to maximize throughput and conserve raw socket slots.
  * **TCP Lane (All Other Ports & TLS Fallback):** Uses Cloudflare's `connect()` socket API to forward raw, opaque TCP bytes. Client-side TLS (such as `epoxy-tls` or `libcurl.js`) is passed through untouched without server-side termination.
* **Smart Concurrency & Queueing:** Enforces Cloudflare's 6-connection ceiling per WebSocket session (defaulting to 4 HTTP fetch slots and 2 TCP socket slots with idle slot borrowing) backed by a round-robin bounded queue so concurrent streams don't starve or fail abruptly.
* **No UDP:** UDP (`0x02`) is unsupported and rejected cleanly with `CLOSE 0x41`.
* **Bounded Lifetimes & Budget Rotation:** Enforces idle and max-lifetime timers on TCP streams, and automatically drains/rotates sessions (WebSocket close `1001`) when subrequest budgets are exhausted so clients can seamlessly reconnect.

---

## Intended Use Cases

* **Edge-Hosted Browser Proxies:** Powering client-side web proxy frontends (like `epoxy-tls` and `libcurl.js`) globally on Cloudflare's edge network without managing traditional VPS infrastructure.
* **Lightweight TCP/HTTP Tunneling:** Multiplexing multiple outbound TCP and HTTP/1.x streams over a single TLS-encrypted WebSocket connection.
* **High-Concurrency Serverless Relays:** Environments where standard serverless functions would hit connection-limit errors, utilizing `wisp-rs`'s built-in queueing and backpressure (`CONTINUE` / `0x49` throttling) to keep clients stable.

---

## Client Compatibility

| Client / Mode | Configuration & Behavior |
| :--- | :--- |
| **`epoxy-tls`** | Connect to `wss://<host>/wisp/` with **Wisp v2 disabled** (this profile implements Wisp v1 only). |
| **`libcurl.js`** | Set the WebSocket transport URL to `wss://<host>/wisp/`. |
| **Plain HTTP (`80` / `443`)** | Routed through the HTTP lane via `fetch()`. |
| **Client-Side TLS** | Automatically detected via `LANE_FALLBACK=tcp` and routed through raw TCP slots. |

> **Deployment Note:** While functional on the Cloudflare Workers Free tier for light testing, forwarding substantial data will quickly exceed the 10 ms Free CPU limit. **Workers Paid** is recommended for production workloads.
