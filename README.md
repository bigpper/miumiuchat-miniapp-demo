# MiuMiu Chat MiniApp Demo

This is a static MiniApp bridge demonstration. It accepts only its pinned,
exact host broker URL, performs an in-memory PKCE S256 handshake, and invokes
the one-time launch-code callback only for lifecycle demonstration.

Electron uses only the exact `miniAppHostBridge` API exposed by the isolated
preload context. It verifies the Electron terminal contract and unregisters the
native listener on page teardown.

HTTPS browser hosts use the isolated nested broker. Two pinned local development
brokers use an exact-source parent bridge because an HTTPS MiniApp cannot embed
an HTTP broker as active mixed content:

- `http://localhost:8080/miniapp-host-broker.html` is the Web local host broker.
- `http://localhost:5173/h5/static/miniapp-host-broker.html` is the UniApp H5
  local host broker.

The fallback is restricted to these two exact URLs, correlates a fresh binding
identifier, rejects transferred ports, and still verifies both `source` and
`origin` on every message. Other ports, paths, queries, and fragments are not
trusted.

It has no MiniApp BFF, credentials, browser-side OpenID exchange, or token
storage. The SDK discards its launch-code reference as soon as the synchronous
callback returns; a caller is responsible for not retaining it. A production
MiniApp performs any exchange only through its own server-side BFF using its
protected client credentials.

Run the dependency-free SDK tests with `npm test`.
