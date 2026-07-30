# MiuMiu Chat MiniApp Demo

This is a static MiniApp bridge demonstration. It accepts only its pinned,
exact host broker URL, performs an in-memory PKCE S256 handshake, and invokes
the one-time launch-code callback only for lifecycle demonstration.

It has no MiniApp BFF, credentials, browser-side OpenID exchange, or token
storage. The SDK discards its launch-code reference as soon as the synchronous
callback returns; a caller is responsible for not retaining it. A production
MiniApp performs any exchange only through its own server-side BFF using its
protected client credentials.

Run the dependency-free SDK tests with `npm test`.
