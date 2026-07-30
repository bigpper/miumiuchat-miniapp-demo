# MiuMiu Chat MiniApp Demo

This is a static MiniApp bridge demonstration. It validates the host broker,
performs an in-memory PKCE S256 handshake, and accepts a one-time launch-code
callback only for lifecycle demonstration.

It has no MiniApp BFF, credentials, browser-side OpenID exchange, or token
storage. A production MiniApp must exchange a launch code only through its own
server-side BFF using its protected client credentials.

Run the dependency-free SDK tests with `npm test`.
