# Security notes

- Proxy listeners are restricted to loopback addresses by default.
- TLS certificate verification is enabled by default. `--allow-insecure` weakens TLS authentication; avoid it.
- The URI is not saved by default. Avoid the `--link` option for credentials if other local users can inspect process arguments.
- Link files must be private on POSIX systems (`chmod 600`); parent config directory should be private (`chmod 700`).
- Xray configuration is written to a short-lived config file with `0600` permissions under a `0700` directory because Xray's CLI consumes JSON files. It is removed when the process exits.
- The downloader accepts only the official XTLS/Xray-core release API and release assets, applies a download size limit, and verifies the archive against the accompanying SHA-256 `.dgst` file before installing.
- No software release checksum fetched from the same hosting service substitutes for independently verified signed provenance. For high assurance, verify the Xray release signature/provenance using the upstream's documented method.
- Do not expose SOCKS/HTTP ports to LAN/public interfaces. There is no proxy authentication in this simple local-only version.
