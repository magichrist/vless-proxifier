"""vlessp — VLESS profile manager.

Public surface, in dependency order. Each module owns exactly one job:

    errors       AppError, the shared error contract
    links        parse_vless_uri / build_xray_config   (pure, no I/O)
    profiles     Profile model + ProfileStore          (JSON, never sees a UUID)
    secrets      SecretStore + macOS Keychain + null   (the only Keychain caller)
    xray         binary install + process supervision   (subprocess)
    proxy        ProxyService, the orchestration seam
    latency      one-shot server reachability probe
    cli          argparse entry point
    tui          Textual front-end

Nothing here imports a later module from an earlier one. `errors` is the only
shared leaf.
"""

__version__ = "0.2.0"

APP_NAME = "vless-python-proxy"