#!/usr/bin/env python3
"""Compatibility shim for the pre-V1 single-file launcher.

V0 shipped one 557-line module. V1 splits it into :mod:`vlessp` and this file
keeps the two things that still have to work:

* ``python3 vless_proxy.py …`` -- the command line is unchanged, including every
  V0 flag. It delegates to :func:`vlessp.cli.main`.
* ``from vless_proxy import AppError, build_xray_config, parse_vless_uri`` --
  ``tests/test_vless_proxy.py`` is the V0 parser suite and is meant to keep
  running *unmodified* through this refactor. Those three names are re-exported
  for exactly that reason and are the only implementation that lives here.

There is deliberately no other code below this point. Anything added to this file
is code that no longer has a test and no longer has an owner.
"""
from __future__ import annotations

from vlessp.cli import main
from vlessp.errors import AppError
from vlessp.links import build_xray_config, parse_vless_uri

__all__ = ["AppError", "build_xray_config", "main", "parse_vless_uri"]


if __name__ == "__main__":
    raise SystemExit(main())