"""Textual front-end for the VLESS profile manager.

The TUI is a *front end over the same service* the CLI uses — it never talks to
Xray, the Keychain, or the network directly. Everything slow happens in a
``@work(thread=True)`` worker; see :mod:`vlessp.tui.app` for the threading rules
and :mod:`vlessp.tui.screens` for the credential-handling order.
"""
from __future__ import annotations

from vlessp.tui.app import VlessApp
from vlessp.tui.screens import AddProfileScreen, ConfirmScreen, EditProfileScreen
from vlessp.tui.widgets import ProfileTable, StatusBar

__all__ = [
    "AddProfileScreen",
    "ConfirmScreen",
    "EditProfileScreen",
    "ProfileTable",
    "StatusBar",
    "VlessApp",
]