# V1 — Multi-profile VLESS client with a TUI

Turn `vless_proxy.py` from a **one-shot, one-link launcher** into a **profile manager with a
terminal UI**, so you can hold many VLESS links, switch between them without editing files,
and see which one is live.

| File | Contents |
|---|---|
| [`00-decisions.md`](00-decisions.md) | Locked decisions, rejected alternatives, why |
| [`01-architecture.md`](01-architecture.md) | Module boundaries, data model, control flow |
| [`02-tui-design.md`](02-tui-design.md) | Screens, widgets, keybindings, user flows |
| [`03-security.md`](03-security.md) | Threat model delta — persistence now exists |
| [`04-implementation-plan.md`](04-implementation-plan.md) | Phased tasks, test strategy, exit criteria |
| [`05-v2-parked.md`](05-v2-parked.md) | Decisions already made for V2 subscriptions |

## V1 in one sentence

Add a profile store, a supervised Xray process that can be **re-pointed at a different profile
without the UI knowing about Xray**, and a Textual front-end over it — while keeping the existing
headless CLI working exactly as it does today.

## Explicitly out of V1

Subscriptions, TUN/system-wide routing, per-process interception, hot config swap without
restart, background health polling, automatic failover, non-macOS platforms.

Subscriptions were **deliberately deferred**, not forgotten. Their format and refresh policy are
already decided and recorded in [`05-v2-parked.md`](05-v2-parked.md) so V2 does not re-litigate them.

## The one contract break

V1 abandons `standard-library-only`. `pyproject.toml` moves from `dependencies = []` to
`textual`. The README's opening claim must be rewritten in the same change — leaving it would
make the docs lie.