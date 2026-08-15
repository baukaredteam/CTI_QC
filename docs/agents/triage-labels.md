# Triage Labels

The mattpocock engineering skills speak in terms of five canonical triage roles. This file maps those roles to the label/`Status:` strings used in this repo's local markdown tracker.

| Skill role | Our `Status:` value | Meaning                                   |
| ---------- | ------------------- | ----------------------------------------- |
| `needs-triage`    | `needs-triage`    | Maintainer needs to evaluate this issue   |
| `needs-info`      | `needs-info`      | Waiting for info / not fully specified    |
| `ready-for-agent` | `ready-for-agent` | Fully specified, ready for an AFK agent   |
| `ready-for-human` | `ready-for-human` | Requires human implementation            |
| `wontfix`         | `wontfix`         | Will not be actioned                      |

When a skill mentions a role (e.g. "apply the AFK-ready label"), use the corresponding string from this table for the issue's `Status:` line.