# Managed application configuration

**Status:** accepted design; lifecycle enforcement is implemented, per-app
configuration adapters are not yet shipped.

**Extends:** [`app-catalog.md`](app-catalog.md) and SPEC section 46.

## 1. Product promise

Punar must make the personal path simple and the managed path deterministic:

- a personal device offers **Install**, **Open**, and **Uninstall**;
- an enrolled device applies `required`, `denied`, and `allowUserInstall`
  before any package mutation;
- an organization may configure supported applications without asking a user
  to edit files, run commands, or sign in to a second management agent;
- the same inventory record reports the installed version, source, policy,
  configuration generation, enforcement result, and drift state;
- unenrollment removes organization-owned configuration without deleting the
  user's application data.

Application policy is not a shell-command delivery channel. No desired-state
field may contain an executable, argv, environment variable, package-manager
option, URL outside a catalog adapter, or arbitrary filesystem path.

## 2. Two separate controls

Lifecycle and configuration are intentionally separate.

| Control | Question | Current state |
|---|---|---|
| Lifecycle | Must, may, or must not this catalog id be installed? | Implemented in `punard` |
| Configuration | Which vendor-supported settings must the installed app use? | Typed adapters pending |

A required app whose configuration cannot be enforced is not compliant. Punar
must not report success merely because the package exists.

## 3. Typed adapter rule

Every supported application has a compiled adapter with a closed contract:

```text
catalog id
  -> supported configuration schema version
  -> validated typed settings
  -> fixed machine/profile destination owned by the adapter
  -> atomic write
  -> re-read through the application's documented format
  -> exact effective-value comparison
  -> audit + compliance result
```

There is no generic “write this JSON to this path” adapter. Adding an
application means reviewing and shipping code that knows its documented Linux
policy surface, ownership, permissions, reload behavior, precedence, and
version floor.

An adapter returns one of:

- `enforced` — the destination was written and the effective value verified;
- `already_enforced` — the effective value was already exact;
- `unsupported_version` — the installed app is too old/new for this adapter;
- `unsupported_platform` — the vendor does not expose this policy on Linux;
- `invalid_configuration` — schema validation failed before any write;
- `apply_failed` — no successful atomic commit occurred;
- `verify_failed` — the app's effective readback did not match;
- `drifted` — a later observation differs from managed policy.

Only the first two are compliant.

## 4. Authority and scope

The existing lower-rank-wins policy ladder applies per setting. A device-scoped
organization setting outranks profile and user settings when both govern the
same adapter key. A profile-scoped setting applies only while that profile is
active and may be time/event bound once the profile engine ships.

Precedence must be visible in `policy.explain`; a user must be able to see:

- the effective value or a safe summary;
- the application and adapter schema version;
- device or profile scope;
- source name and policy id;
- whether user override is permitted;
- the last verification result and time.

Secrets are never configuration values. Policy carries a secret reference; a
privileged broker resolves it directly into the adapter's fixed destination.
The plaintext must not enter desired-state documents, IPC responses, argv,
environment variables, logs, audit events, inventory, or the portal UI.

## 5. Transaction boundary

Applying one generation is all-or-nothing per application:

1. validate the signed policy and adapter schema;
2. resolve lifecycle policy and installed-version compatibility;
3. stage the exact fixed destinations with restrictive modes;
4. `fsync` staged files and their parent directories;
5. atomically replace all destinations;
6. request the adapter's documented reload, if one exists;
7. re-read effective configuration and compare typed values;
8. publish audit and compliance only after verification.

If verification fails, restore the prior generation atomically and report
`verify_failed`. An application update must re-run adapter compatibility and
verification before the update is considered healthy.

## 6. Claude Desktop boundary

Anthropic documents managed Claude Desktop settings for macOS preferences and
Windows policy keys, including organization login, extensions, local MCP,
Claude Code, secure VM features, workspace folders, effort level, and update
controls. As of 2026-08-30, that document does not define an equivalent Linux
managed-policy path:

- <https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop>
- <https://code.claude.com/docs/en/desktop-linux>

Therefore Punar may manage Claude Desktop lifecycle and OS-enforceable controls
today, but must return `unsupported_platform` for vendor in-app settings until
Anthropic publishes a Linux interface that can be applied and verified. Punar
must not guess that a macOS preference name or Windows registry key maps to an
undocumented Linux file.

When a Linux interface exists, `claude-desktop` becomes a dedicated adapter.
Its schema may expose only the documented keys and their exact types/ranges;
unknown keys fail before write. Update behavior remains owned by Punar's pinned
catalog/OS channel because the Linux application is delivered through the
system package path rather than an unmanaged self-updater.

## 7. Portal and local UX

The Application Library remains one surface:

- `MANAGED · REQUIRED` replaces the uninstall affordance with the named policy;
- `MANAGED · DENIED` prevents install and offers policy explanation;
- optional managed apps retain Install/Uninstall when `allowUserInstall` is
  true;
- configuration state appears as `Managed settings · enforced`, `drifted`, or
  an honest unsupported/error state;
- a personal device never shows organization controls or synthetic policy.

The Smplify portal uses the same adapter schema to render forms. It cannot send
fields an endpoint build does not know. Plan/apply must show target count,
adapter versions, unsupported devices, change summary, staged rollout, deadline,
rollback generation, and final verified inventory.

## 8. Definition of done for one adapter

An adapter is production-supported only when all of these pass on x86_64 and
ARM64:

1. strict schema positive/negative corpus;
2. precedence and device/profile-scope tests;
3. atomic apply, crash-before-rename, rollback, and disk-full tests;
4. restrictive ownership/mode and symlink/hardlink/path-traversal tests;
5. no-secret argv/environment/log/audit/inventory tests;
6. supported-version and unsupported-version tests;
7. application effective-readback proof;
8. update compatibility and rollback proof;
9. unenrollment cleanup without user-data loss;
10. portal-to-device signed-policy and received-compliance proof.

Until that matrix is green, the portal may label the adapter **preview** but
the endpoint must continue reporting its exact unsupported or unverified state.
