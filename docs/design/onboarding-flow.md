# First run — the binding onboarding flow

**Status:** accepted product contract; implementation and live proof pending.

**Owner direction (2026-08-26):** account creation asks for username,
password, and device name; onboarding stays simple and feels inviting.
This document supersedes the seven-stage interaction in `onboarding.md`,
Plate D-008 where they conflict, and Milestone 13's autologin-only first run.
The detailed identity/storage/security research in `onboarding.md` remains the
backend reference.

## The whole experience

First run is one calm card over Stillpoint. There is no progress rail and no
fake tour. The top bar says `WELCOME TO PUNAR` and offers a quiet keyboard
layout control because entering a password with the wrong keymap is a lockout,
not a preference. The card says:

```text
Make this machine yours.
Three details, then the desktop is ready.

USERNAME
alice
Your home folder and terminal name. This cannot be changed later.

PASSWORD                         CONFIRM PASSWORD
••••••••••••                     ••••••••••••
Use 10 or more characters. No symbol rules, no forced rotation.

DEVICE NAME
Alice's ThinkPad
Network name: alices-thinkpad

                                      CONTINUE  ↵

Local account · Created on this device
No email required · Start without a cloud login
Private setup · These details stay here
```

Those are exactly three required user-provided values. Confirmation verifies
the password and is not a fourth value. Timezone is not an onboarding question:
Punar automatically accepts RFC 4833 timezone data from the local DHCP server
and otherwise keeps the honest UTC fallback. It does not call a GeoIP service.
The user can search the installed IANA timezone catalog and make a manual,
audited choice later in **System Control › System › Date & Time**; that choice
then disables later network timezone overrides. There is no full name, avatar,
account type, organization, telemetry, AI, theme, wallpaper, or update
question. Their defaults are already safe:

- display name falls back to the username and can be edited later;
- Stillpoint and the Paper theme make the first desktop immediately coherent;
- telemetry and cloud sync do not exist;
- the device starts personal and unenrolled;
- network, timezone, enrollment, appearance, and accessibility remain
  discoverable in System Control after the desktop is usable.

After the desktop is usable, a separate, dismissible **Set up your
workstation** guide may help the user choose AI tools, secure connectivity,
project environments, or REST API testing. It is optional, performs only real
catalog-backed actions, and never adds questions or fabricated state to this
account-creation flow. See `workstation-activation.md`.

The three closing facts describe this setup transaction, not every future
network action an installed app can take. In particular, the interface does
not claim that "nothing leaves this machine": a browser can use the network
and an explicitly enrolled device can later exchange the governed fields in
its enrollment contract. The truthful promise here is narrower and stronger:
the local account needs no email or cloud login, and the account details are
processed on the device. Automatic timezone only receives a setting offered by
the connected network; the later manual chooser reads local tzdata.

If the account is created successfully, the same card—not a new wizard page—
morphs into a short receipt:

```text
You're ready, alice

RECOVERY CODE                     COPY
7K3M2-R9…-8Q1JH
Save this somewhere off the device. It is shown once.

                                  ENTER DESKTOP  ↵
```

The transition is the only flourish: 300 ms, one opacity/vertical movement,
then the desktop. Reduced-motion mode makes it instant. A recovery code is an
output of account creation, never another question.

## Interaction rules

- The username field is focused first. `Tab` follows visual order; `Shift+Tab`
  reverses; `Enter` continues only when every field is valid; `Escape` does not
  bypass first run.
- Validation happens after blur or Continue, not on the first keystroke. One
  concise reason appears directly below the field and focus returns there.
- Username: `^[a-z][a-z0-9_-]{0,31}$`, not ending in `-`, excluding existing
  accounts and reserved Punar/system names. It is permanent.
- Password: 10–256 bytes, no composition rules, offline common-password and
  username/device-name checks, yescrypt at rest. The reveal control is
  keyboard reachable and springs back to concealed on focus loss.
- Device display name: trimmed 1–64 grapheme clusters. The RFC-1123 hostname
  derived beneath it updates live and is validated by `system.hostname`.
- Errors never clear a valid field or either password. A backend failure says
  what was not changed and offers Retry; it never drops to a shell.
- Screen readers receive labels, descriptions, error association, password
  visibility state, and the one-time recovery warning. At 200% scale the card
  scrolls rather than clipping Continue.

## Security and persistence contract

The production image contains no login-capable placeholder user and no greetd
`initial_session`. Root is locked. The first account is a standard user in the
`punar` admission group, never `wheel`, and elevates through typed JIT grants.

Account creation is one transactional privileged operation. It validates all
three values before mutation, allocates uid/home/subuid/subgid, writes the
versioned account and authenticator records under `/var`, materializes NSS,
sets the hostname, creates the recovery record, and commits the completed
marker only after all verification succeeds. A failure rolls back any new
account/home and leaves onboarding open; it never leaves a half-created login.

The password must never appear in argv, environment, a QML log, a temporary
file, desired state, audit details, crash artifacts, or IPC responses. The
first-run client sends a length-framed request over an admitted local channel;
the daemon stores the secret in a zeroizing buffer and returns only a typed
verdict. Qt necessarily holds the characters transiently in the password
input; the surface clears both fields immediately after the request and never
binds their values into any other property. This limit is explicit rather than
claiming impossible heap zeroization for `QString` copies.

The account record, password hash, recovery hash, device name, home, and
first-run marker live on shared `/var` or `/home`, not an A/B root slot. They
survive update and rollback. The one-time recovery plaintext exists only in
the daemon response and visible receipt until Enter Desktop.

## Performance contract

The first-run component is loaded only while the completion marker is absent
and is destroyed before the desktop handoff. It adds no resident post-login
surface, daemon, polling loop, network request, or periodic timer. Stillpoint
is already the desktop texture; onboarding adds a card, not a second full-screen
image decode.

## Definition of done

The flow is not complete until CI and a human VM run prove all of these:

1. Fresh production image has no `punar` login, no autologin, and a locked root.
2. Mouse-free account creation with username/password/device name reaches a
   session owned by the new uid; logout returns to a real greeter and the same
   password logs back in.
3. Invalid/reserved/colliding usernames, mismatched/weak passwords, invalid
   device names, and a simulated mid-transaction failure leave no partial
   account, home, hash, hostname, or completion marker.
4. Greeter, lock screen, terminal, home ownership, `getent`, subuid/subgid, and
   audit attribution all resolve the created account.
5. Password/recovery plaintext negative scans cover process argv/environment,
   journal, audit, exported artifacts, desired state, and world-readable files.
6. A/B update and rollback preserve the account and successful authentication.
7. Keyboard, screen-reader, 200% scale, reduced-motion, and recovery-copy paths
   are exercised; screenshots capture the empty, validation, receipt, desktop,
   and post-logout greeter states.
8. The first-run component has zero resident memory after handoff and adds zero
   idle wake-ups; the normal desktop remains within the published RAM budget.

Until every item passes on the production image, the dev-image `punar/punar`
autologin remains explicitly a test fixture and onboarding remains unshipped.
