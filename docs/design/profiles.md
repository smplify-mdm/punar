# Profiles — bounded identities, policy, and lifecycle

**Status:** product direction accepted 2026-08-28; security architecture and
implementation pending.

**Owner direction:** Punar should support personal, work, home-automation, and
other profiles. Profiles may be activated manually, for a bounded time, or by
a reviewed local or signed event. Encryption and management have both device-
wide and profile-specific responsibilities. The idea must be complete before
the interface or persistence format becomes a compatibility promise.

## What a profile is

A Punar profile is a durable isolation and policy boundary for one purpose. It
is not a color theme, notification preset, browser folder, or mutable label on
one Linux user. Activating a profile selects a separately attributable storage,
secret, process, network, application, peripheral, and policy context.

The product uses five distinct nouns:

- **device** — the physical machine and the one installed Punar system;
- **account** — a human identity that can authenticate locally;
- **profile** — a purpose-bound context owned by an account, an organization,
  or the device itself;
- **project** — source and toolchain isolation inside a human profile;
- **service profile** — a deliberately headless, long-running purpose such as
  a Home Assistant hub, with no human desktop identity.

This document's profile must not be confused with the existing hardware
`DeviceProfile` classifier or with an AI agent's authority profile. The public
name may change before schemas ship if a collision-free term is clearer.

## The authority stack

Effective authority is evaluated from broadest to narrowest:

```text
OS hard safety constraint
  → device policy and posture
    → account boundary
      → active profile policy
        → project/application policy
          → temporary human approval
```

Each lower layer may narrow a higher layer. It cannot widen a denied device or
OS capability. A temporary grant is bounded to the exact capability, subject,
profile, and expiry and still cannot override a hard constraint. “Developer,”
“personal,” and “home” are never bypass modes.

## Scope is explicit

| Concern | Device scope | Profile scope |
|---|---|---|
| Verified boot, kernel, firmware trust | Always | Never |
| Physical-drive encryption | Always | Never represented as profile-only |
| Additional encrypted storage | Provides the substrate | Optional separately keyed profile vault/home |
| OS and kernel update | One atomic device release | May choose app/tool cadence within device policy |
| Enrollment | Device enrollment and attestation | Optional managed-profile enrollment |
| Hardware posture/inventory | One measured device fact set | Receives only the disclosed subset it needs |
| Firewall | Non-bypassable safety floor | Narrower routes, peers, listeners, DNS, and VPN |
| Apps and browser data | Signed supply and global deny floor | Separate install visibility, data, sessions, defaults |
| Projects and AI agents | Runtime safety primitives | Separate sessions, authority, ledgers, and secrets |
| USB, camera, microphone, Bluetooth | Device broker owns hardware | Explicit device-by-device/profile grants |
| Notifications and appearance | Accessibility/emergency floor | Separate preferences and interruption rules |
| Resource use | Device availability floor | CPU, memory, storage, I/O, and background budgets |

“Device or profile scoped” therefore means two typed capabilities with
different effects, never a single ambiguous switch.

## Profile classes

The initial product vocabulary is small and behavior-based:

- **Personal** — locally owned, no organization authority, no silent escrow.
- **Work** — organization-owned or hybrid; policy and disclosure contract are
  visible before enrollment and after every material change.
- **Lab** — disposable or expiring experimentation with tighter containment
  and an explicit persistent-data choice.
- **Service** — headless, bounded service lifecycle; Home Hub is one template.
- **Custom** — user-defined from the same typed capabilities, not arbitrary
  setup shell commands.

Names and icons are editable presentation. Class, owner, storage model, and
authority source are security facts and cannot be changed cosmetically.

## Isolation contract

Human profiles use separate OS identities, homes, secret namespaces, browser
stores, application data, D-Bus sessions, process/cgroup ownership, and project
container namespaces. A same-UID environment-variable or directory toggle does
not satisfy this contract.

Multiple profiles may be unlocked concurrently only when isolation remains
enforced. Exactly one human profile owns the active local seat. Background work
from another profile is off by default and visible when allowed. Service
profiles are the exception: they have a non-login service identity, bounded
resources, no clipboard or desktop session, and their own lifecycle controls.

Cross-profile clipboard, drag/drop, filesystem mounts, IPC, credentials,
browser cookies, notifications, search results, and recent-file indexes are
denied by default. A transfer uses a human-reviewed broker that identifies the
source, destination, data class, persistence, and policy citation. It never
becomes a broad shared folder as a side effect.

## Encryption and key ownership

Punar first encrypts the physical data partition with LUKS2. That is a device
property because every profile depends on the same block device and boot path.
The device recovery contract remains the one already defined for installation:
an unenrolled owner receives and confirms a recovery key; an enrolled device
may escrow a device recovery envelope under the disclosed organization policy.

A profile can add a second cryptographic boundary around its home or vault. Its
key is generated independently and is available only while that profile is
unlocked. The implementation must prove crash-safe creation, key rotation,
backup/restore, suspend/hibernate behavior, low-memory key eviction, and that
inactive-profile plaintext is absent from indexes and caches before choosing a
backend. Candidate mechanisms must be spiked rather than assumed; a directory
permission under the already-unlocked device volume is not encryption.

Key recipients are typed:

- a personal profile may wrap to the person's credential and an explicitly
  copied personal recovery key;
- a managed work profile may additionally wrap to an organization recovery
  recipient, with the organization and scope visible to the person;
- device escrow never implicitly grants profile-vault escrow;
- profile escrow never grants the organization access to another profile;
- no local or portal log contains a plaintext recovery key.

Removing an organization recipient is a key-rotation transaction, not a JSON
flag. “Remote wipe” is reported as requested, acknowledged, key-revoked, or
locally completed; an offline device is never falsely reported erased. Backups
carry their own recipient and retention contract, so deleting a local key does
not pretend all copies vanished.

## Management without ownership creep

Punar supports two management shapes:

1. **Managed device:** the organization governs disclosed device capabilities
   and may govern one or more profiles. Personal-profile contents remain out of
   inventory unless a separate, explicit contract says otherwise.
2. **Managed profile on a personal device (BYOD):** the organization governs
   its profile and receives only the minimum device posture needed to decide
   whether that profile may unlock. It does not acquire device-wide software,
   query, recovery, or remote-action authority by implication.

Enrollment shows a plain-language receipt: owner, capability domains, posture
facts disclosed, keys escrowed, remote actions allowed, data retention, offline
grace, and exit consequences. Device and profile compliance are separate
results. A healthy personal profile cannot mask a noncompliant work profile,
and work compliance cannot be drawn over the whole personal device.

Organization policy may force its profile to lock, suspend, rotate keys, or
expire. It cannot silently activate the camera, microphone, location, another
profile, or a cross-profile transfer. Unenrollment exports or destroys work
data only according to the receipt the person accepted.

## Activation triggers

Every trigger is a typed rule with an owner, source, action, priority, start,
optional expiry, cooldown, and last evaluation. Supported trigger families can
include:

- manual selection or a bounded “use for 90 minutes” action;
- a local schedule using the device's trusted clock state;
- presence of a reviewed dock, display, security key, or peripheral identity;
- joining a reviewed network identity (not a mutable display name alone);
- a signed organization event addressed to this device/profile;
- device posture transitions, such as work policy becoming noncompliant;
- an explicitly opted-in, locally evaluated geofence when a location provider
  exists; location is never required for profiles.

Triggers default to **suggest activation**. Automatic activation is available
only after the person reviews the exact effects and whether authentication is
required. A trigger never types a password, opens a profile vault unattended,
or steals the active seat. Automatic deactivation may lock a profile; it must
give running foreground work a clear countdown unless immediate lock is an
already-disclosed security rule.

Conflict resolution is deterministic: OS safety, then device policy, then
profile-owner policy, then user rules; within one authority, explicit priority
and newest reviewed revision resolve ties. The UI shows why a rule won. Wall
clock rollback, network spoofing, duplicated USB identities, and replayed
remote events fail closed and are negative-tested.

## Lifecycle

A profile moves through a closed state machine:

```text
absent → provisioning → locked → activating → active → deactivating → locked
                                      ↓             ↓
                                  suspended ← policy/expiry
                                      ↓
                               removing → removed
```

Provisioning and removal are transactions with receipts. `Active` means its
key, policy, namespace, and required services all verified; a partially mounted
or partially governed profile is failed, not active. Expiry locks first and
then applies the reviewed retention action. Suspension preserves encrypted data
but refuses activation. Removal waits for services to stop and states which
local and backup copies remain.

## User experience

The top bar shows the active profile only when more than one meaningful context
exists. Switching opens a preview with:

- who owns the profile and which authority governs it;
- data and applications that become visible;
- VPN, routes, DNS, listeners, and remote services that change;
- peripherals and secrets that will be granted or revoked;
- background services that start or stop;
- time/event rule and expiry, if any.

The primary actions are **Switch**, **Lock**, and **Finish session**. A service
profile instead uses **Start**, **Stop gracefully**, and **Force stop**; the
last action is visually destructive and explains possible data loss. Profile
switching never calls force stop merely to appear fast.

System Control has separate **Device** and **Profiles** sections. Device
encryption, device enrollment, and OS updates never move into the currently
selected profile page. Search results include their scope in the title and
accessibility label.

## Home Hub template

Home Hub is a service profile intended primarily for Raspberry Pi. Its first
candidate workload is Home Assistant Container, not an undisclosed replacement
for Home Assistant OS. The template must show that Container is self-managed
and does not include the full Home Assistant Supervisor/app experience.

The service receives only its persistent encrypted configuration, selected
USB/Zigbee/Bluetooth devices, bounded CPU/memory/storage, reviewed LAN discovery
and port exposure, and explicit outbound destinations. Remote access is off by
default. The OCI image is version- and digest-bound, backup/restore is tested,
and graceful database shutdown has a product gate. A standard recipe requiring
unrestricted privileged mode or unconstrained host networking is not silently
accepted; compatibility that cannot pass Punar's confinement tests is labelled
unsupported. For a dedicated Pi that needs the complete supported ecosystem,
Punar can offer a verified handoff to the official Home Assistant OS image.

## Privacy and audit

The device records profile lifecycle, winning policy sources, capability grants,
cross-profile transfers, management commands, and security-relevant trigger
decisions. It never records document contents, clipboard contents, passwords,
secret values, browser history, precise location, or Home Assistant entity
state in the device audit trail.

Local profile metadata is not uploaded merely because a device or another
profile is enrolled. Remote inventory is generated per management contract and
names its scope. The shell never infers profile activity from demo fixtures or
from the presence of an installed application.

## Resource contract

An inactive human profile adds no polling daemon and keeps no application
process alive unless the person reviewed a background exception. Trigger
sources are event-driven through existing device services; duplicate per-
profile network, time, and hardware pollers are forbidden. Service profiles
have visible steady-state budgets and cannot starve the active seat or the
update/recovery path.

## Definition of done

1. Two human profiles use different UIDs, homes, secrets, browser stores,
   application data, IPC, process ownership, search history, and network policy.
2. Locked-profile plaintext and keys are absent from other profiles, swap,
   hibernation, crash reports, indexes, logs, and portal payloads.
3. Device encryption and device management are never mislabelled as belonging
   only to the active profile.
4. Device enrollment, managed-profile BYOD, and a fully personal device each
   pass positive and negative authority tests.
5. No lower policy layer or temporary grant can widen an OS/device denial.
6. Manual, scheduled, local-event, signed-event, expiry, conflict, clock-skew,
   replay, and offline trigger paths are deterministic and audited.
7. Switching, locking, graceful finish, force stop, suspend, expire, unenroll,
   recovery, key rotation, backup, restore, and removal survive power loss at
   every transaction boundary.
8. Cross-profile filesystem, clipboard, IPC, secret, network, peripheral, and
   notification access fails closed without a typed broker grant.
9. Home Hub proves bounded devices, LAN exposure, outbound access, backup,
   restore, update, graceful shutdown, and zero access to human profiles.
10. Inactive profiles add zero steady-state wakeups; active profile and service
    budgets remain inside the constrained-device performance contract.

## Required spikes before schemas

- compare separately keyed profile-home mechanisms against the current LUKS2 +
  Btrfs layout, including recovery, suspend, resize, backup, and crypto erase;
- prove per-profile network namespaces with browsers, VPNs, multicast discovery,
  rootless projects, and an active local seat;
- prove seat switching without clipboard, notification, portal, or GPU leakage;
- define minimum posture disclosure and key recipients for managed-profile BYOD;
- confine Home Assistant's discovery and hardware access without a hidden
  unrestricted privileged/host-network grant;
- measure one inactive profile, two unlocked profiles, and Home Hub steady state
  on the lowest supported Raspberry Pi class.

No profile schema, portal API, or marketing claim ships until these spikes close
the security and recovery questions above.

## Product references

- Home Assistant describes Home Assistant OS as its recommended installation
  type and documents the Raspberry Pi path:
  <https://www.home-assistant.io/installation/raspberrypi/>.
- Its Linux installation page distinguishes Home Assistant Container from the
  Home Assistant OS/Supervisor experience:
  <https://www.home-assistant.io/installation/linux/>.
- Its installation overview is the source of truth if those supported methods
  change: <https://www.home-assistant.io/installation/>.
