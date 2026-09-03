# User-blocked items

**Status:** living document · created 2026-08-25
**Why it exists:** the standing mandate is a production-ready distro. Most of
that is engineering work this project can do and gate in CI. A minority
cannot be done from inside a VM by any amount of automation — it needs keys,
accounts, hardware, infrastructure, or a legal decision. Spec §1.22 says we
do not claim what we cannot demonstrate, so those items are listed here
rather than quietly marked done.

Each item states what is needed, what it unblocks, what we do in the
meantime, and how we will prove it once unblocked.

---

## 1. Secure Boot signing keys

**Needed:** a signing key pair for Punar's boot artifacts, and a decision on
whether Punar ships its own Machine Owner Key (user enrolls it at install)
or seeks a shim signed by Microsoft's third-party CA (boots on stock
firmware without user action).

**Unblocks:** spec §44.1 production boot goals, DoD items 2 and 4 beyond
their simulated state, and any claim that Punar boots on a locked-down
enterprise laptop.

**Meanwhile:** the image builds UKIs that are *signable*; mkosi is wired for
it; every surface that mentions Secure Boot renders `SIMULATED` in VM builds.

**Proof when unblocked:** signed UKI verified by `sbctl verify`, a real
Secure Boot enabled machine booting with the key enrolled, and the
compliance capability reporting a non-simulated boot-integrity state.

**Note on the shim path:** Microsoft third-party CA signing has a review
process and a lead time measured in weeks-to-months. If enterprise
deployment on unmodified firmware matters, this is the long pole and should
start early.

---

## 2. TPM 2.0 and measured boot — physical hardware

**Needed:** at least one representative machine from the §5.3 target classes
(2019–2022 ThinkPad / Latitude / EliteBook), physically available for test.

**Unblocks:** TPM-assisted LUKS unlock (§44.2), measured boot investigation
(§44.1), hardware-backed device identity, and the honest removal of the
`SIMULATED` tag from boot-integrity and disk-encryption compliance rows.

**Meanwhile:** attended and signed-unattended KVM installs create and inspect
real LUKS2 storage, exercise passphrase and recovery custody, and scan for
literal secret leakage. Nothing claims TPM-assisted unlock or measured boot.

**Proof when unblocked:** unlock without a passphrase on real hardware after
a measured boot, plus a deliberate PCR mismatch refusing to unlock.

---

## 3. Hardware compatibility matrix

**Needed:** the same physical machines, plus any laptop models Smplify
intends to support at launch.

**Unblocks:** DoD-adjacent claims about the product thesis ("make existing
8–16 GB enterprise laptops useful again", §81 Test B). Firmware quirks,
GPU/Wayland behaviour, suspend/resume, Wi-Fi and Bluetooth firmware, and
docking behaviour are only discoverable on metal.

**Meanwhile:** everything is validated on QEMU with virtio and llvmpipe,
which proves the software stack and nothing about hardware.

**Proof when unblocked:** a per-model results table with boot time, idle RAM,
suspend/resume, external display, Wi-Fi, and audio — published honestly,
including the models that do not work.

---

## 4. Real Smplify control plane

**Needed:** the actual cloud service (or a staging deployment), with device
enrollment endpoints, an admin console, and RBAC.

**Unblocks:** replacing `punar-mock-smplify`, the §51 remote-query story
against a real authorization model, and the §72 fleet view.

**Meanwhile:** the mock implements the full protocol over a Unix socket and
persists what it receives, so the endpoint side is exercised end to end. The
protocol is the deliverable; the service is Smplify's product.

**Proof when unblocked:** the same in-VM enrollment check pointed at the real
endpoint, with mTLS replacing filesystem admission.

---

## 5. Identity provider tenants

**Needed:** test tenants for Google Workspace, Microsoft Entra, or Okta —
whichever Smplify supports first.

**Unblocks:** the §49 "user authentication" step of enrollment, which today
is honestly absent (the mock enrolls a device, not a person).

**Meanwhile:** enrollment is device-scoped and says so; no surface claims a
verified human identity.

**Proof when unblocked:** enrollment that requires an interactive login and
binds the device to a real directory user.

---

## 6. Private relay infrastructure

**Needed:** deployed ingress and egress relay nodes under separate
operational control, or a decision to partner rather than build.

**Unblocks:** §33–34's dual-hop privacy property. This is the largest item on
the list by far — Apple and Cloudflare operate this class of infrastructure,
and §34 explicitly forbids routing everything through one Smplify-owned VPN
and calling it private.

**Meanwhile:** M12 designs the relay as an abstraction with a SIMULATED
implementation, drawn dashed on every surface per the design language.

**Proof when unblocked:** the ingress node demonstrably unable to see
destinations and the egress node unable to see client identity — a property
that must be argued architecturally, not just measured.

---

## 7. Release signing and distribution infrastructure

**Needed:** a signing key for release artifacts and package repositories, a
hosting decision for the vendor repo and image artifacts, and key custody
(who holds it, how it is rotated, what happens if it leaks).

**Unblocks:** DoD item 25 end to end, the §57 staged rollout with real
devices, and any public download of Punar.

**Meanwhile:** `docs/development/update-and-rollback.md` designs the
mechanism; CI exercises it against a local fixture repository.

**Proof when unblocked:** a device verifying a signed release before trusting
it, and refusing an unsigned or tampered one.

---

## 8. Legal and naming

**Needed:** trademark clearance for "Punar", a license-compliance review of
the shipped package set (Apache-2.0 first-party code aggregating GPL and
other upstream licenses is normal, but the distribution needs its notices
right), and an export-control read if Punar ships encryption by default —
which it does.

**Unblocks:** public release under the Punar name.

**Meanwhile:** LICENSE and NOTICE are in place for first-party code; upstream
licenses ship with their packages.

---

## 9. Security review

**Needed:** an independent review, ideally adversarial, against
`docs/threat-model/THREAT_MODEL.md`.

**Unblocks:** any security claim made to an enterprise buyer.

**Meanwhile:** every milestone runs an adversarial audit agent that has found
real defects (a path reaching ledger storage in M8, a hostname validation
bypass in M3). That is not a substitute for a human review with different
incentives.

---

## What is NOT on this list

Everything else. The installer, SBOM and provenance, the idle-RAM diet,
removing dev-image conveniences (the `punar:punar` password, autologin, the
mock control plane), reproducible-build verification, the update mechanism
itself, and the remaining milestones are all engineering this project can do
and prove in CI. They are tracked in `IMPLEMENTATION_STATUS.md` and the
milestone docs, not here.
