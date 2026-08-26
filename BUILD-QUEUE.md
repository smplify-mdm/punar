# Punar — Build Queue

**Companion to [`HANDOFF.md`](HANDOFF.md).** That document explains *what Punar
is and how it works*. This one is *what to build next and how*.

**Read `HANDOFF.md` §3 (standing rules) and §11 (failure modes) first.** Several
tasks below exist because an earlier decision was reversed, and §11 lists
mistakes that each cost a full CI cycle.

---

## 0. The finish line

Spec §80 defines done as: a clean VM can do 26 things. **20 of the 26 are
already demonstrated** by the 760 green assertions. The genuinely open ones:

| # | DoD item | Status |
|---|---|---|
| 7 | launch browser / **web app** | browser yes; web-app install is M11, unbuilt |
| 19 | enforce project network rule | M12, unbuilt (`punar-netd` is a 14-line stub) |
| 20 | display local network activity | M12, unbuilt |
| 25 | demonstrate rollback/update mechanism | **ADR-003 ratified but NOT built** — no repart config, single `Format=disk` |
| 3 | remain within idle budget | 1274 MB against a 1024 MB target **never once met** |
| 10 | report compliance | works, but the *word* was wrong on personal devices — see §3 |

And spec §81 Test A is the real bar: *"If Smplify management were removed,
would an engineer still choose Punar?"* The answer must be yes. That is why the
unmanaged-first work in `HANDOFF.md` §3.3 is not cosmetic.

---

## 1. Immediately

### 1.1 Push the local commits
```bash
git log --oneline origin/main..HEAD    # several commits, gates pass locally
```
Run the gates anyway (`HANDOFF.md` §6), then push. **Never push while a CI run
is in flight** — the concurrency group cancels it.

---

## 2. Latency and memory — finish what is measured

This is first because the instruments exist, the numbers are recorded, and the
owner's two hardest rules (**least RAM possible**, **speed is table stakes**)
collide here. `tests/performance/README.md` carries the full reasoning.

### 2.1 Fix the latency instrument
**Problem:** `surfaces-check.sh` times `open_ms`/`map_ms` by polling with
`qs ipc call` and `hyprctl -j layers` — each poll spawns a process. A keypress
spawns nothing. The recorded 112–240 ms therefore **overstates** what a person
feels, and the overstatement is not constant.

**Do:** measure the path a person takes — dispatch the chord through Hyprland
and time to `layer_mapped`, without a per-poll process spawn in the loop. One
approach: have the shell timestamp `open()` and expose it on the existing
read-only IPC probe, so the number comes from inside the process rather than
from a poller outside it.

**Done when:** `surfaces-latency.txt` records a figure whose instrument
overhead is stated and bounded, and the report says which path it measured.

**File:** `os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/surfaces-check.sh`

### 2.2 Measure construction cost, then lazy-load by the rule
**Problem:** every surface is instantiated at shell startup. The shell holds
**328 MB** — the largest single consumer on the machine. Nobody has measured
what a surface costs to *build* versus to *hold*.

**Do, in this order:**
1. Measure per-surface **construction** time and **resident** cost.
2. Lazy-load every surface whose construction is imperceptible. If building the
   AI panel on first `SUPER+A` costs 40 ms, there is no trade — the RAM comes
   back and nothing is felt.
3. Keep eager only what measurement proves expensive, **and put the number in
   the commit message**. *"This surface stays resident because building it
   costs 380 ms"* is defensible; *"surfaces are eager for speed"* is not.

**Never lazy-load:** bar and wallpaper (always visible); approval and alerts
(must appear **unbidden**); notifications, toasts, OSD (must receive events
while closed); lock (must never hesitate).

**Trap:** hoist each surface's `IpcHandler` **outside** its `Loader`, or
`state()` cannot answer `"closed"` without instantiating the thing it is
reporting on — which defeats the entire change and breaks 13 assertions.

### 2.3 Attack `shortcuts` at 240 ms
The slowest surface under KVM by 65 ms, and real. `Shortcuts/` is 1,313 lines
across 4 files and builds its table from `hyprctl binds -j` — 72 binds. Suspect
the table build. Measure before changing.

---

## 3. Finish the unmanaged-first pass

`DESIGN_LANGUAGE.md` §8.1 ratifies one word table; the CLI and command centre
are converted, **the rest is not**. Remaining (from a four-area audit; the
daemon data model is deliberately **not** changing — the wire keeps its
spelling and translation happens at render):

- `SystemControl/SystemControl.qml` + `SystemControl/ControlData.qml` — the
  capability card still renders `COMPLIANCE · COMPLIANT` on personal devices.
- The **ORGANIZATION** section in System Control's sidebar (Enrollment,
  Compliance, Policies). On a never-enrolled device this is empty furniture
  implying you should fill it — but it is also where someone would *go* to
  enroll. **Resolve that tension deliberately; do not just delete it.**
- The remaining bare `· no organization is enrolled` tails in `views.rs`.
- `ExplainCard.qml`.

**Rule:** personal words never presuppose an authority. `compliant → matches`,
`non_compliant → drifted`, `remediating → restoring`; section key
`COMPLIANCE` → `DRIFT`. Enrolled wording is unchanged.

**Trap:** `""` is *not* a state — it is the absence of a reading. Never let it
share a `case` arm with a real value; that exact bug made the command centre
read `LOCAL · COMPLIANT` on every personal machine.

---

## 4. Device classes

`docs/design/device-classes.md` — designed, unbuilt. Unblocks the Raspberry Pi
and gives the RAM rule somewhere to live.

**The shape matters.** Every capability today is read-write (`observe()` +
`apply()`). **Hardware is read-only** — you cannot apply RAM. So a device class
is an **observed fact that joins policy resolution as a source of defaults**,
outranked by explicit user preference and by org policy when enrolled. It is
not a capability with desired state.

**Classify by measurement**, never a model-name table: `MemTotal`, core count,
`/sys/class/power_supply/BAT*`, whether a display is connected. Three classes
only — `workstation`, `laptop`, `appliance`.

**It must be forceable.** CI runs one VM shape, so without a typed enumerated
override exactly one class is ever exercised and the other two are code nobody
has run. This repo has shipped that failure before.

**Two assertions matter most:** every class is exercised; and the right-hand
column of `device-classes.md` §2 — the security and privacy guarantees — is
**identical across all three**. That is what stops "adaptive" becoming "less
safe on cheap hardware".

---

## 5. arm64 / Raspberry Pi — after ratification

**`docs/architecture/adr/ADR-005-arm64-support.md` is Proposed and AMENDED.
Read §A before anything.** It corrects two errors in its own first draft.

Decision as amended: **Debian, tracking pinned sid.** Not testing — testing is
36 days behind on chromium and structurally blocked by a missing armhf build
and an arm64 reproducibility regression.

**Do not start an Arch ARM mirror.** That instruction was struck; its urgency
rested on an rsync capability never verified to exist.

**What makes this tractable:** 88,499 lines of the product are
substrate-neutral. 68,614 lines of Rust reference Arch **zero** times; 19,885
lines of QML mention it once, in a comment. The substrate is ~218 lines of
image pipeline plus package names and the boot chain.

**Sequence when ratified:**
1. `snapshot.debian.org` pinning in `os/images/snapshot.env` + `mkosi.conf`
   (mkosi supports it natively — `mkosi/distribution/debian.py`).
2. Translate package names in both `mkosi.conf` files.
3. Swap the builder base to `debian:sid-slim` (publishes `linux/arm64/v8`).
4. Add `ubuntu-24.04-arm` matrix legs to the `rust` and `contracts` jobs —
   cheap and safe, since there is zero architecture-specific Rust.
5. Only then attempt an arm64 image and the Pi boot chain.

**ADR-003 is unresolved on Pi.** Its gain is *"rollback that works when
userspace does not, because it is the firmware selecting a different,
permanently-blessed UKI"* — the Pi's native chain is not UEFI. A weaker
mechanism wearing ADR-003's name would be worse than an honest second
mechanism. That needs its own ADR.

---

## 6. Product gaps, by value

### 6.1 Installer and onboarding
`docs/design/installer.md`, `onboarding.md`. **Nobody can install Punar on a
real machine today** — the only path is booting a prebuilt image. Blocks all
hardware testing, which blocks 9 of the `user-blocked.md` items.

**Known defect already found in the design:** `install.targets` excluded the
boot medium but **not** the answers disk — a data-loss hazard. Check it.

### 6.2 `punarctl app`, Flatpak, and the Chrome command
`docs/design/third-party-apps.md`, `app-catalog.md`.

**Two planning rounds were REJECTED by all reviewers.** Read those objections
before re-planning. They proposed shipping hand-transcribed image digests,
sizes, publishers, and a `containment: sandboxed` **safety label** nothing in
the project could verify — a §1.22 violation on the one field that tells a user
an app cannot reach their files.

**Settled:** Flatpak is the mechanism, because ADR-003 forces it —
`/var/lib/flatpak` is the only place a user-installed app survives an image
swap. **Not settled:** whether `/var/lib/flatpak` and `/usr/local` are actually
on shared storage. §1.7 of the design proposes it; **it is not built.**

**Also:** the UX reviewer's objection stands — spec §12.2's worked example is
typing `> install Firefox` into the **command centre**, and non-negotiable 17
is *"do not rely on the terminal"*. A CLI-only answer is not the product.

### 6.3 Execution trust
`docs/design/execution-trust.md`. fanotify `FAN_OPEN_EXEC_PERM` inside
`punard`; `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` is verified present.

**This widens `punard` to `CAP_SYS_ADMIN`** — a real privilege increase,
recorded in the design rather than hidden. Two design claims were **falsified
before implementation** and must stay falsified: Chromium on Linux writes **no**
provenance xattr, and IMA/EVM is **not** compiled into Arch's kernel.

### 6.4 Developer workstation: Slack, local Kubernetes, VMs
The owner's ask: *"support slack, support containers to deploy kubernetes apps
locally like our smplify deployment and other VMs."*

- **`kind` on rootless podman** is the likely stack — `k3d` requires Docker,
  which Punar does not ship. `kind` is 10 MiB at the pin; `kubectl` is 85 MiB
  and is the largest single line item.
- **`punar-env` hardcodes `--network none`** (`crates/punar-env/src/podman.rs`),
  justified in M6 partly by *"no rootless-net helper in the image"* — **that is
  now false**, `passt` ships as a podman dependency. So a developer currently
  cannot install a dependency inside the one supported dev environment. Lift it
  deliberately, with policy.
- **`gtk3` already ships** (chromium depends on it), so the portal backend for
  screen-sharing is nearly free — check it, because "can you share your screen
  in a huddle" is a day-one blocker.
- **CI cannot prove most of this** (`-nic none`, 14 GB runner disk with
  `-snapshot`). M6 is the precedent for working around it: preload an OCI
  archive, `podman load`. `podman kube play` runs real Kubernetes YAML offline
  for zero added megabytes — but with `--network none` there is no Service and
  no published port, so it cannot demonstrate "reach a service from the
  browser". Say so rather than implying otherwise.

### 6.5 M11 browser/web-apps · M12 network + relay
`docs/development/milestone-11.md`, `milestone-12.md`. Both designed, unbuilt.
M12 closes DoD items 19 and 20; the private relay is `user-blocked.md` item 6
and is the largest item on that list.

---

## 7. How to add a new in-VM check

Almost every task above needs one. The full recipe:

1. **Script** at `os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/<name>-check.sh`,
   committed **mode 0755**. Always `exit 0`; the verdict is the last line of
   `/run/punar/<name>-report.txt` as `PUNAR_<NAME>_OK` / `_FAIL`.
2. **Unit** at `.../usr/lib/systemd/system/punar-<name>-check.service`.
   **Not enabled, no `.wants` symlink** — `idle-ram.sh` starts it synchronously.
   Choose `User=punar` for user-session things (shell IPC, the compositor) or
   root for system things (modprobe, D-Bus policy, `/var/lib`).
3. **Hook** it in `idle-ram.sh`, after the RAM sampling window.
4. **Gate** it in `tools/boot-test.sh`: a delivered `_FAIL` **or a missing
   report under KVM** must `exit 1`. A missing verdict once passed as a warning
   and hid a check that never ran.
5. **Export** the report in `boot-test.sh` (tar list **and** the guest-side copy
   loop — they are separate, and missing the second one silently drops the file)
   and in `.github/workflows/ci.yml`.
6. **Lint** it: add the path to the shellcheck list in `ci.yml`.

**Assertion rules** (`docs/development/checks-conventions.md`, binding): assert
the invariant that survives fulfilment, never the placeholder text. Prefer
relations over constants — several M10 assertions turned out to be wrong about
the *product*, not the reverse. Write a vacuity guard where an assertion could
pass against an empty set.

---

## 8. Definition of done for each change

- All gates green: `qmllint` (fails on **any** output), shellcheck, actionlint,
  `cargo fmt/clippy/test`, schemas, and the full CI run.
- New behaviour is **asserted on the running machine**, not on a config file.
- Anything unproven is **labelled** (spec §1.22). Anything simulated says so.
- The commit message explains **why**, and states plainly what was wrong before
  if it corrects something.
- No assertion was weakened to get green.
