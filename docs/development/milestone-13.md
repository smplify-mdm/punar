# Milestone 13 — Demo polish: design plan

> **Implementation note (2026-08-30):** this document is the original M13
> design/audit and its embedded evidence matrix is historical until refreshed
> by the final M13 check. The current status of record is `BUILD-QUEUE.md` and
> `IMPLEMENTATION_STATUS.md`: M2–M10 and M12 are canonical runtime-proven, the
> A/B update fallback is canonical ARM64-proven, CPU/write gates exist, and a
> fixture-free ARM64 release image now passes the real first-account journey
> through the signed-in desktop (`PUNAR_ONBOARDING_OK`, image SHA-256
> `12db1a9b9d51a4fbcb74ab45c7770040d76e33d16994ea872350443b44b6a9c6`). M13 is
> **partially implemented**; the deterministic personal/enrolled 14-beat demo,
> updated matrix, x86 release-image parity, human keyboard walkthrough and
> physical-hardware acceptance remain open. Do not read the older `NOT MET`
> rows below as current claims.

## Current implementation evidence

`tools/test-release-onboarding-arm64.sh` is the executable clean-release gate.
It boots the fixture-free image through QEMU in mandatory snapshot mode, waits
for framebuffer states rather than sleeping blindly, drives the real keyboard
fields, creates the first local account, observes the recovery receipt, enters
through the one-use PAM token and requires the real desktop bar. Its structural
probe performs no OCR. It retains only `firstboot.png`, `desktop.png` and a
secret-free report; the password is never logged and the one-time recovery
receipt is never saved. The 2026-08-30 native Apple-HVF run emitted
`PUNAR_ONBOARDING_OK`.

The same change makes compact onboarding focus reveal each field inside the
Flickable, resets scroll before the recovery receipt, provides deterministic
forward/back focus targets and treats Enter on the focused receipt heading as
the default **Enter desktop** action. This is real release-path evidence, but
it does not replace the final human keyboard-only walkthrough or the complete
14-beat personal/enrolled demo.

Spec authority: section 76 Milestone 13 ("Deliver first boot, enrollment,
keyboard UX, AI panel, privacy panel, and a deterministic demo"), grounded
in section 75 (the MVP hero demo — **fourteen steps, and this milestone's
job is to make every one of them real and repeatable**), 80 (the
twenty-six-item Definition of Done — the acceptance list this document
audits line by line), 81 (the five product success tests), 65 (first-boot
UX, and its absolute rule: *avoid requiring shell commands during first
boot*), 63 (graphical system control), 64 (the privacy UI), 12.3
(discoverability), 6 (performance is an acceptance criterion), 1.21
(*optimize the MVP for a deterministic hero demo*), 1.22 (treat
unsupported claims honestly), 1.17 (do not rely on the terminal for
ordinary OS administration), 1.24 (avoid deep forks of upstream
projects), 66 (installation MVP: *do not build a complex custom installer
before core OS architecture works*), 79 (MVP non-goals), 82 (final
architectural rules).

Binding prior contracts, not relitigated: every schema under `schemas/`
(**M13 changes none of them**); `docs/api/ipc.md` §1–§23 (M13's only
additions are the two `update.*` methods proposed in §11); the in-VM
harness contract (`idle-ram.sh` starts never-enabled root oneshot
`punar-mN-check.service` units in order, each writing
`/run/punar/mN-report.txt` with `ok`/`FAIL` lines and a
`PUNAR_MN_OK`/`PUNAR_MN_FAIL` verdict, exported over virtio-serial;
`tools/boot-test.sh` gates on the verdict and treats a MISSING verdict as
a hard failure); `PERFORMANCE_BUDGETS.md` §1–§2 (**thresholds do not
move in this milestone, in either direction**);
`docs/design/DESIGN_LANGUAGE.md` §7 (dashed stroke = outside the current
production claim) and §8 (unmanaged-first);
`docs/design/mockups/first-boot.html` (**Plate D-008 — the acceptance
reference for §5 and for demo beat 1**);
`docs/design/mockups/system-control.html` (Plate D-004 — the acceptance
reference for §7.2); `milestone-9.md` / `milestone-10.md` /
`milestone-11.md` / `milestone-12.md` (**being implemented and planned
concurrently; M13 touches none of their files, and every one of their
"deferred to M13" rows is adjudicated in §6**).

M13 is the last milestone. That changes what a deferral means. Every
prior milestone could write *"M13 owns it"* and be honest. M13 cannot
write *"a later milestone owns it"* about anything, because there is no
later milestone — it can only build the thing, or send it to Phase 2, or
record it **NOT MET**. §6 does exactly that for every dangling promise in
the repository, and §3 does it for all twenty-six Definition-of-Done
items. Nothing is allowed to end this project pointing at a milestone
that has already ended.

---

## 0. The architectural law of this milestone

Six rules. Every decision below is downstream of them.

**Law 1 — A demo that only a human can run is a demo that rots.** The
hero demo is fourteen steps of behavior that eight milestones spent
themselves producing. If nothing executes those steps on every push, the
first regression is discovered by an audience. So the demo is a **check
script** first and a performance second (§4).

**Law 2 — A demo a script can run is not proof that a person can use
it.** The inverse of Law 1, and equally load-bearing. `hyprctl dispatch`
proves a dispatcher works; it does not prove a keystroke reaches it. A
screenshot proves pixels were rendered; it does not prove they were
legible. Wherever the only honest evidence is a human, M13 says so and
writes the runbook step instead of inventing an assertion that looks like
proof (§4.6, §3.4).

**Law 3 — M13 adds no daemon.** Four resident daemons exist (`punard`,
`punar-agentd`, `punar-secrets`, `punar-netd`); M12 added the fourth,
and the services budget is 100 MB. A polish milestone that grows the
resident set while claiming to cut RAM is arguing with itself. Every M13
surface is a shell layer, a `punarctl` verb, a one-shot, or a capability
backend.

**Law 4 — Polish is measured against a demo beat or it is not polish.**
§7 lists every candidate with the beat it improves. Anything that cannot
name a beat is gold-plating and is refused by name, with the reason
written down, so the refusal is a decision and not an oversight.

**Law 5 — The RAM diet does not move a threshold and does not hide a
number.** Idle RAM has been 1156–1175 MB in every measured run against a
1024 MB target. The honest responses are: measure where it goes, cut what
can be cut, publish before and after by the same canonical method, and if
the target is still missed, **say the target is missed** (§7.3). zram,
threshold edits, sampling-window changes and metric substitutions are not
on the list.

**Law 6 — The Definition of Done is an audit, not a narrative.** §3's
matrix is the deliverable this milestone is actually judged on. Its rows
were written by reading check scripts and source files, not milestone
prose, and three of them say **NOT MET** about work this project has been
carrying for eight milestones.

---

## 1. Scope

| Area | In M13 | Out — and where it goes |
|---|---|---|
| Definition-of-Done audit | The §3 traceability matrix, all 26 items, one owner and one named piece of evidence each, refreshed at implementation time from the run that proves it | — |
| Deterministic demo | `punar-demo-check.sh` (14 beats, in-VM, 14 screenshots) **and** the human runbook (§6 of this document → extracted to `docs/development/demo-runbook.md` by the implementation) | A recorded video; a presenter deck |
| First boot | A seven-stage OOBE layer in `punar-shell` (Plate D-008), typed side effects only, no shell commands, no terminal (§5) | Account creation, real Wi-Fi credentials, locale generation, the D-002 greeter — §5.4 |
| Graphical system control | Plate D-004 navigator chrome + the **SECURITY** and **ORGANIZATION** sections, read-only, `PUNAR+S` (§7.2) | The SYSTEM / DEVELOPER sections' setters — Phase 2 |
| Keyboard UX | The bind-table assertion, the shortcut overlay (spec 12.3, ranked last), the executed human walkthrough | Remapping UI; per-app bindings |
| AI panel | Nothing new — M7/M8/M10 own it; M13 reviews fidelity against D-005 and fixes only what the review finds | A second AI surface |
| Privacy panel | Nothing new — M12 owns it (its decision 21); M13 reviews fidelity against D-006 | — |
| Rollback / update (DoD 25) | `update.status` + `update.rollback` typed methods, btrfs+snapper root layout, one demonstrated rollback (§8) | Staged fleet rollout, health gating, A/B images, signed UKIs — Phase 2 |
| Budgets | The RAM diet (§7.3) **and** the two missing gates: idle CPU and idle write throughput (§7.4) | Bare-metal measurement — needs hardware (§9, Test B) |
| Notifications | One denial toast, no D-Bus name (§6.2 row 3) | A freedesktop notification daemon / notification centre — **not planned for MVP** |
| Everything in spec 77/78/79 | — | Out. §12. |

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **The demo is driven twice — scripted and human — and both are shipped.** `punar-demo-check.sh` walks the fourteen beats in-VM on every push; the runbook is what a person performs. Neither substitutes for the other (§4.1). |
| 2 | **Every beat produces exactly one screenshot, `punar-demo-NN-<beat>.png`**, uploaded as one CI artifact, so the demo is reviewable by a person who has no VM (§4.4). |
| 3 | **The demo runs twice per CI run: `--mode personal` and `--mode enrolled`**, producing two screenshot sets and an explicit surface-delta list. This is the only mechanical evidence the repo can produce for success Test C (§9). |
| 4 | **First boot is a layer inside `punar-shell`, not a second session and not a second compositor.** Gated on a marker file, opened over the existing `qs ipc` target, so CI can replay it deterministically (§5.2). |
| 5 | **First boot performs no privileged write itself.** Every side effect is a fixed-argv `punarctl` invocation — the M9 approval-overlay and M11 install-card pattern verbatim. The shell gains no socket client (§5.2). |
| 6 | **Account creation is deferred, stated on the stage.** A password field in a QML surface is a credential surface, and spec 66 explicitly forbids building the installer before the core OS works. §65 item 4 is therefore **partially met**, and §5.4 says so in those words. |
| 7 | **The D-002 QML greeter stays deferred.** A greeter's job is authentication; authentication needs the account surface decision 6 defers. A greeter that cannot authenticate is theatre. M13 ships only the part of D-002 the demo actually sees: the 450 ms first-light handoff (§5.5). |
| 8 | **M13 claims Definition-of-Done item 25** (rollback/update), which no milestone owns and which `punarctl update status` currently refuses with the words *"no SPEC section 76 milestone schedules it"*. Scope: btrfs+snapper root layout, two typed methods, one demonstrated rollback (§8). |
| 9 | **The btrfs change lands first in the milestone order**, because it is the one change that can break every existing check, and the fallback is written before it starts: if it destabilizes the image, M13 ships the honest `update status` and item 25 is recorded **NOT MET** — never quietly relabeled (§8.4). |
| 10 | **M13 does not build a notification daemon**, and re-points M10's and M11's deferrals accordingly. `org.freedesktop.Notifications` is an API with a queue, actions and a security model; shipping one as final-milestone polish is how you ship a bad one. M13 ships one denial toast for beat 8 (§6.2). |
| 11 | **The D-013 web-app titlebar masthead is refused permanently**, not deferred. M11's own analysis says it requires patching Chromium or painting over its window; spec 1.24 forbids the first and §3.4 of M11 rejects the second. It leaves the repo as *not planned*, not as *M13 polish* (§6.2). |
| 12 | **`PUNAR+S` is claimed for System Control** (spec 63's own suggested chord; verified free against the M1/M2/M7/M9/M10/M11/M12 grammars as of this writing). **`PUNAR+N` is not claimed** — it is M2's notes scratchpad, and M10 §17's `Punar+N` notification-centre note is a collision that M13 records rather than resolves, because M13 declines the notification centre (§10.5). |
| 13 | **System Control is read-only in M13.** Every row prints the exact `punarctl` verb that changes it (the D-006/D-014 precedent). A second write path to state that already has a typed one is the duplication spec 10 exists to prevent, and a read-only navigator is what beats 2 and 11 actually need. |
| 14 | **The RAM diet begins with a measurement, not a cut.** `punar-ram-breakdown.txt` — per-cgroup, per-process PSS at stabilized idle — is produced and published *before* any package or service is touched, and every cut is landed with a before/after by the canonical method (§7.3). |
| 15 | **Idle CPU and idle disk-write gates are added.** Definition-of-Done item 3 says *"idle resource budget"*, and spec 6 defines four of them. Two have never been measured, by anyone, in any run (§7.4). |
| 16 | **The keyboard-only walkthrough is executed by a human and the result is recorded with a date and a name**, whichever way it goes. It has been "pending" since M1 and is the last open M1 acceptance item (§3.4, §6.2). |
| 17 | **`punar-demo-check.sh` is a separate script from `m13-check.sh`.** The first proves the *product story*; the second proves *M13's own deliverables*. Merging them would make a demo-beat failure indistinguishable from a first-boot bug (§10). |

---

## 3. The Definition-of-Done traceability matrix (spec 80)

This is the centerpiece of the milestone. One row per numbered item in
spec section 80, mapped to the milestone that owns it, the exact evidence
that proves it, and its honest status.

### 3.1 Status vocabulary — fixed, and used literally

| Status | Means |
|---|---|
| **PROVEN IN CI** | A named assertion in a named check script has gone green in a named CI run. |
| **IMPLEMENTED — NOT YET RUN** | The code and the in-VM assertion both exist on disk and pass their static gates; the assertion has never executed in a VM. |
| **PLANNED** | A design plan exists in a milestone document. No code. |
| **HUMAN-VERIFIED ONLY** | No automatable evidence exists or is possible; a documented human step is the only proof. Whether that step has actually been performed is stated per row. |
| **NOT MET** | The claim is false today. |

Two rules govern how these are applied. First, a status describes the
**weakest** link in the item's evidence chain, never the strongest.
Second, an item whose literal wording differs from what the evidence
proves carries a dagger (†) and gets a paragraph in §3.4 — a footnote is
not a downgrade, it is a refusal to let a caveat live only in someone's
memory.

### 3.2 The matrix

| # | DoD item (spec 80) | Owner | Evidence — named | Status | What is missing |
|---|---|---|---|---|---|
| 1 | boot Punar | M0 | `tools/boot-test.sh` phase 1, `PUNAR_BOOT_OK` on the serial console — run 32788238871 | **PROVEN IN CI** | Nothing. Bare-metal boot is Phase 2 (spec 66). |
| 2 | reach graphical keyboard-first desktop | M1 | `PUNAR_DESKTOP_OK` (greetd → Hyprland → quickshell chain, 18 s) + a real rendered frame in `punar-desktop-screenshot` — run 32804034681 | **PROVEN IN CI** † | The adjective *keyboard-first* is carried entirely by item 5, which is not met. This row proves *graphical*, not *keyboard-first*. |
| 3 | remain within defined idle resource budget | M1 + **M13** | `idle-ram.sh` → `PUNAR_RAM_MEAN_MB` / `PUNAR_SERVICES_RSS_MB`, gated by `tests/performance/check-budgets.sh` — mean 1156–1175 MB across runs 32804034681…32868450695; services 4 MB | **NOT MET** | (a) Idle RAM is **131–151 MB over the 1.0 GB target** in every run ever taken (under the 1.5 GB ceiling, recorded as a standing warning). (b) **Idle CPU has never been measured** — spec 6.3 defines a budget and no gate exists. (c) **Idle disk-write throughput has never been measured** — spec 6.4, same. (d) Every number is from an emulated x86_64 VM on an arm64 host and is labeled indicative, not a hardware claim. §7.3, §7.4. |
| 4 | use universal command center | M1 + **M13** | `CommandCenter.qml` ships and loads (it is inside `PUNAR_DESKTOP_OK`); `PUNAR+Space` bind is in `punar-binds.conf` and parses | **NOT MET** | **No check script has ever opened the command center** (`grep commandcenter` across `m2..m9-check.sh` returns nothing; only `aipanel` and `approval` are opened over `qs ipc`). Its action table is still M1's two static entries plus `DesktopEntries`; M2 §2 listed rename-workspace / go-to-workspace / layout-preset actions as in-scope and **they did not ship** (M2's own §8 verification table never claims they did). Spec 75 step 3 — type `Open Atlas` — has **no owner and no implementation**. §6.2 row 1. |
| 5 | manage windows without mouse | M1/M2 | `m2-check.sh` drives every window operation via `hyprctl dispatch` and asserts the resulting state — `PUNAR_M2_OK`, run 32825539021; the keyboard grammar parses under `Hyprland --verify-config` on the pinned 0.56.2-1 | **HUMAN-VERIFIED ONLY — never executed** | **No keystroke has ever been injected anywhere in this project.** `hyprctl dispatch` proves the dispatcher; it does not traverse the bind table. The 23-step walkthrough in `keyboard-grammar.md` "must be executed by a human against a booted desktop image" and has been the single open M1 acceptance item since 2026-08-25. §3.4, §7.5. |
| 6 | switch project workspaces | M2 | `m2-check.sh` rows 1–11: rename → `workspaces.json` schema-valid → shell restart → name restored — `PUNAR_M2_OK`, run 32825539021 | **PROVEN IN CI** | Nothing for this item. The *command-center* route to it is item 4. |
| 7 | launch browser/web app | M1 (browser) / **M11** (web app) | Browser: `chromium 151.0.7922.169-1` in the image, `PUNAR+B` bind parses. Web app: `m11-check.sh` groups 1–8 (planned) | **PLANNED** | **Chromium has never been launched in any check script** (`grep chromium` across all `m*-check.sh`: no hits) — the browser half rests on human walkthrough step 12, unexecuted. The web-app half is M11, whose plan exists and whose code does not. |
| 8 | enroll into mocked Smplify | M5 | `m5-check.sh`, 63 assertions — enroll → managed → offline → unenroll — `PUNAR_M5_OK`, run 32849448721 | **PROVEN IN CI** | Nothing. Real Smplify is Phase 2 by spec 50. |
| 9 | receive organization policy | M5 | `m5-check.sh`: `policy.d` envelopes written, strict-parsed, merged, reconciled; `punarctl policy explain` names the org source — run 32849448721 | **PROVEN IN CI** | Nothing. |
| 10 | report compliance | M5 | `m5-check.sh`: compliance report asserted **on the mock's received side** (`received-compliance.jsonl`), category states only — run 32849448721 | **PROVEN IN CI** | Nothing. This is the strongest privacy evidence in the repository (§9, Test E). |
| 11 | initialize Atlas dev environment | M6 | `m6-check.sh`, 56 assertions — offline `podman load` → rootless `up`/`shell`/`status`/`destroy`, fixture byte-identical — `PUNAR_M6_OK`, run 32857914904 | **PROVEN IN CI** | Nothing. |
| 12 | launch Claude Code as managed AI session | M7 | `m7-check.sh`, 74 assertions — managed session in its own `punar-agent-<id>.scope`, kernel-checked cgroup attribution, schema-exact `registry.jsonl` transitions — `PUNAR_M7_OK`, run 32868450695 | **PROVEN IN CI** † | The **real `claude` binary has never run under Punar anywhere**. What is proven is the claude-code *adapter* driving `punar-mock-agent`. The mechanism is real; the third-party binary is absent by design (no network in CI, no licence). §3.4. |
| 13 | show effective AI authority | M7 | `AiPanel.qml` authority block (`AuthorityRow`, `authorityRows()`), opened over `qs ipc call aipanel open` and screenshotted — `punar-m7.png`, run 32868450695 | **PROVEN IN CI** | Nothing for the surface. Individual rows' *enforcement* is per-milestone (`declared · M9/M12`) and each row says so on its face. |
| 14 | show local AI Agent Registry | M7 | `m7-check.sh`: adapters-as-data, `registry.jsonl` transitions, `punarctl agents list/inspect`, the D-005 panel screenshot — run 32868450695 | **PROVEN IN CI** | Nothing. |
| 15 | show AI Access Ledger summary | M8 | `m8-check.sh`, 17 assertion groups; `ledger-summary.json` schema; the D-005 ledger register in `AiPanel.qml` | **IMPLEMENTED — NOT YET RUN** | `PUNAR_M8_OK` exists nowhere; `punar-m8.png` has never been taken. Host gates are green (`cargo test` 534/0, schemas 15/127). |
| 16 | approval-gate a host action | M9 | `m9-check.sh` group 4 + `Approval/ApprovalOverlay.qml` (D-003), `qs ipc call approval open`; boot-test phase 11 + 11b (host re-validates the exported approval against `schemas/audit/approval.json`) | **IMPLEMENTED — NOT YET RUN** | No in-VM run: `PUNAR_M9_OK` exists nowhere. Host gates green (`cargo test` 719/0, qmllint 12 files clean). |
| 17 | issue short-lived mock Dev credential | M9 | `m9-check.sh` groups 6–9, including the redaction sweep over the export tar, audit trail, ledger files and every Punar process's `/proc/*/environ` and `/proc/*/cmdline` | **IMPLEMENTED — NOT YET RUN** | Same run gap. The redaction sweep is the milestone's headline assertion and has never executed. |
| 18 | deny Prod credential | M9 | `m9-check.sh` group 6 (`aws_prod` refusal + section-73 explanation + audit event) | **IMPLEMENTED — NOT YET RUN** | Same run gap. |
| 19 | enforce project network rule | M12 | `m12-check.sh` groups 2–6: `nft` table partition, `socket cgroupv2` match, allow/deny probes from inside a live agent scope plus the identical out-of-scope same-user control | **IMPLEMENTED — CLEAN VM PROOF PENDING** | `punar-netd` is a real daemon and the hard runtime gate exists. Host gates pass; no clean x86_64/ARM64 `PUNAR_M12_OK` is claimed yet. |
| 20 | display local network activity | M12 | `m12-check.sh` observation/privacy groups + the D-006 panel on `PUNAR+P`, `punar-m12.png` | **IMPLEMENTED — CLEAN VM PROOF PENDING** | Connection aggregation, deny audit, AI-ledger ingestion and the panel are implemented. The clean-image gate and screenshot remain the evidence required to call them verified. |
| 21 | detect an unknown/unmanaged AI fixture | M7 (detection) / M10 (alert) | `m7-check.sh`: the `foo-agent` fixture is found and classified `UNKNOWN · SUSPECTED` by the on-demand scan — run 32868450695 | **PROVEN IN CI** † | The *detection* is proven. **Periodic** detection (240 s timer), the D-009 local alert card and its dismissal/DND behavior are M10 — **PLANNED**, no code. The demo beat needs the alert, not just the scan. §3.4. |
| 22 | allow authorized Smplify query of that local AI metadata | M10 | `m10-check.sh` (planned): device-pull on the sync piggyback, four scopes, three-way intersection, out-of-scope refusal recorded in `queries.jsonl` | **PLANNED** | No code. Authorization is mock roles from a fixture by design (real RBAC/IdP is Phase 2). |
| 23 | remediate firewall drift | M4 | `m4-check.sh`, 29 assertions incl. the timer-driven drift-remediation demo — `PUNAR_M4_OK`, run 32849448721 | **PROVEN IN CI** | Nothing. The *graphical* display of the remediation is beat 11 and lands with System Control (§7.2). |
| 24 | show structured audit | M3 | `m3-check.sh` group 8: `punarctl audit tail -n 20`, every event carrying all 12 schema-required keys, `evt_` prefixes, enums, RFC 3339 — `PUNAR_M3_OK`, run 32828986305 | **PROVEN IN CI** | Nothing for the CLI. There is no graphical audit view and spec 80 does not ask for one. |
| 25 | demonstrate rollback/update mechanism appropriate to chosen substrate | **nobody — M13 claims it** | None. `punarctl update status` is a stub that prints *"not implemented — update orchestration (SPEC section 11.1) is not scheduled by the SPEC section 76 milestone plan; this stub stays until a milestone claims it"* (`crates/punarctl/src/main.rs:1509–1517`), and `crates/punarctl/tests/cli.rs:861` asserts that stub | **NOT MET** | Everything. ADR-001 designed btrfs+snapper snapshot rollback for the MVP and cited this exact DoD item; `os/images/mkosi.conf` ships a plain `Format=disk` image with the btrfs+snapper layout listed under *"not yet done"*. No snapshot has ever been taken and no rollback has ever been performed. §8. |
| 26 | complete without generic privileged root-shell RPC | M3 | `m3-check.sh` lines 226–232: `punarctl debug rpc system.exec` and `shell.run` are both rejected `unknown_method` against punard's closed method table — `PUNAR_M3_OK`, run 32828986305 | **PROVEN IN CI** | Nothing. This is a negative assertion and M13 must keep it negative: every new method in §11 is a named, typed, closed-table entry. |

### 3.3 Counts

| Status | Count | Items |
|---|---|---|
| **PROVEN IN CI** | 14 | 1, 2†, 6, 8, 9, 10, 11, 12†, 13, 14, 21†, 23, 24, 26 |
| **IMPLEMENTED — NOT YET RUN** | 4 | 15, 16, 17, 18 |
| **PLANNED** | 4 | 7, 19, 20, 22 |
| **HUMAN-VERIFIED ONLY** | 1 | 5 (never executed) |
| **NOT MET** | 3 | 3, 4, 25 |
| | **26** | |

Three of the fourteen "PROVEN IN CI" rows carry a dagger. Read strictly,
the number of Definition-of-Done items that are true today, without a
caveat and without a pending run, is **eleven**.

The matrix is regenerated at implementation time from the run that
proves it, and the counts in this section are updated in place. A count
that drifts from the runs is worse than no count.

### 3.4 The four rows that need care

**Item 3 — idle resource budget: measured, and over.** This is not a
gap in evidence; it is a gap in the product. Every measured run since
2026-08-25 has landed between 1156 MB and 1175 MB against a 1024 MB
target — 13–15% over — and the number went *up* by 13 MB when M7 added
the second daemon, honestly reported. It sits under the 1536 MB hard
ceiling, so it is a standing warning and not a release blocker, and that
is the only thing keeping item 3 out of blocker territory. Two further
holes: **idle CPU and idle disk I/O have never been measured at all**.
`tests/performance/check-budgets.sh` gates RAM and services-RSS and
nothing else; `PERFORMANCE_BUDGETS.md` has said "the rest of section 5
remains planned" since M0 and it is still true. An item that reads
*"remain within defined idle resource budget"* cannot be called met when
two of the four defined budgets have no measurement and the headline one
is over. §7.3 and §7.4 are M13's answer, and §7.3 states plainly what
happens if the diet does not close the gap: the item stays **NOT MET**
and the threshold does not move.

**Item 5 — manage windows without a mouse: never executed by anyone.**
This is the most-cited capability in the product's positioning and the
least-tested claim in the repository. What exists: a documented grammar,
a config that parses under the pinned Hyprland with a non-vacuous
negative control, and an in-VM exercise that drives every operation
through `hyprctl dispatch` and asserts the resulting state. What does not
exist: any evidence that pressing a key reaches the dispatcher. The bind
table has never been traversed, in CI or by a person. The 23-step
walkthrough in `keyboard-grammar.md` has been marked "pending" since M1
and is the only open M1 acceptance item. M13 closes this in two moves
(§7.5): a **bind-table assertion** — `hyprctl binds -j` must contain
every chord documented in `keyboard-grammar.md` with the exact
dispatcher and argument, which converts the grammar document into a
tested contract — and, if the pinned Hyprland 0.56.2-1 provides the
`sendshortcut` dispatcher (**to be verified against the pinned binary at
implementation time, not assumed here**), a synthetic traversal of the
bind path for a representative subset. If `sendshortcut` is absent, the
image ships no virtual-input tool (`wtype` is not in the package set,
`/dev/uinput` has no consumer), and **the human runbook remains the only
proof** — which M13 then executes, dates and signs. Either way the matrix
row stops saying "pending" and starts saying what happened.

**Item 12 — Claude Code: the mechanism is real, the binary is absent.**
Seventy-four assertions prove a managed session: its own
`punar-agent-<id>.scope`, kernel-attested cgroup attribution, schema-exact
registry transitions, adapters loaded as data, an authority document
bound to the session. All of it runs `punar-mock-agent` through the
`claude-code.json` adapter. The real `claude` binary has never executed
under Punar in CI or anywhere else, and it cannot in CI: the VM runs
`-nic none` and the binary is third-party and licensed. M13's position:
the **scripted** demo runs the mock through the real adapter and labels
the agent on every surface and in every screenshot caption as
`punar-mock-agent · claude-code adapter · FIXTURE`; the **human runbook**
carries an optional step 5b for an operator with a network and a licence,
and records the result. Presenting a mock as the real agent in a demo
would be exactly the spec 1.22 failure this project has avoided for
twelve milestones.

**Item 25 — rollback/update: unowned for the entire project.** The
strongest evidence that this is a real gap and not a documentation
oversight is that the code says so out loud: `punarctl update status`
refuses with *"no SPEC section 76 milestone schedules it; this stub stays
until a milestone claims it"*, and a unit test pins that sentence.
ADR-001 chose btrfs + snapper snapshot rollback for the MVP **explicitly
citing spec 80 item 25**, and the image never got the layout —
`os/images/mkosi.conf` lists it under "not yet done" alongside signed UKIs
and ISO output. M13 is the last milestone, so the choice is build it or
end the project with a numbered acceptance item unmet. §8 builds it, with
a written fallback.

---

## 4. The deterministic demo (spec 75)

### 4.1 Driven twice — and why both

**Recommendation: build both. They prove different things and neither is
optional.**

The **scripted path** (`punar-demo-check.sh`) exists because of Law 1.
Fourteen beats depend on eight milestones' worth of behavior across four
daemons, a compositor, a container runtime and a browser. Any of those
can regress silently. A demo that lives only in a runbook is discovered
to be broken by an audience; a demo that runs on every push is discovered
to be broken by CI, on the commit that broke it, with a report naming the
beat. It is also the only thing that makes spec 1.21 ("optimize the MVP
for a deterministic hero demo") mean something operational rather than
aspirational: *deterministic* is a property you assert, not a property
you hope for.

The **human runbook** exists because of Law 2. A script cannot press
`PUNAR+TAB` — it dispatches. It cannot judge whether the workspace
transition in beat 12 reads as fluid or as a jump. It cannot notice that
the enrollment block's alignment breaks at a longer org name, or that
the approval overlay's affirmative is unreadable against the wallpaper.
It cannot run a real Claude Code. And a demo is a *performance*: the
runbook is the thing a person rehearses, with the timings, the fallbacks,
and the sentences to say while a container image loads.

The division of labor is explicit: **the script owns every assertion; the
runbook owns every judgement.** Where the runbook contains a step the
script also performs, the runbook says so and the operator's job is to
watch, not to verify.

### 4.2 The scripted path — `punar-demo-check.sh`

`/usr/lib/punar/punar-demo-check.sh`, root oneshot
(`punar-demo-check.service`, **never enabled** — vendor
`/usr/lib/systemd/system/…wants/` symlink only, and the check asserts
symlink + `Wants=`, never `is-enabled`), started synchronously by
`idle-ram.sh` **last, after `m13-check`**; `set -u`; always exits 0;
verdict lines to `/run/punar/demo-report.txt`; final `PUNAR_DEMO_OK` /
`PUNAR_DEMO_FAIL`; host gate `tools/boot-test.sh` **phase 16**
(`m13-check` takes 15; if a concurrent milestone's numbering moves, the
demo takes the next free phase and this line records it). Committed
`0755`. All verdict greps case-insensitive. No `cmp`/`diff` (the image
ships no diffutils — use `sha256sum`). `qs` invocations pass
`-p /usr/share/punar/shell`. **A missing verdict is a hard failure.**

Three properties make it a demo check rather than a fourteenth milestone
check:

1. **It asserts the story, not the mechanism.** Every mechanism already
   has a check that owns it. `punar-demo-check.sh` asserts only that the
   *user-visible beat* happened: a surface opened, a value appeared on
   it, a screenshot was captured. Where a beat's underlying mechanism is
   `PLANNED` or `NOT YET RUN` (§3.2), the beat emits a **labeled
   `skip`** naming the milestone and the check that owns it — never a
   silent pass, and never a `FAIL` for work that has not shipped. The
   verdict line reports `ok/skip/FAIL` counts separately, and
   `boot-test.sh` prints the skip list, so "the demo is green" can never
   quietly mean "the demo is green because ten beats were skipped".
2. **It runs the beats in order, on one machine, in one session.** The
   hero demo's value is that it is *one continuous story*. Running beat 9
   from a fresh fixture would prove something weaker than what the demo
   claims. The script carries state forward exactly as an operator would:
   the Atlas workspace opened in beat 3 is the workspace the agent runs
   in for beats 5–9.
3. **It runs twice** (decision 3): `--mode personal` and `--mode
   enrolled`. Beats 2, 9 (org route), 10 (remote query) and 11 (org
   policy drift) are enrolled-only and skip in personal mode with a
   labeled reason; every other beat must pass **identically in both
   modes**, and the script diffs the two surface captures and prints the
   delta. That delta list is the deliverable for success Test C (§9).

### 4.3 The fourteen beats — what each one proves and who owns it

| Beat | Spec 75 step | What the script asserts | Owner of the mechanism | Beat status today |
|---|---|---|---|---|
| 01 boot | Boot; low idle RAM; graphical desktop; keyboard-first navigation | `PUNAR_DESKTOP_OK` present; `PUNAR_RAM_MEAN_MB` present and inside the ceiling; bar rendered; the bind-table assertion (§7.5) passes | M0/M1 + M13 | **ok** — with the over-target RAM warning printed on the beat line, not hidden |
| 02 enrollment | Choose *Use with my organization*; enroll into mocked Acme; show the five-row compliance block | first-boot fork selects organization (§5); `punarctl enroll start` completes; System Control **SECURITY**+**ORGANIZATION** sections render `Acme Engineering` and the five rows with their real states and their `simulated` tags | M5 + **M13** (§5, §7.2) | **ok after M13** — the graphical block does not exist today |
| 03 workspace | Command center; type `Open Atlas`; a named Atlas workspace opens | `qs ipc call commandcenter open`; the project verb resolves `atlas`; `hyprctl -j workspaces` shows workspace named `atlas`; `workspaces.json` updated | M2 + **M13** (§6.2 row 1) | **ok after M13** — the command center has no project verb today |
| 04 development | Open sample repository; `punar-env up` | `punar-env up` in `~punar/atlas` returns 0 rootless; `punar-env status` shows running; the Atlas fixture is byte-identical | M6 | **ok** |
| 05 AI | Launch Claude Code; show the authority table; registry shows Managed | managed session in its own scope; `AiPanel` opened over IPC renders the authority rows and `MANAGED`; agent labeled `FIXTURE` (§3.4) | M7 | **ok (mock through the real adapter)** |
| 06 approval | Claude requests a host capability; graphical approval; keyboard approve; typed API executes; audit event | approval overlay opens; `approvals.resolve` from the keyboard path; capability applied; audit event with all 12 keys | M9 | **skip until `PUNAR_M9_OK` exists** |
| 07 credential | Mock AWS Dev credential issued; expires; secret not logged | `secrets.get aws_dev` succeeds; grant expires; redaction sweep finds no token anywhere Punar writes | M9 | **skip until `PUNAR_M9_OK` exists** |
| 08 production attempt | Production resource requested; denied; policy explanation shown | `aws_prod` refused; the section-73 explanation renders; **the denial toast appears** (§6.2 row 3) | M9 + **M13** (toast) | **skip until M9 runs;** toast is M13 |
| 09 network | Claude's active destinations and project route | `punarctl privacy connections` renders; the privacy panel shows the agent's rows and the denied production row | M12 | **skip until `PUNAR_M12_OK` exists** |
| 10 shadow AI | Fixture unknown agent detected/classified; local warning; authorized Smplify query returns metadata | `foo-agent` classified `UNKNOWN · SUSPECTED`; the D-009 alert card renders; the mock answers an authorized `inventory` query and refuses an out-of-scope one | M7 (detection) + M10 (alert, query) | **partial** — classification `ok` today, alert + query **skip** until M10 |
| 11 drift | Firewall disabled outside the supported UI; detected and remediated | `nft flush` outside punard; the reconcile timer fires; capability returns to `enabled`; **System Control shows the state flip** | M4 + **M13** (the graphical half) | **ok after M13** |
| 12 multitasking | `PUNAR+TAB`; switch Atlas / Punar / Browser; layouts restore | overview opens over IPC; three workspaces exist and are named; layout preset restores after a shell restart | M2 | **ok** (the *fluid* adjective is a runbook judgement — §4.6) |
| 13 browser / web app | Installed web app launched from the command center; behaves like a native window | web app installed from the fixture manifest; launched; the window carries the recorded app id; the context tag renders on Punar surfaces | M11 | **skip until `PUNAR_M11_OK` exists**; the titlebar masthead is refused (decision 11) |
| 14 privacy | Local privacy panel: relay state, active destinations, process/agent attribution | `PUNAR+P` panel opens; relay row renders with its `SIMULATED` tag; per-process rows including the two honest zero-connection rows | M12 | **skip until `PUNAR_M12_OK` exists** |

The honest reading of that table, at the moment this plan is written:
**six beats pass today, three more pass once M13's own work lands, and
five are gated on M9–M12 running.** The demo becomes fully green when
those four milestones' checks go green — which is precisely why the
demo script is a separate gate that reports skips loudly rather than a
pass/fail that hides them.

### 4.4 The artifact set — the demo is reviewable without a VM

Every beat produces exactly one screenshot, captured with `grim` inside
the guest, written to `/run/punar/`, exported in the same tar as the
reports, and uploaded by `ci.yml` as a **single artifact**,
`punar-demo-screenshots`:

```text
punar-demo-01-boot.png
punar-demo-02-enrollment.png
punar-demo-03-workspace.png
punar-demo-04-devenv.png
punar-demo-05-ai-session.png
punar-demo-06-approval.png
punar-demo-07-credential.png
punar-demo-08-denied.png
punar-demo-09-network.png
punar-demo-10-shadow-ai.png
punar-demo-11-drift.png
punar-demo-12-multitasking.png
punar-demo-13-webapp.png
punar-demo-14-privacy.png
```

Rules that make the set trustworthy:

- **A skipped beat still produces a file** — a `grim` capture of whatever
  is actually on screen, and the beat's line in `demo-report.txt` says
  `skip` with the reason. A missing file and a skipped beat must not look
  the same to a reviewer.
- **`--mode enrolled` writes the same fourteen names into a
  `punar-demo-enrolled/` subdirectory**, so the personal and enrolled
  sets can be opened side by side. This is the surface-delta evidence for
  Test C.
- **Filenames are stable across runs.** A reviewer comparing two CI runs
  compares `punar-demo-05-ai-session.png` to
  `punar-demo-05-ai-session.png`. Beat names never change; if a beat's
  content changes, the beat's line in the report says so.
- **No screenshot is retouched, cropped or composited.** What CI captured
  is what ships. If a surface is ugly, the fix is the surface.

`demo-report.txt` accompanies them with one line per beat —
`ok`/`skip`/`FAIL`, the beat name, the assertion that decided it, and the
owning milestone — so the artifact pair is a complete, reviewable record
of the product story for anyone with a browser and no VM.

### 4.5 The human runbook (extracted to `docs/development/demo-runbook.md` by the implementation)

Structure, fixed here so the implementation has no design left to do:

1. **Preflight** (before the audience): image built from a named commit;
   VM started with the documented QEMU line; the first-boot marker
   removed so beat 1 starts at first boot; the mock Smplify service
   available for beats 2 and 10; network expectations stated (the VM has
   none — every "network" beat is loopback or fixture, and the operator
   says so out loud rather than letting the audience assume).
2. **The fourteen beats**, each with: the keystrokes to press (never a
   shell command, except beat 4's `punar-env up`, which spec 75 itself
   writes as a command), the expected screen, the sentence to say, the
   expected duration, and **the failure fallback** — what to do when a
   container image is slow or a surface does not open, phrased so the
   operator can move on without narrating a bug.
3. **The judgements only a human can make**, listed per beat and gathered
   in §4.6.
4. **The optional step 5b** — a real Claude Code on a machine with a
   network and a licence (§3.4).
5. **The honesty script**: the exact words for the four things the demo
   must not overstate — attestation is simulated, the relay is simulated,
   the agent is a fixture driving the real adapter, and the numbers are
   from an emulated VM.
6. **A post-run record**: date, operator, image commit, which beats were
   performed, what broke. Filed with the CI artifacts.

### 4.6 What the script structurally cannot prove

Written here so no reader mistakes a green `PUNAR_DEMO_OK` for a finished
product:

- **That a keystroke reaches the dispatcher** — §3.4 item 5. Every beat
  the script drives, it drives over `hyprctl dispatch` or `qs ipc`.
- **That a transition feels fluid** (beat 12's own word, from spec 75).
  Frame timing under llvmpipe in an emulated VM is not evidence about
  hardware either way.
- **That a surface is legible** — contrast, alignment at real string
  lengths, focus-ring visibility. Screenshot review is a human step and
  the runbook names it per beat.
- **That the story is persuasive.** Success Test A (§9) is not a CI
  question.
- **That the real Claude Code behaves as the adapter expects.**

---

## 5. First boot (spec 65, Plate D-008)

### 5.1 Today's truth

There is no first-boot experience of any kind. `greetd`'s
`initial_session` autologins the `punar` user straight into
`/usr/lib/punar/session.sh` → Hyprland → `punar-shell`; the config file
itself records that the QML greeter implementing D-002 "is deferred and
will replace this". Nothing asks for a language, a keyboard, a timezone,
a network, an account, a mode, or a privacy default. Beat 1 of the hero
demo and steps 1–7 of spec 65 have, today, no implementation at all.

### 5.2 The smallest thing that satisfies section 65

**First boot is a full-surface layer inside `punar-shell`** —
`FirstBoot/FirstBoot.qml`, a `WlrLayershell` panel in the
`punar-firstboot` namespace, rendered *before* the bar and desktop
chrome are exposed, gated on the absence of
`~/.local/state/punar/first-boot.json`.

Why a layer and not a session (decision 4): a separate greetd session or
a second compositor means a second session chain, a PAM surface, a second
set of graphics environment variables, and a boot path CI has never
exercised — in the last milestone. A layer reuses the session that
already boots, the shell that already loads, the theme tokens that
already ship, and the `qs ipc` harness that `m7`/`m8`/`m9` already use to
open surfaces. It is also **replayable**: delete the marker, call
`qs ipc call firstboot open`, and the OOBE is on screen deterministically
— which is exactly what beat 1 and `m13-check` need.

Why no privileged write from the shell (decision 5): the shell has had no
socket client since M5 and gains none here. Every stage's side effect is
`Quickshell.execDetached([...])` against a fixed `punarctl` argv — the
M9 approval-overlay and M11 install-card pattern — so first boot inherits
the whole typed-capability and audit story instead of inventing a
parallel one. And it satisfies spec 65's rule literally: the *user* types
no shell command; the surface issues typed calls.

The seven stages, in D-008's order, with what each one actually does:

| Stage | D-008 | What M13 ships | Mechanism | Honest label on the stage |
|---|---|---|---|---|
| 01 Welcome | Language · Keyboard · Timezone | **Timezone**: real, selectable, applied. **Keyboard**: real, selectable, applied. **Language**: `English (US)` only | Timezone → `punarctl capabilities set system.timezone <tz>` (backend exists: `crates/punard/src/backends/timezone.rs`). Keyboard → **one new capability backend, `system.keymap`** (§5.3) | Language list renders one entry plus a dashed `OTHER LOCALES · NOT IN THIS BUILD` row naming the reason (the image ships `Locale=C.UTF-8`; locale generation is an image question, §5.4) |
| 02 Network | Wi-Fi picker | The **offline** state D-008 already draws | Read-only: `ip -j link` for interface presence. **No credential entry, no picker.** | `No network interfaces — setup continues offline`, and D-008's own line: *the organization path simply stays closed until a network exists* (in CI it is opened by the mock, and the stage says so) |
| 03 Account | Local user, no email | The existing local account, **displayed** | Read-only | Dashed: `ACCOUNT CREATION · INSTALLER · PHASE 2` with the spec-66 reason on the stage (§5.4). The "no email, no cloud sign-up" promise renders as written — it is true |
| 04 The fork | Personal (default) vs organization | **Fully real.** Personal = the default, pre-selected, and choosing it writes nothing anywhere. Organization = `punarctl enroll start <domain>` against mocked Smplify | M5, unchanged | Nothing dashed. This stage is the milestone's acceptance reference |
| 05 Privacy | Relay toggle · telemetry fact block | Relay toggle → `punarctl relay set <mode>` (M12); telemetry renders as a **fact**, not a toggle; ledger retention (14 d, M8) shown and named | M12 + M8 | Relay carries `SIMULATED · M12` dashed until M12's check is green, exactly as the plate draws it. If M12 has not landed, the row renders `NOT IN THIS BUILD` rather than a dead toggle |
| 06 Organization | The six-step §49 chain as a progress register | The real chain, with real per-step completion | M5's enrollment chain, surfaced | `Attestation · SIMULATED · VM` dashed — the plate is already correct and M13 does not soften it |
| 07 Done | Handoff → desktop | The 450 ms first-light handoff into the shell | §5.5 | Footer states which path was taken and, in personal mode, `Nothing left this machine` — a claim the demo's `--mode personal` run then *proves* by enumerating punard's sockets (M12 §10.3) |

Spec 65's remaining items (8 open terminal or browser, 9 clone project,
10 create project workspace, 11 launch AI agent) are **post-first-boot
desktop actions**, owned by M1/M2/M6/M7 and demonstrated by demo beats
3–5. First boot's job is to hand the user a desktop from which they are
one keystroke away; it does not wrap them.

### 5.3 The one new capability backend

`system.keymap` — the keyboard layout. It is the single stage value a
keyboard-first operating system cannot honestly defer, and it is small:

- **Backend** in `crates/punard/src/backends/keymap.rs`, alongside
  `firewall.rs`, `hostname.rs`, `timezone.rs`. Observe: read the current
  layout. Apply: write a root-owned Hyprland drop-in
  (`input:kb_layout`) plus `/etc/vconsole.conf` for the console, then
  `hyprctl keyword` for the live session. Fixed argv, no shell string, no
  new IPC method (it rides the existing `capabilities.get`/`set`).
- **It becomes a fourth reconciled capability**, so it inherits drift
  detection, `punarctl policy explain`, the audit event, and the M5
  compliance category list for free — and `m4`/`m5` assertions that
  enumerate capabilities go stale and must be updated (§10.5).
- **Allowed values are a closed set** validated against the layouts the
  image actually ships. An unvalidated layout string reaching a config
  file is a config-injection surface, and a capability whose apply can be
  fed arbitrary text is not a typed capability.

Timezone needs no new backend. Locale does, plus glibc locale generation
and font coverage, and that is §5.4's deferral.

### 5.4 What is deferred, and said plainly

| Deferred | Why | Where it goes | What section 65 loses |
|---|---|---|---|
| **Account creation / authentication** (§65 item 4) | A password field in a QML surface is a credential surface, and this project's own rule is that secrets do not pass through the shell (M9 §6). Doing it properly means PAM, a policy for password quality, and a recovery story. Spec 66 says do not build the installer before the core OS works | **Phase 2, with the installer** | §65 item 4 is **partially met**: the account exists, is shown, and is honestly described; it is not created here. Stated on the stage and in §3.2 row 2's caveat |
| **Real network configuration** (§65 item 3) | The CI VM runs `-nic none`. A Wi-Fi picker cannot be built against a NIC that does not exist, cannot be tested, and would be a mockup shipped as a feature | **Phase 2** (spec 77 lists Wi-Fi explicitly) | §65 item 3 is met **in its offline form only** — D-008 already draws that form, which is why the plate can be followed honestly |
| **Locale selection beyond `English (US)`** | The image ships `Locale=C.UTF-8` and a single font family set; real locale selection needs generated locales, font coverage, and input methods | **Phase 2** | §65 item 2 is met for keyboard and timezone, and **one-entry** for language, labeled |
| **The D-002 QML greeter** | Decision 7: a greeter authenticates, and authentication is the surface deferred above. A greeter that only decorates an autologin is theatre, and this repo has spent twelve milestones not shipping theatre | **Phase 2, with the account work** | Nothing in §65 — §65 never asks for a greeter. What the demo would have wanted from D-002 is the handoff, and §5.5 ships that |
| **Enrollment from the desktop after first boot** | Already exists as `punarctl enroll start`; a graphical entry point is System Control's ORGANIZATION section, read-only in M13 (decision 13) | The section prints the verb | D-008's "enroll later, never retroactively" promise stays true and is stated on the fork card |

### 5.5 The handoff — the part of D-002 that ships

D-008 §V.03 specifies that `ENTER DESKTOP` performs *"the same 450 ms
first-light handoff the greeter uses — one spatial transition, once, into
Punar Shell"*. M13 ships that transition from the OOBE layer: one
opacity+scale transition on the layer as the bar and desktop chrome are
exposed, 450 ms, once per install, never replayed. It costs one QML
animation, it is the first thing the demo's audience sees, and it is the
only piece of D-002 that has a demo beat behind it (Law 4).

### 5.6 Determinism and replay

- The marker is `~/.local/state/punar/first-boot.json`
  (`{v, completed_at, mode}`), written by the shell through the M2
  `FileView` `atomicWrites` path — the same mechanism `workspaces.json`
  uses, which `m2-check` already proves is atomic and schema-stable.
- **The marker records the mode, not the answers.** Answers are state
  Punar already owns: the timezone and keymap are capabilities, the mode
  is enrollment state, the relay is relay state. A second copy of any of
  them in the marker would be a drift source.
- Missing or corrupt marker → first boot runs. Present and valid → the
  layer never instantiates (a `Loader` with `active: false`, which is
  also §7.3's lazy-loading rule).
- `qs ipc call firstboot open` forces the layer for the check and the
  demo. It does **not** clear the marker: a replay is a replay, and a
  surface that can silently un-complete first boot is a surface that can
  re-ask for enrollment.

---

## 6. The gaps no milestone owns

Compiled by reading every milestone document for `deferred`, `M13`,
`future`, `not yet drawn`, `not planned`, and by checking each claim
against the source and check scripts rather than against the prose.

### 6.1 Gaps found — the full list

| # | Gap | Where it was deferred | Evidence it is real | M13's verdict |
|---|---|---|---|---|
| 1 | **Command-center project verb** — spec 75 step 3's `Open Atlas` | Never explicitly deferred; M2 §2 listed command-center actions as in-scope and shipped none of them | `CommandCenter.qml` `staticActions` has exactly two entries (`Open terminal`, `System Control` stub); no check script opens the overlay | **BUILD** (§7.1 B3) — it is a hero-demo step with no owner |
| 2 | **Keyboard-only walkthrough never executed** | M1 acceptance, "pending" since 2026-08-25 | `IMPLEMENTATION_STATUS.md` M1: *"the only open M1 item"* | **BUILD + EXECUTE** (§7.5) — bind-table assertion, then a human runs the 23 steps and signs it |
| 3 | **Idle RAM 13–15% over target** | M1; carried as a standing warning through M2–M7 | Every measured run: 1156–1175 MB vs 1024 MB | **BUILD** (§7.3) — measure first, then cut; if it misses, item 3 stays NOT MET |
| 4 | **Idle CPU and idle disk-write never measured** | Never deferred — simply never built | `check-budgets.sh` gates RAM and services-RSS only; `PERFORMANCE_BUDGETS.md` still says "the rest of section 5 remains planned" | **BUILD** (§7.4) — two gates, cheap, closes half of DoD item 3's hole |
| 5 | **Rollback / update mechanism (DoD 25)** | Never assigned to any milestone | `punarctl update status` stub text names the absence; `mkosi.conf` lists btrfs+snapper under "not yet done" | **BUILD** (§8), with a written fallback to **NOT MET** |
| 6 | **Graphical system control (spec 63, Plate D-004)** | No milestone references D-004 at all | `grep D-004 milestone-*.md`: no hits. `CommandCenter.qml` has a `System Control` entry whose meta reads *"arrives M3"* — a stub that outlived the milestone it named | **BUILD, scoped** (§7.2) — navigator chrome + SECURITY/ORGANIZATION only; beats 2 and 11 need it |
| 7 | **Notification centre / freedesktop notification daemon** | M10 §17 ("— **M13**"), M11 §4.9 + §15 row 1 | The image contains no `org.freedesktop.Notifications` implementation | **REFUSE** (decision 10). Ship one denial toast for beat 8; re-point M10's and M11's rows to *not planned for MVP* |
| 8 | **D-013 web-app titlebar masthead** | M11 §4.5, §15 row 2 ("M13 polish") | M11's own analysis: patch Chromium (spec 1.24) or paint over its window | **REFUSE PERMANENTLY** (decision 11) — record as *not planned*, keep the `PARTIAL` coverage label |
| 9 | **Graphical elevation dialog (D-012 Sect I)** | M9 §13 row 4 | M9 ships CLI + grant + bar chip | **REFUSE** — beat 6 is already covered by the D-003 approval overlay; a second privilege surface with no distinct beat is gold-plating (§7.6) |
| 10 | **Graphical broker issuance card (D-012 Sect II)** | M9 §13 row 5 | Beat 7 (credential issued, expires) has **no visual** without it | **BUILD, minimal** (§7.1 B7) — one card, issuance + live expiry, no new data path |
| 11 | **Multi-approval queue UI** | M9 §13 row 9; D-003 lists it among "states not drawn" | Beat 6 raises exactly one approval | **REFUSE** — no beat needs it; the `↑`/`↓` + count badge M9 ships is sufficient (§7.6) |
| 12 | **Inline (in-process) restriction explanations** | M12 §15 ("M13") | The kernel returns an errno; Punar cannot write prose into a third-party binary's stderr | **REFUSE — structurally impossible as stated.** Re-point to *never, as stated*; the wrapped-process path (`punar-env` translating a connect failure) is Phase 2 |
| 13 | **Shell notification on denial** | M12 §15 ("M13") | Beat 8's denial has no visible reaction today | **BUILD** — this is gap 7's one exception, and the whole reason a toast exists |
| 14 | **Escape-proof per-session netns; org network policy via desired state** | M12 §15 ("M13+") | Needs address allocation, forwarding, an uplink | **PHASE 2** — the CI VM has no network; there is nothing to test against |
| 15 | **Design plates with no implementation**: D-002 (greeter), D-004 (system control), D-010 (updates/apps), D-011 (projects), D-016 (menubar / shortcuts), D-007's wallpaper sheet | Never assigned | `grep -l` across milestone docs: D-002, D-004, D-008, D-010, D-011, D-016 appear in **no** milestone document | D-004 **BUILD scoped** (§7.2); D-008 **BUILD** (§5); the shortcuts overlay from D-016 **BUILD, ranked last** (§7.1 B1b, spec 12.3); a single static wallpaper from D-007 **BUILD** (§7.1 B1a); D-002, D-010, D-011 and the menubar sheet **PHASE 2**, recorded |
| 16 | **`punarctl web-apps list` vs D-013's `punarctl app list` caption** | M11 §10.1 — "reconciled when the mockup is next touched, not by M11" | A naming mismatch between a shipped verb and a plate | **RECORD ONLY** — M13 owns no mockup file either; it goes on the Phase-2 design-debt list rather than dangling |

### 6.2 The five that matter for the demo, and why

1. **Command-center project verb (gap 1)** — without it, spec 75 step 3
   cannot be performed as written. An operator would have to type
   `hyprctl dispatch renameworkspace`, which violates spec 1.17 and
   makes beat 3 a lie about the product.
2. **System Control (gap 6)** — beat 2's five-row compliance block is
   drawn in spec 75 as a *screen*. Today the only place that data
   appears graphically is a bar chip with an org name and a dot.
3. **The denial toast (gap 13)** — beat 8 is "denied, with an
   explanation". A denial with no visible reaction reads to an audience
   as nothing happening.
4. **Item 25 (gap 5)** — not a demo beat, but a numbered acceptance item,
   and the last milestone is the last chance.
5. **The keyboard walkthrough (gap 2)** — beat 1 claims "keyboard-first
   navigation" and no keystroke has ever been proven to work.

---

## 7. Polish with a budget

The demo is the product's first impression, so polish is real work — and
Law 4 binds every item to a beat. Items are ranked; if the milestone runs
long, the cut line moves up from the bottom and the matrix records what
was cut.

### 7.1 In budget — ranked, each tied to a beat

| Rank | Item | Beat improved | Cost | Why it earns its place |
|---|---|---|---|---|
| 1 | **The RAM diet** (§7.3) | 01 | Large — measurement-led | Spec 6 makes it an acceptance criterion and DoD item 3 is a standing warning. Beat 1's first spoken claim is "low idle RAM" |
| 2 | **Idle CPU + write gates** (§7.4) | 01 | Small | Two of four defined budgets have no measurement at all |
| 3 | **First boot** (§5) | 01, 02 | Large | Spec 65 has no implementation; beat 1 starts here |
| 4 | **Command-center project verb** (gap 1) | 03 | Medium | Spec 75 step 3 is otherwise unperformable |
| 5 | **System Control, scoped** (§7.2) | 02, 11 | Medium | Beat 2's compliance block and beat 11's drift flip have no graphical home |
| 6 | **`update.status` + `update.rollback`** (§8) | — (DoD 25) | Medium-large | The only unowned numbered acceptance item |
| 7 | **Bind-table assertion + executed walkthrough** (§7.5) | 01, 12 | Small + one human hour | Turns the keyboard grammar from a document into a tested contract |
| 8 | **Denial toast** (gap 13) | 08 | Small | Beat 8 currently has no visible reaction |
| 9 | **Broker issuance card** (gap 10) | 07 | Small | Beat 7 currently has no visual at all |
| 10 | **Historical decision — superseded 2026-08-26:** one static wallpaper from D-007's sheet | 01, 12 | Superseded by `docs/design/wallpapers.md` | The owner-approved catalog now ships one original 3840×2400 artwork, three 3840×2400 photographs, and the Field vector; only the active asset is decoded |
| 11 | **Fidelity review of D-005 and D-006** against the shipped panels, fixing only what the review finds | 05, 14 | Small | M7's and M12's own verification tables list plate fidelity as an unverified human review |
| 12 | **Shortcut overlay** (hold `PUNAR`, spec 12.3), reading `hyprctl binds -j` — no new data source | 01 | Small-medium | The cheapest way to make "keyboard-first" *visible*; **ranked last deliberately** — it is the first thing cut if the diet or btrfs runs long |

### 7.2 System Control — scoped to what the beats need

`PUNAR+S` → `punar-shell` `SystemControl` (IPC target `systemcontrol`),
Plate D-004's navigator chrome: arrow keys navigate, `Enter` opens,
`Escape` returns, `/` searches (spec 63's own grammar, verbatim).

Ships in M13:

- **SECURITY** — Device, Encryption, Secure Boot, Firewall. Real states
  from the capability registry; `Encryption` and `Secure Boot` render
  dashed `SIMULATED · VM` (spec 1.22, and the same tag D-008 uses).
  **This is beat 2's compliance block and beat 11's drift display.**
- **ORGANIZATION** — Enrollment, Compliance, Policies, Privilege. Real
  state from `status.json` and `punarctl policy explain`. Unenrolled:
  these rows are **absent, not greyed** (DESIGN_LANGUAGE §8).

Routes to surfaces that already exist: **AI** → the `PUNAR+A` panel;
**PRIVACY** → the `PUNAR+P` panel (M12). Renders `NOT IN THIS BUILD`
with the owning phase: **SYSTEM** (Network, Bluetooth, Displays, Audio,
Power) and **DEVELOPER** (Projects, Containers, Toolchains) — every one
of which would need a setter Punar does not have.

Read-only (decision 13): each row prints the `punarctl` verb that changes
it. This also removes the `System Control · arrives M3` stub from
`CommandCenter.qml`, a placeholder that has outlived its milestone by ten.

### 7.3 The RAM diet — first-class, measurement-led

**Target: mean idle RAM under 1024 MB by the canonical
`PERFORMANCE_BUDGETS.md` §2.1–2.2 method. Stretch: 750 MB. Current:
1156–1175 MB. The thresholds do not move (Law 5).**

**Step 0, before any cut: publish the breakdown.** `idle-ram.sh` gains a
per-process, per-cgroup PSS dump at the end of the sampling window
(`smaps_rollup` over every pid, grouped by cgroup, sorted descending) →
`/run/punar/ram-breakdown.txt`, exported and uploaded as
`punar-ram-breakdown`. Nothing is cut before this file exists, because
every candidate below is a hypothesis and the repository has never
enumerated where the gigabyte goes.

Candidates, with the honest expectation attached to each — **none of
these is a commitment to a number**:

| Candidate | Hypothesis | Expected value | Risk / label |
|---|---|---|---|
| **llvmpipe worker arenas** — cap `LP_NUM_THREADS` in `session.sh` | Software GL thread arenas scale with CPU count; the CI VM has several | Possibly large — and **VM-only** | Must be labeled non-representative of hardware; a cut that only helps under llvmpipe does **not** count toward the hardware claim |
| **Lazy QML surfaces** — `Loader { active: false }` for AiPanel, Overview, Approval, FirstBoot, SystemControl, PrivacyPanel | Six QML scenes are instantiated at shell start for surfaces that are closed | Tens of MB, real on hardware too | Also improves first paint of every panel beat. Interacts with `qs ipc` opening: the loader must activate on the IPC call |
| **`xdg-desktop-portal` + `-hyprland`** — two resident processes | Nothing in the current session opens a portal at idle | Small-medium | **Check with M11 first** — web apps may need the file-chooser portal. Socket-activate rather than remove if so |
| **`pipewire` + `pipewire-pulse` + `wireplumber`** — three resident processes | The VM has no audio device | Small-medium | Socket-activate, do not remove: spec 63 lists Audio under System Control, and removing audio from a desktop to win a benchmark is the wrong trade |
| **`hyprpolkitagent`** — resident | punard uses its own peer authorization, not polkit | Small | Verify nothing in the stack raises a polkit prompt before touching it |
| **journald runtime storage** — `RuntimeMaxUse` | The journal in `/run` is RAM, and the checks are chatty | Small | Must not reduce diagnostic value of a failing CI run — cap, do not disable |

Rules that keep the diet honest:

1. Every cut lands with a **before/after pair by the canonical method**,
   both quoted in `PERFORMANCE_BUDGETS.md` with the run ids.
2. **zram is not a diet item.** It does not reduce
   `MemTotal - MemAvailable` and adopting it to move the number would be
   metric-shopping. Spec 6.6 wants it for memory-pressure behavior; that
   is a different claim on a different line.
3. **No threshold edits, no sampling-window edits, no metric
   substitution.** The gate is the mean over the canonical window.
4. **If the target is still missed**, the honest outcome is published: the
   breakdown, the hardware-relevant subtotal with the emulation-specific
   components itemized and excluded *with the exclusion labeled*, and the
   sentence that the 1.0 GB target remains **unproven** until a bare-metal
   measurement on a spec 5.3 device exists. DoD item 3 then stays **NOT
   MET** in §3.2, and the milestone ships anyway.

### 7.4 The two missing budget gates

`idle-ram.sh` already owns the stabilized-idle window; both gates ride it
at zero additional cost and with no new timers (spec 6.3 forbids polling,
so both are computed from two readings, not sampled continuously):

- **`PUNAR_IDLE_CPU_PCT`** — total CPU consumed by all Punar first-party
  service cgroups plus the session, from `cpu.stat` deltas across the
  5-minute window. Threshold is an **engineering interpretation** of spec
  6.3's "effectively 0%", set in `PERFORMANCE_BUDGETS.md` §2.3 and
  labeled as such, not as a spec number.
- **`PUNAR_IDLE_WRITE_KB`** — bytes written by the same cgroups over the
  window, from `io.stat`. Spec 6.4 defines rules, not a number, so the
  first run **records a baseline and warns on nothing**; the threshold is
  set from that baseline in a follow-up, which is the same discipline M0
  used for RAM.

`tests/performance/check-budgets.sh` consumes both. An absent value is an
error for CPU (every service must be alive) and a warning for writes
until the baseline exists.

### 7.5 Keyboard UX — closing item 5

Two moves, in order:

1. **The bind-table assertion** (in `m13-check`): parse the chord table in
   `docs/development/keyboard-grammar.md`, read `hyprctl binds -j`, and
   assert that **every documented chord exists with the exact modmask,
   key, dispatcher and argument**, and that no undocumented bind exists.
   This turns the grammar document into a tested contract and catches the
   whole class of "the doc says `PUNAR+P`, the config says something
   else" — a class this repo is now exposed to, with four milestones
   claiming chords concurrently. It does **not** prove a keystroke
   traverses the table.
2. **Synthetic traversal, if the pinned Hyprland supports it.** Hyprland
   is understood to expose a `sendshortcut` dispatcher that replays a
   chord through the bind path. **This must be verified against
   hyprland 0.56.2-1 from the pinned ALA snapshot at implementation
   time**, by the M1/M2 method (source tag + `--verify-config` +
   a negative control) — it is asserted here as a candidate, not as a
   fact. If it exists, `m13-check` traverses a representative subset
   (focus, move, workspace, command center, AI panel, privacy panel,
   System Control) and item 5 gains real CI evidence. If it does not, the
   image ships no virtual-input tool and **the human walkthrough stays
   the only proof** — which M13 then executes.
3. **The walkthrough is executed, dated and signed** either way, and its
   result recorded in `keyboard-grammar.md` and §3.2 row 5. It gains
   first-boot and System Control steps (24–27). If steps fail, they are
   recorded as failures and fixed or carried as NOT MET; a walkthrough
   that can only pass is not a test.

### 7.6 Gold-plating — refused by name

| Refused | Would improve | Why refused |
|---|---|---|
| A freedesktop notification daemon / notification centre | Nothing in the fourteen beats except beat 8, which the toast covers | An API with a queue, actions, and a "any app can post" security model. Shipping one as final-milestone polish is how you ship a bad one (decision 10) |
| The D-002 greeter | Beat 1, marginally | Decision 7 — it cannot authenticate, and §5.5 ships the part the demo sees |
| Graphical elevation dialog (D-012 Sect I) | Beat 6, which the D-003 overlay already covers | A second privilege surface with no distinct beat |
| Multi-approval queue UI | Nothing — beat 6 raises one approval | No beat needs it |
| D-010 updates/apps panel | Nothing — DoD 25 needs a *mechanism*, and `punarctl update status` + System Control's rows carry it | A panel over a mechanism that is one milestone old is premature |
| D-011 projects panel | Beat 3, which the overview and command center already cover | Duplicate surface |
| Animated/generated wallpaper, icon set, sound | Beat 1's first second | Spec 6.6: developer applications take priority. Static installed wallpaper choices are now accepted by `docs/design/wallpapers.md`; animation/generation remains outside the budget |
| A recorded demo video | The demo's reach | Not a repository artifact; the screenshot set plus the runbook is the reviewable form |
| Chromium titlebar masthead | Beat 13 | Decision 11 — patching Chromium violates spec 1.24 |

---

## 8. Definition-of-Done item 25 — rollback and update

### 8.1 What is actually missing

ADR-001 chose, for the MVP, **btrfs + snapper bootable-snapshot
rollback**, and cited spec 80 item 25 by name while choosing it. The
image never got it: `os/images/mkosi.conf` ships `Format=disk` and lists
"btrfs+snapper rollback layout" under *not yet done*. No milestone
scheduled it, and `punarctl update status` has been refusing with that
exact explanation since M3. Nothing in the repository has ever taken a
snapshot.

### 8.2 The smallest demonstrable mechanism

1. **Image layout** — btrfs root with the openSUSE-style subvolume
   layout ADR-001 §"Rollback engineering" already designed (`@` default
   subvolume, `@snapshots`, `@var`, `@home`), and `snapper` (present in
   the pinned Arch snapshot) with one config for root. The
   default-subvolume approach is chosen over an overlayfs pseudo-rollback
   for the reason ADR-001 already wrote down.
2. **Two typed methods** on punard's closed table (§11):
   `update.status` (read, unprivileged) and `update.rollback` (root-only,
   fixed argv, audited). The operator never types `snapper` — spec 1.17
   forbids relying on the terminal for ordinary administration, and
   spec 82 says typed capabilities execute authorized changes.
3. **`punarctl update status`** stops being a stub and reports what the
   device can prove offline: image id, snapshot/build date, channel, the
   snapshot list with ids and timestamps, the current default subvolume,
   and — carried over from M11 §7.5 if it has landed — browser provenance
   and `Security channel · not configured`.
4. **The demonstration**, in `m13-check`: take a pre-change snapshot →
   mutate a tracked file → `punarctl update rollback --to <id>` → assert
   the default subvolume changed and the file's content is restored in
   the live tree → assert the audit event exists with all 12 required
   keys.

### 8.3 The honest limit

**The harness boots the VM once.** Proving that the machine *comes back
up* on the rolled-back generation requires a second boot of the same
disk, which `tools/boot-test.sh` does not do. So:

- `m13-check` proves the **mechanism and its state transition** in the
  live system.
- **Booting into the rolled-back generation is a human runbook step**,
  performed once against a built image, dated and recorded.
- §3.2 row 25 records exactly that split. It does not claim a reboot test
  that did not happen.

Extending `boot-test.sh` to a second boot is the better answer and is
named here as the follow-up; it is not attempted in the last milestone
alongside a root-filesystem change.

### 8.4 The fallback, written before the work starts

Changing the root filesystem is the single highest-risk change in this
milestone — it touches the image build, the boot path, `/var` and `/home`
placement, and therefore potentially every one of the 282 assertions
M2–M7 already prove. Decision 9 puts it **first in the implementation
order** so a failure is discovered with time left. If it destabilizes the
image:

- M13 ships **only** the honest `update status` — which is still a
  genuine improvement over a stub, because it states the absence
  precisely (`ROLLBACK · NOT AVAILABLE · root filesystem is not
  snapshot-capable in this build`) instead of pointing at a milestone
  plan.
- **DoD item 25 is recorded NOT MET**, with the reason, in §3.2 and in
  `IMPLEMENTATION_STATUS.md`.
- It is **not** relabeled, softened, or moved to a phase that does not
  exist in the milestone plan.

---

## 9. The five product success tests (spec 81)

| Test | What M13 produces as evidence | What is impossible without real users / hardware |
|---|---|---|
| **A — Developer**: *if Smplify management were removed, would an engineer still choose Punar?* | The **unmanaged-first proof**, mechanically: `punar-demo-check.sh --mode personal` performs beats 1, 3, 4, 5, 6, 7, 12, 13, 14 on a device that has never enrolled, and the surface-delta against `--mode enrolled` shows exactly which chrome enrollment adds. Plus: M12 §10.3's two zero-connection rows proving punard talks to nobody; M10 §11's structurally inert query surface; M8's user-purgeable ledger; the fact that no first-party surface requires an account | **Everything that matters.** This is a preference question about people, and no assertion can answer it. CI can prove the product *works* without management; it cannot prove an engineer *prefers* it. The smallest honest test — five engineers, two weeks on their real work, one instrumented question — is **Phase 2 work and is not attempted here**. §3.2 does not contain a row for Test A, and neither does any check script |
| **B — Older hardware**: *does Punar make an 8–16 GB enterprise laptop feel meaningfully more useful?* | The RAM breakdown (§7.3), the diet's before/after, the services-RSS number (4 MB against a 100 MB target — the strongest number in the repository), the new CPU and write gates, and boot-to-desktop timing | **A bare-metal measurement on a spec 5.3 device.** Every number this project has ever produced comes from an emulated x86_64 VM on an arm64 macOS host with llvmpipe, and `PERFORMANCE_BUDGETS.md` has labeled them indicative since M0. "Feels meaningfully more useful" is additionally a comparative human judgement against a real bloated endpoint stack. **M13 cannot settle Test B**, and the honest deliverable is the labeled numbers plus the named missing artifact |
| **C — Enterprise**: *can IT/security deploy without destroying the developer experience?* | The **strongest mechanical evidence M13 can produce**, and the reason decision 3 exists: the same fourteen beats run personal and enrolled, and the delta is enumerated. If enrollment changes only the masthead line, the compliance pill, and the org rows — as DESIGN_LANGUAGE §8 requires and as D-008 §I.04 promises — the delta list says so in machine-checked form. Plus M5's proven enroll → managed → offline → unenroll journey (a device that can leave is a device IT can deploy) | The other half of the question — whether *IT* can operate a fleet — needs a real control plane, real identity, and real fleet scale, all of which spec 50/77 place in Phase 2. What M13 proves is the **developer-side** half: that enrollment is additive |
| **D — AI governance**: *can user and admin understand which agents run, what authority they have, what they touch?* | The registry (M7, proven), the authority table (M7, proven), the ledger (M8, implemented — pending its first run), the classification of the unknown fixture (M7, proven), the alert and the authorized query (M10, planned), the network attribution (M12, planned). Beats 5, 9, 10 and 14 are this test performed end to end | Nothing structural — **this is the test the MVP is best positioned to pass**, and it becomes fully evidenced the moment M8, M10 and M12 go green. The remaining honest gap is that everything is proven against a **fixture agent**, never a real one (§3.4 item 12), and that classification of a genuinely novel agent is explicitly imperfect by spec 79 |
| **E — Privacy**: *enterprise visibility without silently uploading detailed developer activity?* | M5's compliance sync asserted **on the mock's received side** as category states only — the org's own copy is checked to contain nothing more (the single strongest privacy assertion in the repo); M8's privacy-as-types construction and user purge; M10's device-side scope refusal recorded in `queries.jsonl` and visible to an unprivileged user via `punarctl privacy queries`; M12's Law 4 (a destination never enters the audit log); the absence of eBPF, fanotify, ptrace and `LD_PRELOAD` anywhere in the tree | The claim is about **what is not sent**, which is proven by construction and by received-side assertions — a strong form. What remains unprovable in MVP: that a *real* Smplify cloud would not ask for more, since there is no real Smplify (spec 50, Phase 2). The mock is the contract; the cloud is not built |

**Stated plainly, because spec 1.22 requires it: Tests A and B cannot be
settled by this milestone, by CI, or by any artifact in this repository.**
Test C is half-settled and the settled half is mechanical. Tests D and E
are the ones the evidence actually supports.

---

## 10. M13's in-VM checks and screenshot set

Two scripts (decision 17). Both root oneshots, never-enabled, vendored
`.wants` symlink asserted rather than `is-enabled`, started
synchronously by `idle-ram.sh` after `m12-check`, always exit 0, verdict
in `/run/punar/`, hard-failed by `boot-test.sh` on a missing verdict.

### 10.1 `m13-check.sh` — M13's own deliverables (phase 15, target ≈ 55 assertions)

1. **First boot — replay** (≈10): marker absent → `qs ipc call firstboot
   open` renders the layer; the seven stages exist in D-008's order;
   stage 04's personal card is pre-selected and carries the only
   `DEFAULT` tag; the org card states baseline + visibility; no stage
   contains a shell command string (**a literal assertion — grep the QML
   for `exec`/shell-string construction and fail on a hit**, because
   spec 65's rule is absolute and this is the only mechanical way to hold
   it); completion writes a schema-shaped marker; a second open does not
   clear it.
2. **First boot — typed side effects** (≈8): timezone stage applies
   through `capabilities.set` and the capability's observed state changes;
   keymap likewise, and an invalid layout is **refused** (the closed-set
   rule, §5.3); the fork's organization path drives `enroll start` and
   reaches `enrolled`; the personal path writes nothing (assert the
   enrollment state file's absence and punard's audit stream carrying no
   enroll event).
3. **System Control** (≈8): `qs ipc call systemcontrol open`; SECURITY
   renders four rows with real capability states; `Encryption` and
   `Secure Boot` carry the dashed `SIMULATED` tag; ORGANIZATION rows are
   **absent** when unenrolled and present when enrolled; every row prints
   a `punarctl` verb; no row exposes a setter.
4. **Update / rollback** (≈10): `punarctl update status` exits 0 and
   reports image id, build date, channel, snapshot list, default
   subvolume; a snapshot is created; a tracked file is mutated;
   `update.rollback` restores it and switches the default subvolume; the
   audit event has all 12 required keys; a non-root peer's
   `update.rollback` is **refused**; `update.status` from a non-root peer
   **succeeds** (read verbs are unprivileged).
5. **Keyboard grammar** (≈8): the bind-table assertion (§7.5) — every
   documented chord present with the exact dispatcher and argument, no
   undocumented binds; plus the synthetic traversal subset **if and only
   if** `sendshortcut` was verified on the pinned Hyprland, and an
   explicit `info` line naming its absence if not.
6. **Toast** (≈4): a denial event produces exactly one toast; a second
   identical denial within the window does not duplicate it; the toast
   auto-dismisses; it claims **no** D-Bus name (assert
   `org.freedesktop.Notifications` is unowned — the mechanical form of
   decision 10).
7. **Budgets** (≈5): `PUNAR_IDLE_CPU_PCT` and `PUNAR_IDLE_WRITE_KB`
   present and numeric; `ram-breakdown.txt` present, non-empty, and
   accounting for at least 90% of `PUNAR_RAM_MEAN_MB` (a breakdown that
   explains a third of the number is not a breakdown).
8. **Info lines** (not assertions): the current DoD counts, the skip list,
   and every M13 refusal from §6.1 restated in the report, so the exported
   artifact carries the honest position without anyone opening this file.

Screenshots: `punar-m13-firstboot.png` (stage 04, the fork — the
acceptance reference), `punar-m13-systemcontrol.png` (SECURITY, enrolled),
`punar-m13.png` (the desktop with the toast raised).

### 10.2 `punar-demo-check.sh` — the story (phase 16)

Specified in §4.2–§4.4. Verdict `PUNAR_DEMO_OK` / `PUNAR_DEMO_FAIL` with
separate `ok`/`skip`/`FAIL` counts; fourteen screenshots per mode; two
modes per run.

### 10.3 CI wiring

`ci.yml`: `desktop-test` job renamed to M2..M13; `timeout-minutes` raised
to cover two extra phases **and the two demo modes** (the second mode
re-runs beats on an already-warm system, so the increment is smaller than
a doubling — measured on the first run and recorded, not guessed); new
artifacts `punar-demo-screenshots`, `punar-ram-breakdown`;
`punar-m13*.png` added to the screenshot artifact; `m13-report.txt` and
`demo-report.txt` added to the report artifact; `m13-check.sh` and
`punar-demo-check.sh` added to the shellcheck list.

### 10.4 Stale assertions M13 creates

M13 fulfills placeholders earlier milestones shipped honestly, and
refuses others. Both cases leave assertions that now certify something
false. **A stale assertion is rewritten to assert the new invariant, not
"updated to still pass"** — if M13's work regresses, these must go red.

| Script / file | Current | Must become |
|---|---|---|
| `crates/punarctl/tests/cli.rs:861` | asserts `update status` prints `"not scheduled"` | asserts the real status output's shape; the "no milestone schedules it" sentence is deleted from `main.rs:1509–1517` and from the test |
| `crates/punarctl/src/main.rs` | the `Command::Update` stub | the implementation; the `M12_NETWORK_PRIVACY` stub constant's users (`relay status`, `privacy connections`) are **M12's** to retire, not M13's |
| `m4-check.sh` / `m5-check.sh` | enumerate the capability set as three (firewall, hostname, timezone); M5's compliance categories likewise | four, including `system.keymap` — and M5's category-only sync assertion must still hold with the fourth category present, which is the *interesting* half of the change |
| `m9-check.sh` | `info` line: *"the graphical broker card is M13 polish"* | the card exists; the line is rewritten to name what is still CLI-only (the elevation dialog, refused — §6.1 row 9) |
| `m10-check.sh` | alert assertions and `info` lines naming **M13** for the notification centre, OSD, DND and grouping | **not planned for MVP** — decision 10. The M10 alert's own behavior is unchanged; only the forward pointer changes |
| `m11-check.sh` | `UNSUPPORTED` notification rows pointing at M13; the `PARTIAL` masthead row "deferred to M13 polish" | notifications: `UNSUPPORTED · NOT PLANNED FOR MVP` (still `UNSUPPORTED`, honestly re-pointed); masthead: `PARTIAL · NOT PLANNED` with the spec 1.24 reason |
| `m12-check.sh` | *"shell notification on denial is M13"*; *"inline restriction explanations M13"* | the toast exists (M13 ships it); inline explanations are **never, as stated** — re-pointed, with the wrapped-process path named as Phase 2 |
| `m1`/`m2` consumers of `idle-ram.sh` | `check-budgets.sh` reads two values | three more: `PUNAR_IDLE_CPU_PCT`, `PUNAR_IDLE_WRITE_KB`, and the breakdown file's presence |
| `CommandCenter.qml` | `System Control · SystemControl() · arrives M3` stub | the real `systemcontrol` IPC action; the project verb (`Open <workspace>`); the stub `kind: "stub"` branch is removed if nothing else uses it |
| `keyboard-grammar.md` | `PUNAR+S` unclaimed; the walkthrough marked "must be executed by a human"; the M2+ shortcut-overlay row | `PUNAR+S` claimed for System Control; the walkthrough's **executed** result with a date; the `PUNAR+N` collision recorded (§10.5); the overlay row resolved either way |
| `IMPLEMENTATION_STATUS.md` | M8–M13 rows; the `Current milestone` heading | the post-M13 truth, including the §3.3 counts verbatim |
| `PERFORMANCE_BUDGETS.md` | "budgets defined, nothing measured yet"; §1.5 has no boot number | the diet's before/after, the CPU and write baselines, the boot baseline, and the breakdown method as a new §2.5 |
| `os/images/mkosi.conf` | btrfs+snapper listed under "not yet done" | done — or, on the §8.4 fallback, **still** listed with the reason it was attempted and abandoned |
| `docs/api/ipc.md` | §1–§23 | plus `update.status` / `update.rollback` (§11), landed at implementation time |

### 10.5 The `PUNAR+N` collision, recorded

M10 §17 lists `Punar+N` among the notification-centre items it defers to
M13. `PUNAR+N` is already M2's **notes scratchpad**
(`keyboard-grammar.md`, shipped and exercised). M13 declines the
notification centre (decision 10), so the collision does not need
resolving now — but it must not be rediscovered by whoever builds one in
Phase 2. It is written into `keyboard-grammar.md` as a known conflict
with both claimants named.

---

## 11. Proposed contract (to land in `docs/api/ipc.md` at implementation time)

Two methods, both on punard's existing closed table. **No generic
execution surface, no parameterized command, no path passed from a
caller** — DoD item 26 is a negative assertion this milestone must keep
negative.

| Method | Peer | Params | Returns | Audited |
|---|---|---|---|---|
| `update.status` | any peer on the socket | `{}` | `{v, image_id, build_date, channel, default_subvolume, snapshots:[{id, kind, created_at, description}], rollback_available: bool, rollback_unavailable_reason?: string}` | no (read) |
| `update.rollback` | **root only** | `{to_snapshot_id: u32}` | `{v, previous_default, new_default, requires_reboot: true}` | yes — full 12-key event |

Notes that are part of the contract, not commentary: `to_snapshot_id` is
an integer validated against the snapshot list punard itself reads — a
caller cannot name a path, a subvolume, or a command.
`rollback_unavailable_reason` is a **required** field whenever
`rollback_available` is false, so the §8.4 fallback has a first-class
place to say why rather than rendering an empty success.

`system.keymap` adds **no** method: it is a capability id on the existing
`capabilities.get` / `capabilities.set` surface (§5.3).

---

## 12. Scope-out

| Out | Where it lives | Why, in one line |
|---|---|---|
| Everything in spec 77 (Phase 2) — real Secure Boot, TPM, hardware-backed identity, physical install, LUKS recovery, real Smplify cloud, Google/Entra/Okta, enterprise certificates, Wi-Fi, VPN replacement, real dual-hop relay, eBPF attribution, stronger sandbox, staged fleet updates, SIEM/OCSF, real secret integrations, richer MCP governance, software provenance, on-prem Smplify | **Phase 2** | Each needs real hardware, a real cloud, or a real organization; none is testable on a netless VM |
| Everything in spec 78 (Phase 3) — secure local inference, GPU fleet management, per-project model policy, AI routing, sovereign deployment, ephemeral workstations, remote Punar environments, activity-scoped credentials, measured boot, AI risk scoring, broad AI-application discovery, enterprise browser policy, isolated web-app packaging | **Phase 3** | Opportunities, not commitments — spec 78's own word |
| Spec 79's MVP non-goals — custom kernel, every laptop model, **full graphical installer**, full EDR, full DLP, replacing GitHub, replacing VS Code, building a browser engine, supporting every AI agent, perfect Shadow AI detection, large local models, exhaustive GPU tuning, production global relay, MDM, Windows/macOS parity | **Not in MVP** | The spec says so; §5.4's account deferral is the installer line applied |
| Notification daemon / centre, OSD, persistent DND | **Not planned for MVP** | Decision 10 |
| D-013 titlebar masthead | **Not planned** | Decision 11 / spec 1.24 |
| Inline in-process restriction explanations | **Never, as stated**; wrapped-process variant Phase 2 | The kernel returns an errno |
| D-002 greeter, D-010 updates panel, D-011 projects panel, D-016 menubar | **Phase 2** | No demo beat; each needs a surface Punar does not yet own |
| A second boot in `boot-test.sh` (rollback reboot proof) | **Follow-up**, named in §8.3 | Not attempted alongside a root-filesystem change in the final milestone |
| Bare-metal performance measurement | **Phase 2 / hardware** | §9 Test B — no device |
| Real Claude Code in CI | **Never in CI** | No network, third-party licence; runbook step 5b covers it |

---

## 13. Definition of done for M13 itself

1. `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test
   --workspace` green in the pinned `rust:1` container.
2. `./tools/validate-schemas.sh` green; `qmllint` clean on every new QML
   surface; `shellcheck` v0.11.0 clean on `m13-check.sh`,
   `punar-demo-check.sh` and the edited `idle-ram.sh`; `actionlint` clean.
3. `PUNAR_BUILD_MODE=summary ./tools/build-image.sh` succeeds **on the
   btrfs layout** — or, on the §8.4 fallback, on the existing layout with
   the fallback recorded.
4. `PUNAR_M13_OK` in `m13-report.txt`, boot-test phase 15 green; the three
   M13 screenshots captured.
5. `PUNAR_DEMO_OK` in `demo-report.txt`, boot-test phase 16 green; **28
   demo screenshots** (fourteen per mode) uploaded; the skip list printed
   and non-surprising — every skip naming a milestone whose check is not
   yet green.
6. `punar-ram-breakdown.txt` published, and the diet's before/after
   recorded in `PERFORMANCE_BUDGETS.md` with run ids — **whether or not
   the target was reached**.
7. `PUNAR_IDLE_CPU_PCT` and `PUNAR_IDLE_WRITE_KB` measured and recorded.
8. The keyboard-only walkthrough **executed by a human**, dated, with the
   result — pass or fail — written into `keyboard-grammar.md` and §3.2
   row 5.
9. The §3 matrix regenerated from the runs that prove it, with the §3.3
   counts updated in place and copied into `IMPLEMENTATION_STATUS.md`.
10. Every stale assertion in §10.4 rewritten to the new invariant, and
    every §6.1 refusal re-pointed in the document that deferred it, so no
    file in the repository still points at M13 for something M13 did not
    do.
11. Every claim in the build record names the gate that proved it, and
    everything unproven appears in §3.2, §10.4 or the report's `info`
    lines. Spec 1.22.

---

## 14. Verification status (spec 1.22)

**This document is a design plan. Nothing in it has been built, and no
claim in it rests on a run that has not happened.**

What was verified while writing it, by reading the tree rather than the
prose:

- The Definition-of-Done matrix's statuses come from check scripts and
  source, not from milestone narratives. Specifically: `grep
  commandcenter` over `m2..m9-check.sh` returns nothing (item 4); `grep
  chromium` likewise (item 7); `crates/punarctl/src/main.rs:1509–1517`
  and `crates/punarctl/tests/cli.rs:861` carry the update stub and its
  test (item 25); `crates/punard/src/backends/` contains exactly three
  backends (§5.3); `m3-check.sh:226–232` is the `system.exec` /
  `shell.run` refusal (item 26); `tests/performance/check-budgets.sh`
  gates RAM and services-RSS only (item 3).
- `CommandCenter.qml`'s `staticActions` has two entries and no workspace
  verb; M2's own §8 verification table never claims otherwise.
- D-002, D-004, D-008, D-010, D-011 and D-016 appear in no milestone
  document.
- `PUNAR+S` is unclaimed across the M1/M2/M7/M9/M10/M11/M12 grammars;
  `PUNAR+N` is claimed by M2 and wanted by M10 §17.

What is **not** verified and must be at implementation time:

- **The `sendshortcut` dispatcher on hyprland 0.56.2-1** (§7.5). Asserted
  as a candidate from general knowledge of Hyprland; **not** checked
  against the pinned binary. If it is absent, §7.5's fallback is the
  plan, not a surprise.
- **Whether btrfs + snapper builds cleanly under the pinned mkosi and
  boots under QEMU/OVMF** (§8). This is the milestone's largest unknown
  and the reason decision 9 sequences it first and §8.4 writes the
  fallback in advance.
- **Every RAM-diet candidate in §7.3.** They are hypotheses. The
  breakdown decides, and no number is promised.
- **Whether `xdg-desktop-portal` is required by M11's web apps** — must
  be confirmed with M11 before it is touched.
- **The M9–M12 statuses in §3.2**, which are true as of this writing and
  will change as those milestones' checks run. The matrix is regenerated,
  not remembered.

No `m13-check.sh` or `punar-demo-check.sh` exists. No `PUNAR_M13_OK` or
`PUNAR_DEMO_OK` exists anywhere. No demo screenshot has ever been taken.
No snapshot has ever been created on any Punar image. The keyboard-only
walkthrough has never been performed.
