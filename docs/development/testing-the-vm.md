# Testing Punar in the VM

**Who this is for:** someone sitting down in front of the machine wanting to
drive the desktop and judge it. It is deliberately short. The exhaustive
per-surface record is [`desktop-surfaces.md`](desktop-surfaces.md); the
honest limits of the whole project are
[`user-blocked.md`](user-blocked.md).

---

## 1. Start it

```bash
./tools/punar-up.sh
```

That fetches the newest CI-built image (~2 GB, cached outside the repo under
`$TMPDIR`), verifies its SHA256, boots it under QEMU, and opens TigerVNC on
`127.0.0.1:5900`. Pass a run id to boot a specific build:
`./tools/punar-up.sh 32945695360`.

It needs `gh` (authenticated), `qemu` and TigerVNC — all already installed on
this machine.

**It boots straight to the desktop** — the dev image autologins as `punar`
(`/etc/greetd/config.toml`, `initial_session`). If you are ever asked, the
dev password is `punar`.

> **Be patient on the first boot.** Apple Silicon cannot hardware-virtualise
> an x86_64 guest, so this is TCG emulation: minutes to the desktop, against
> the 18 s the KVM CI path measures. That gap is the entire argument for the
> aarch64 image in the "Try Punar" plan, and it is a property of your laptop,
> not of Punar.

If TigerVNC does not open by itself, open it and connect to `127.0.0.1:5900`.
macOS Screen Sharing **will not work** — it requires Apple's auth extensions
that QEMU's VNC server does not implement.

## Native ARM64 desktop on Apple Silicon

The ARM64 desktop runs under hardware virtualization instead of the very slow
x86-on-ARM translation path:

```sh
PUNAR_ARM64_IMAGES=desktop ./tools/build-arm64-image.sh
./tools/demo-arm64-vm.sh
```

Connect TigerVNC to `127.0.0.1:5901`. The launcher uses a disposable disk
snapshot, binds VNC and QMP to localhost, and gives its keyboard and pointer
stable device IDs so automated press/release sequences cannot leave a virtual
modifier latched. Set `PUNAR_VM_OFFLINE=1` when validating offline behavior.

When you are finished, stop the disposable guest cleanly from another terminal:

```bash
./tools/punar-down.sh
```

The launcher refuses to collide with an already-running VM and points to this
command; it never unlinks a live QEMU monitor or silently replaces your session.

Capture the VM's exact framebuffer at any point with:

```bash
./tools/punar-screenshot.sh /tmp/punar-command-center.png
```

This uses QEMU's monitor rather than a host-desktop screenshot, so the PNG is
only the guest's 1280×800 display. It refuses to overwrite an existing file.

---

## 2. The ten-minute tour

Everything is keyboard-first. `PUNAR` means the **Punar key**: Windows / Meta
on a PC keyboard, or the key your VM client maps to guest Meta (normally
Command on an Apple keyboard).

| Do this | Chord | What you should see |
|---|---|---|
| **Start here** | `PUNAR + /` | The shortcut help. It is generated from `hyprctl binds -j` — the live table, not a written copy. **If this page and any document disagree, this page is right.** |
| Terminal | `PUNAR + Return` | foot, Geist Mono, panel surface |
| Browser | `PUNAR + B` | Chromium, native Wayland |
| Find and open an app | `PUNAR + Space` | Type `Chromium`, then Enter; installed `.desktop` entries are searched live |
| Choose a wallpaper | `PUNAR + Space` | Type `wallpaper`; Stillpoint, Daybreak, Winterline, Earthrise, and the lean Field vector are explicit typed actions |
| System control | `PUNAR + S` | The settings surface |
| Notification centre | `PUNAR + SHIFT + N` | The centre; toasts appear on their own |
| Project overview | `PUNAR + Tab` | Workspaces as projects |
| AI panel | `PUNAR + A` | What AI has done on this device |
| Close the focused app | `PUNAR + Q` | Its window disappears and the menubar clears the app name |
| Lock | `PUNAR + Escape` | Password is `punar` |

Layouts: `PUNAR + ,` / `PUNAR + .` cycle presets. `PUNAR + 1..9` switch
workspaces. `PUNAR + T` is a scratchpad terminal.

**Themes have no chord** — they are driven over IPC:

```bash
qs -p /usr/share/punar/shell ipc call theme list
qs -p /usr/share/punar/shell ipc call theme show nocturne
```

Seven themes ship (`paper`, `panel`, `graphite`, `nocturne`, `oxide`,
`ember`, `contrast`). Any surface can be driven the same way — `ipc show`
lists all fourteen targets.

---

## 3. What is real, and what is not

This is the part worth reading before forming a judgement.

**Real, and exercised by CI on every push:**
the compositor and all fourteen shell targets, the terminal, the browser
(native Wayland, launched through the same flags on every path), link
handling via `xdg-open`, the theme system, `punard` + `punarctl` and their
typed capability API, declarative desired state and reconciliation, the
mock-enrolment journey, the developer environment manager, the AI agent
registry, the access ledger, approval gates, the secret broker, and
shadow-AI detection. As of the most recent green run that is **561+
assertions** across nine in-VM exercises plus a live desktop-surfaces
exercise.

**Real but simulated, and labelled so wherever it appears:** Secure Boot,
TPM/measured boot, the Smplify control plane (a local mock), identity
providers, and the private relay. Anything drawn with a dashed stroke in the
design language is in this category by construction.

**Not built at all:** the installer and onboarding, `punarctl app` and the
third-party app catalogue (including the Google Chrome install command),
execution trust / the Gatekeeper-class exec gate, web-app install and
browser contexts (Milestone 11), and network policy and the relay
(Milestone 12). Each of these is *designed* — see `docs/design/` — and
none of it is claimed as working.

**Networking is new and untested by CI.** The gate runs the VM with
`-nic none`, so wired DHCP + resolved have never been exercised by a
machine. The demo VM is launched *with* user-mode networking specifically so
you are the first to try it. If the browser cannot load a page, that is the
first thing to check:

```bash
networkctl status
resolvectl status
```

---

## 4. If something is wrong

The surfaces are one process, so the fastest triage is:

```bash
systemctl --user status punar-shell    # or: pgrep -a qs
journalctl --user -u punar-shell -n 50
punarctl status
punarctl audit tail
```

The in-VM exercise reports from the CI run live in `/run/punar/`
(`surfaces-report.txt`, `m2-report.txt` … `m10-report.txt`). Each line is
one assertion, and the last line is the verdict.

**Nothing here needs to be preserved.** The VM boots with `-snapshot`, so
every change is discarded on exit — experiment freely.
