# Milestone 6 — Developer environment manager: architecture plan

Spec authority: section 76 Milestone 6 ("Deliver `punar-env`,
Podman/devcontainer, and Atlas fixture"), grounded in sections 11.6
(`punar-env` service listing), 16 (developer experience — "Avoid
preinstalling excessive toolchains on the host. Prefer project isolation"),
17 (developer environments: the command set and the sole full
ProjectEnvironment example, which is the Atlas fixture verbatim), 14
(project workspaces — context only, M2-built), 27 (AI session launch —
`punar-env agent` is the entry point, deferred to M7), 36 (project-aware
networking — manifest semantics only; enforcement is FUTURE), and 1.22
(honesty: never claim enforcement that does not exist).

Binding prior contracts, not relitigated: `docs/api/ipc.md` (untouched —
see §3.1: `punar-env` speaks to no daemon in M6),
`docs/development/milestone-1.md` (podman 6.1.0-1 + crun + netavark already
in the desktop image; `punar:100000:65536` subuid/subgid for rootless),
`milestone-2.md` (workspaces.json contract in `crates/punar-workspace`),
`milestone-3.md`–`milestone-5.md` (check mechanics, D-014 CLI grammar, the
idle-ram.sh ordering chain, budgets discipline), ADR-001 (vendor-pinned
snapshot inputs, `os/images/snapshot.env`).

M6 is the milestone where the **environment boundary of section 17 becomes
a real container**: a project directory with a manifest becomes a running
rootless Podman container with the project bind-mounted at `/workspace`,
driven by a user-facing CLI, on a CI VM that has **no network**
(`-nic none` in `tools/boot-test.sh`). Everything the manifest *declares*
but the OS does not yet *enforce* — toolchain provisioning, services,
network zones, credential grants, AI agents — is parsed, validated, and
**displayed with its enforcement milestone**, never silently faked
(spec 1.22).

---

## 1. Scope

In: `crates/punar-env` new workspace **bin** crate (user-facing CLI, runs
as the invoking user, no daemon, no root); strict-parse + schema-conformant
validation of the section 17 ProjectEnvironment manifest; `init` / `up` /
`shell` / `status` / `destroy` implemented against rootless podman;
`agent <name>` as a labeled M7 stub; a tiny deterministic offline base
image (`punar-env-base` OCI archive) built at image-build time from the
pinned snapshot and staged at `/usr/share/punar/oci/punar-env-base.tar`;
the Atlas fixture staged into the image at
`/usr/share/punar/fixtures/projects/atlas/`; `m6-check` exercising the
full lifecycle rootless; boot-test/CI gate additions.

Out (all documented in status output or §13, never silently dropped):
toolchain **provisioning** (declared-only in M6 — devcontainer feature
install needs registry network the product does not have yet); **service
containers** (postgres is declared-not-started — decision §5.6); network
enforcement (spec 36 FUTURE; M12); credential grants (M9 secret broker);
AI agent launch (M7 registry/adapters); devcontainer.json interop (§13);
any punard IPC or schema change; any punar-shell/workspace wiring beyond
documentation (§11).

## 2. Decision summary

| # | Decision |
|---|----------|
| 1 | **Crate**: `crates/punar-env`, new workspace bin crate. Runs **as the user** — no daemon, no root, no punard IPC in M6. Talks to rootless podman via the **podman CLI with fixed argv** (`std::process::Command`, one string per argument), never a shell string, never the podman REST/varlink socket. §3. |
| 2 | **Manifest**: canonical filename `punar-env.yaml` (accepted alternates `punar-env.yml`, `project-environment.yaml` — the fixture's name); parsed with **`serde_norway`** (maintained continuation of the archived `serde_yaml`, same serde API) into structs mirroring `schemas/project/project-environment.json` **field-for-field** (unknown fields **warn**, they do not fail — as-built decision, §4.3); Atlas fixture round-trips byte-verbatim in unit tests. §4. |
| 3 | **Environment model**: one container per project, `punar-env-<project>`, labels `dev.punar.project=<name>` + `dev.punar.managed-by=punar-env`; project dir bind-mounted at `/workspace` with the filesystem grade mapped (`read_write`→rw, `read`→ro, `deny`→no mount); **`--network none` always in M6** (honesty + no rootless-net helper in the image + offline CI); podman is the single source of truth for environment state — no state file. §5. |
| 4 | **Toolchains/services honesty**: toolchains are **declared, reported in status, not installed** (provisioning needs network; plan §13). Service containers are **skipped in M6** (decision: keep the offline story to one tiny base image); `status` shows them as declared with the label. §5.5–5.6. |
| 5 | **Offline base image**: `punar-env-base` is a **hand-assembled single-layer OCI archive built during image build from the pinned snapshot's `busybox` package** (static shell + core applets), deterministic (fixed timestamps, sorted tar, numeric owners), staged world-readable at `/usr/share/punar/oci/punar-env-base.tar`, `podman load`ed on first `up`. ~2–3 MB; total M6 image growth budgeted < 10 MB (allowance ~80 MB). Rejected: `skopeo copy` from docker.io (second provenance), full Arch chroot rootfs (size). §6. |
| 6 | **status output**: D-014 grammar (masthead, middle-dot separators, aligned columns, `--json`); renders the section 17 permissions block as a table with per-row `DECLARED · enforcement M7/M9/M12` labels; the one grant `punar-env` actually realizes in M6 — `filesystem.project` via the bind mount — is labeled `applied (bind mount)`. Unmanaged-first: no org rows. §7. |
| 7 | **m6-check**: root oneshot `punar-m6-check.service` (never enabled; started synchronously by idle-ram.sh after m5-check); all env commands run **as `punar`** via `runuser` with the session env; asserts rootless podman, init idempotence, up (load + running + `/workspace` writable), shell exit-code passthrough, status rendering incl. permissions verbatim, destroy (container gone, files intact); verdict `/run/punar/m6-report.txt` `PUNAR_M6_OK`/`PUNAR_M6_FAIL`; host gate boot-test phase 8. §10. |
| 8 | **Budgets**: `punar-env` is a short-lived CLI — the punard-only `PUNAR_SERVICES_RSS_MB` gate is structurally untouched; containers run only inside the m6-check window, after the idle-RAM sampling window has closed. §9. |

---

## 3. `punar-env` — the crate

New workspace member `crates/punar-env` (bin `punar-env`), spec section
11.6. Same workspace hygiene as every other crate: edition 2024,
`#![forbid(unsafe_code)]`, clap derive for the CLI (workspace dep already
present), `thiserror` for error taxonomy.

### 3.1 No daemon, no root, no IPC — by design

Developer environments are the *user's* environments. `punar-env`:

- runs as the invoking user; never elevates; refuses to run as uid 0
  (hard error — rootless podman as root would create root-owned container
  state and defeat the M1 subuid design);
- speaks to **no** punard socket in M6. `docs/api/ipc.md` is untouched.
  The M7 link (agent launch consults the registry / punar-agentd) is
  documented in §11 and §13, not stubbed into the protocol now;
- holds **no state of its own**. Environment state is derived from podman
  (`podman ps`/`inspect` filtered by the `dev.punar.managed-by` label);
  the manifest on disk is the declaration. Nothing to corrupt, nothing to
  drift.

### 3.2 Podman invocation discipline

Every podman call is a fixed argv built with `std::process::Command` —
one `.arg()` per token, project-derived values (name, paths) passed as
whole arguments. **Never a shell string, never `sh -c` on the host.** The
only place a user-provided string rides a `-c` is *inside the container*
(`punar-env shell -c <cmd>` → argv
`["podman","exec",…,"/bin/sh","-c",<cmd>]` — the container's own shell
interprets it, which is the documented meaning of the flag; the host never
interpolates). Unit tests assert exact argv vectors table-driven (§14).

The podman **CLI** (6.1.0-1, pinned since M1) is the integration surface,
not the REST/varlink API: the CLI is the stable user-facing contract, needs
no service socket, no API-version negotiation, and no new dependency. If a
future milestone needs events/streaming, that is the point to revisit.

### 3.3 Command set and exit codes

Exactly the section 17 verbs, D-014 exit-code discipline
(`docs/api/ipc.md` §7): `0` success · `1` runtime/podman error · `2` usage
(clap). Plus:

- `punar-env shell` (and `shell -c`) **passes the container command's exit
  code through** verbatim (`podman exec` semantics). Documented collision
  with 1/2 is accepted — passthrough is the useful property for scripts
  and for m6-check.
- `punar-env agent <name>` is the **labeled M7 stub**: validates that
  `<name>` appears in the manifest's `ai.agents` list (a real check —
  parsing is delivered), then prints
  `agent sessions arrive in Milestone 7 (AI Agent Registry); '<name>' is declared in this environment's manifest`
  to stderr and exits `1`. `--help` lists it with an `(M7)` tag. Never
  pretends to launch anything (spec 1.22).

All human output follows Plate D-014; `--json` on `status` prints the
machine object (§7). Non-TTY stdout or `NO_COLOR` strips ANSI.

---

## 4. Manifest parsing and validation

### 4.1 Filename resolution

Section 17 names the commands, not the file. Decision: canonical name
**`punar-env.yaml`** in the project root; accepted alternates
`punar-env.yml` and `project-environment.yaml` (the Atlas fixture's
name, which matches the schema file `project-environment.json`). Lookup
order is exactly that list; **more than one present is a hard error**
(exit 2, listing the conflict) — never guess. `init` scaffolds
`punar-env.yaml` and only when no accepted name exists.

### 4.2 YAML dependency — evaluated, justified

There is **no YAML crate anywhere in the workspace today** (`Cargo.lock`
has serde/serde_json only; the only YAML handling in the repo is pyyaml
inside `tools/validate-schemas.sh`'s python venv — a build-tool, not
vendorable into a Rust binary). A dependency must be added; the field is:

- `serde_yaml` — the de-facto standard, but **archived by its author in
  March 2024**; frozen, flagged unmaintained by advisory tooling. Rejected
  as a *new* dependency in 2026.
- `serde_yml` — automated fork; rejected on maintenance-quality
  reputation.
- `saphyr` / `yaml-rust2` lineage — maintained but no serde integration;
  would mean hand-mapping. Rejected: the manifest is a serde-shaped
  problem.
- **`serde_norway`** — maintained continuation fork of `serde_yaml`,
  drop-in serde API. **Chosen.** The `unsafe` it inherits (the
  `unsafe-libyaml` translation) stays in the audited dependency, not in
  Punar crates — the same stance the workspace already took for
  `signal-hook`/`rustix` (root `Cargo.toml` comments). Pinned in the
  workspace `[workspace.dependencies]` like every external dep.

Implementation-time verification step (§14): confirm `serde_norway`'s
advisory status at vendoring; the documented fallback is pinning frozen
`serde_yaml 0.9.34+deprecated` (identical API — a one-line swap), accepted
only with the deprecation noted in Cargo.toml.

### 4.3 Strict structs, schema-conformant

Serde structs mirror `schemas/project/project-environment.json`
**field-for-field**. As built, unknown fields **warn rather than fail**
(a deliberate softening of this plan's original `deny_unknown_fields`
wording, directed at implementation time: a manifest from a newer Punar
should degrade legibly, not brick the environment — the warning names
the unknown path). Everything else stays strict: `apiVersion`/`kind`
checked against the schema's `const` values (`punar.dev/v1alpha1`, `ProjectEnvironment`);
enums exactly the schema's — filesystem grade `read_write|read|deny`,
network decision from the shared decision def (**`request` is invalid in
network**, valid in credentials — the schema's deliberate asymmetry,
preserved); the name-pattern and min-length constraints
(`^[a-z][a-z0-9_]*$` map keys, kebab/dotted service and agent names,
non-empty toolchain versions, `minProperties`/`minItems` ≥ 1) enforced in
a post-parse validate pass with **path-qualified error messages**
(`permissions.network.corp_prod: …`). The schema's Milestone 3 `$comment`
about punar-common reconciliation stays true: these structs live in
`punar-env` (sole consumer today); promotion to `punar-common` happens
when a second consumer appears (M7 agent launch) — tracked §13.

Unit tests parse `fixtures/projects/atlas/project-environment.yaml` (the
spec-verbatim bytes) and assert every field; a serialize round-trip
asserts no data loss; invalid-manifest cases (`request` in
network, empty toolchains, wrong apiVersion) assert the path-qualified
rejection, and the unknown-field case asserts the warn-not-fail path. `tools/validate-schemas.sh` remains the schema-side oracle —
no schema changes (§12).

### 4.4 `init` — scaffold, idempotent

- No accepted manifest present → write `punar-env.yaml`: the full
  section 17 shape (all eight top-level keys — the schema requires all,
  each non-empty), `project.name` derived from the directory name
  (lowercased; must match the project-name conventions or `init` asks for
  `--name`), remaining values the Atlas example's, under a header comment
  telling the user to edit. **Schema-valid out of the box.**
- Manifest present → parse + validate it, print
  `already initialized · <file> · project <name>`, exit 0, **never
  rewrite a byte** (m6-check asserts byte-identity — §10).
- The scaffold template is one file,
  `crates/punar-env/assets/punar-env.scaffold.yaml`, `include_str!`-ed
  into the binary; a byte-identical copy sits in
  `schemas/project/examples/` so `./tools/validate-schemas.sh` guards the
  template forever; a unit test asserts the two files are identical.

---

## 5. Environment model

### 5.1 Naming and labels

`project dir + manifest → container punar-env-<project.name>`. Labels on
create: `dev.punar.managed-by=punar-env` (ownership filter — `status`
and `destroy` refuse to touch containers without it) and
`dev.punar.project=<name>`. The container name is derived, deterministic,
and collision-checked (a second project with the same name is reported,
not clobbered).

### 5.2 `up`

1. Parse + validate the manifest (any error → exit 1 before podman runs).
2. Ensure the base image: `podman image exists <ref>` else
   `podman load -i /usr/share/punar/oci/punar-env-base.tar` (first-use
   load; also pre-loaded by m6-check so the check can assert both paths).
   `<ref>` is `localhost/punar-env-base:m6` (§6).
3. Create + start:
   `podman run -d --name punar-env-<name> --label … --network none
   --mount type=bind,src=<projdir>,dst=/workspace[,ro] --workdir /workspace
   <ref> /bin/sh -c 'exec sleep 2147483647'`
   — a sleep-forever PID 1 keeps the environment alive for `exec`
   sessions; sessions come and go via `podman exec`, so PID 1 never needs
   to reap anything.
4. Idempotent: container already running → `already up`, exit 0; exists
   but stopped → `podman start`.

Rootless mapping: container uid 0 maps to the invoking user (podman
rootless default), so files created in `/workspace` land on the host owned
by `punar` — no `--userns` gymnastics needed for the M6 model; the subuid
range (`punar:100000:65536`, M1) covers non-root container uids.

### 5.3 `--network none`, stated loudly

Every M6 container runs with `--network none`. Three reasons, all
documented in `status` output and here:

1. **Honesty (spec 1.22 / section 36):** the manifest's `network` block is
   declared-not-enforced until M12. Running with no network is the only
   configuration that cannot *contradict* the declaration (a `corp_prod:
   deny` next to an unrestricted default network would be a silent lie).
2. **Image reality:** the desktop image ships netavark/aardvark-dns (root
   networking) but **no rootless-net user-mode helper** (`passt`/
   `slirp4netns` are not in the M1 package set) — default rootless
   networking would fail anyway. No new package is added for M6.
3. **CI:** the test VM runs `-nic none`; the offline story must hold.

When M12 lands project-route policy, `punar-env` maps the manifest's
network zones onto enforced configuration; until then `status` says
`network: isolated (M6) · declared zones enforced M12`.

### 5.4 Filesystem grades — the one grant realized in M6

`permissions.filesystem.project` maps to the `/workspace` mount:
`read_write` → rw bind, `read` → ro bind, `deny` → no mount (the
container starts with no project view — legal, weird, honestly rendered).
Zones other than `project` (the schema's open map: `home`, `ssh`, …) have
no M6 realization and are listed as declared with enforcement deferred.

### 5.5 Toolchains — declared, not installed

`toolchains: node "24", rust stable` is **reported in `status`, not
provisioned**. Installing toolchains means devcontainer-feature or
registry downloads — network the CI VM does not have and the product's
network story (M11/M12) does not yet exist. The M-later plan: when
punar-env can pull/build real devcontainer images, toolchains become image
inputs and `status` flips the label from `declared · provisioning M-later`
to versions read from inside the environment. No fake `node` shim, no
pre-baked toolchain in the base image pretending to be provisioning
(§13).

### 5.6 Services — skipped in M6 (decision)

`services: [postgres]` would need a postgres OCI image preloaded — ~90 MB
compressed alone, blowing most of the budget for a service nothing in M6
exercises, plus a second offline archive to pin and load. Decision:
**service containers are out of M6 entirely.** The manifest field is
parsed, validated, and rendered (`postgres · declared · not started in
M6`); no service container is created; `destroy` therefore has exactly one
container to remove. Revisit when the environment has consumers that need
a live service (post-M7 agents are the first candidate).

### 5.7 `shell`, `status`, `destroy`

- `shell`: `podman exec -it <name> /bin/sh` (busybox ash in the M6 base);
  `shell -c <cmd>` non-interactive (no `-t`), exit code passed through
  (§3.3). Not-running → exit 1 with `environment not up · run punar-env up`.
- `status`: §7.
- `destroy`: `podman rm -f punar-env-<name>` (label-checked first — §5.1),
  idempotent (`nothing to destroy`, exit 0). **Touches only the
  container**; the project directory and manifest are never written. The
  loaded base image is left in the user's podman storage (shared across
  projects; removing it is `podman rmi`, the user's call).

---

## 6. Offline base image — `punar-env-base`

### 6.1 The problem

CI VM: no network. `punar-env up` needs an OCI image. Arch's pacman
ecosystem ships no OCI archives, so the image must be **built during the
OS image build** (where the pinned snapshot is reachable) and staged into
the filesystem for `podman load` at runtime.

### 6.2 Decision: hand-assembled single-layer OCI archive from the snapshot's busybox

A new build step in `os/images/scripts/container-build.sh` (invoked from
`stage_desktop_extra`-adjacent code, same staged-gitignored pattern):

1. Download the `busybox` package from the **same pinned ALA snapshot**
   every other input comes from (`pacman -Sw` into a staging cachedir, or
   a direct fetch of the pinned filename+sha256 recorded next to the M1
   package table — exact pin verified at implementation against ALA
   2026/08/20). Arch's busybox is a **statically linked** rescue binary —
   asserted at build time (`ldd` must report "not a dynamic executable");
   contingency if that assertion ever fails on a future snapshot: add the
   snapshot glibc to the rootfs (~+40 MB, still under budget) — documented
   here so the guard has a plan, not to be exercised now.
2. Assemble a minimal rootfs: `/bin/busybox` plus symlinks for the applets
   the M6 contract needs (`sh`, `sleep`, `cat`, `echo`, `ls`, `touch`,
   `env`, `id`, `uname`), `/workspace` mountpoint dir, `/tmp`, and a
   marker file `/etc/punar-env-base-release` containing
   `punar-env-base m6 <snapshot-date>` (m6-check reads it back from inside
   the container — proof the *staged archive* is what ran).
3. Build the OCI layout **by hand, deterministically** — no docker/podman
   daemon inside the builder container, no nesting: an **uncompressed**
   layer tar (`--sort=name --numeric-owner --owner=0 --group=0
   --mtime=<snapshot-date> --pax-option=delete=atime,delete=ctime`;
   uncompressed because gzip embeds timestamps), sha256-addressed blobs,
   an image config (fixed `created` = snapshot date, `Cmd ["/bin/sh"]`),
   manifest + `index.json` (annotation
   `org.opencontainers.image.ref.name=localhost/punar-env-base:m6`) +
   `oci-layout`, all tarred with the same determinism flags into
   `punar-env-base.tar`. Byte-identical across rebuilds of the same
   snapshot pin; the build prints its sha256 into the build log.
4. Stage at `mkosi.extra/usr/share/punar/oci/punar-env-base.tar`, mode
   **0644** (the rootless user must read it), staged-gitignored like the
   shell QML and Acme fixtures.

`podman load -i` accepts oci-archive natively; the ref
`localhost/punar-env-base:m6` is what `up` checks/loads/runs (§5.2). The
tag carries the milestone; a content change means a new tag, and `up`
loads whatever tag the binary was built to expect — binary and archive
ship in the same image, so they cannot skew.

### 6.3 Rejected alternatives

- **`skopeo copy docker.io/library/busybox@sha256:… → oci-archive` at
  build time**: works, but introduces a second provenance (Docker Hub)
  outside the ADR-001 snapshot pin, needs digest-vs-multiarch-index care,
  and adds `skopeo` to the builder. The chosen path has exactly one
  upstream: the snapshot.
- **`alpine` via skopeo**: same provenance objection, 3× the bytes, buys
  nothing busybox doesn't for M6 (`apk` is useless offline).
- **pacman-bootstrapped minimal Arch chroot** (`pacman -r` base into a
  rootdir, tar): same provenance, but ~150–300 MB installed — over budget
  for a container whose M6 job is `sh`, `sleep`, and a writable bind
  mount.
- **`podman export/save` inside the builder**: requires nested
  container tooling in the Docker-driven builder (fragile under the
  arm64-Mac emulation path documented in the Containerfile) and produces
  non-deterministic metadata. Hand assembly is ~40 lines of bash and
  reproducible.

### 6.4 Size, honestly

busybox package ≈ 1–1.5 MB compressed → uncompressed single-layer archive
≈ 2.5–3 MB. Plus the `punar-env` release binary (≈ 2–4 MB, same profile
as punarctl) and the Atlas fixture (KBs): **total M6 growth on the qcow2
budgeted < 10 MB** against the ~80 MB allowance. CI guard: the build step
fails if `punar-env-base.tar` exceeds **16 MiB** — a tripwire far below
the budget so accidental fat (a future glibc contingency, a stray layer)
is caught at build, not at review.

---

## 7. `punar-env status` — D-014 rendering

Plate D-014 (`docs/design/mockups/cli-grammar.html`) via the same
conventions punarctl established (`docs/api/ipc.md` §7): tracked-uppercase
masthead + U+2500 rule, middle-dot separators, aligned columns, ANSI color
only on status words, no org rows ever (unmanaged-first — an environment
manifest is the *user's* declaration; enrollment does not add rows here).
Target render for Atlas, up:

```
PUNAR-ENV · ATLAS
────────────────────────────────────────────────────────
Environment   devcontainer · running · punar-env-atlas
Workspace     /home/punar/atlas → /workspace · read_write (applied · bind mount)
Network       isolated (M6) · declared zones enforced M12

TOOLCHAINS · DECLARED · provisioning arrives with the network story
  node        24
  rust        stable

SERVICES · DECLARED · not started in M6
  postgres    declared

AI AGENTS · DECLARED · sessions arrive M7
  claude-code · codex

PERMISSIONS · DECLARED · enforcement milestones per row
  filesystem  project      read_write   applied (bind mount)
  network     internet     allow        declared · enforced M12
  network     corp_dev     allow        declared · enforced M12
  network     corp_prod    deny         declared · enforced M12
  credentials github       allow        declared · enforced M9
  credentials aws_dev      request      declared · enforced M9
  credentials aws_prod     deny         declared · enforced M9
```

Every manifest value renders **verbatim** (m6-check greps these exact
value tokens against the fixture). States: `running` / `stopped` /
`not created` (green/yellow/dim per D-014 color rules). `--json` emits
`{v:1, project, container, state, workspace:{src,dst,mode}, toolchains,
services, ai, permissions, enforcement:{network:"M12",credentials:"M9",
ai:"M7"}}` — the enforcement labels are part of the machine object too,
so no consumer can scrape a value and drop the honesty label.

---

## 8. Image and pipeline deltas

- **Packages: none.** podman/crun/netavark shipped in M1; busybox enters
  only as bytes inside the OCI archive, never installed on the host.
- **`container-build.sh`**: add `-p punar-env` to the cargo build and the
  `install` list (staged to `extra/usr/bin/`, same as punarctl); add the
  OCI-archive build step (§6.2); add Atlas fixture staging —
  `fixtures/projects/atlas/` →
  `extra/usr/share/punar/fixtures/projects/atlas/` (as-built path; the
  manifest + network-policy contract files only, not the README —
  staged-not-committed-twice, the Acme pattern: repo fixtures stay the
  single source of truth for host tests, schema validation, and the
  image).
- **Units**: `punar-m6-check.service`, root oneshot, **never enabled** —
  no `.wants` symlink anywhere; started only by idle-ram.sh (the
  m2–m5 discipline; vendor-wants lessons don't even apply to a unit that
  is never enabled, and no `is-enabled` assertion is ever written).
- **`idle-ram.sh`**: one appended hook — start `punar-m6-check.service`
  synchronously strictly AFTER the m5-check hook and strictly BEFORE the
  export, so `m6-report.txt` + `m6-*.txt`/`m6-*.json` snapshots ship in
  the same tar. Never fatal there; the verdict is the report file.
  `punar-idle-ram.service` `TimeoutStartSec` is extended 100 → 110 min:
  the bounded phases now sum to 15 (measure) + 25 (m2) + 10 (m3) +
  12 (m4) + 15 (m5) + 10 (m6) = 87 min, and 110 leaves the export and
  TCG slop over 20 min of headroom.
- **`tools/boot-test.sh`**: phase 8 — parse the exported
  `m6-report.txt`; hard-fail on `PUNAR_M6_FAIL` or a truncated report
  (the m2–m5 pattern verbatim); add `m6-*` to the export copy globs and
  the required-artifact list.
- **`ci.yml`**: no new jobs; the desktop boot-test job's artifact upload
  already sweeps the proof dir — extend the artifact name list only if it
  enumerates files explicitly (mirror whatever m5 did).

---

## 9. Budgets (spec 6, PERFORMANCE_BUDGETS.md)

- **Idle RAM / services RSS: structurally untouched.** `punar-env` is a
  short-lived CLI process, not a service; the `PUNAR_SERVICES_RSS_MB`
  gate reads the `punard.service` cgroup only. Containers exist only
  inside the m6-check window, which idle-ram.sh opens strictly after the
  sampling window closes — heavier check work there is free by the
  established ordering.
- **Disk: < 10 MB** growth (§6.4) against the ~80 MB M6 allowance;
  16 MiB archive tripwire at build.
- **m6-check wall time**: seconds (podman load of a 3 MB archive, one
  container create, a handful of execs) — well inside the existing
  EXPORT_TIMEOUT margins; no timer interactions (nothing in M6 uses
  timers).

## 10. In-VM exercise plan — `m6-check`

`/usr/lib/punar/m6-check.sh`, root oneshot, `set -u`, **always exits 0**
— verdict in `/run/punar/m6-report.txt` (`ok`/`FAIL` assertion lines,
final `PUNAR_M6_OK`/`PUNAR_M6_FAIL`), echoed to the console; host gate is
boot-test phase 8 (§8). Unprivileged commands run via the established
session pattern:
`runuser -u punar -- env XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/punar <cmd>`
(the punar logind session exists from greetd autologin, so
`/run/user/1000` is live; rootless podman needs no user dbus — it falls
back to cgroupfs, and assertion 1 records the config actually in effect).
Env commands take the project directory via `punar-env`'s own
`-C <path>` flag inside a single **fixed-argv** `runuser -u punar -- env
XDG_RUNTIME_DIR=… HOME=… punar-env -C …` invocation — no wrapper script,
no `cd`, and no shell string ever crosses the runuser boundary.

Assertion groups:

1. **Rootless preflight**: `podman info --format json` as punar —
   `.host.security.rootless == true`; subuid mapping for punar covers
   `100000:65536` (reads `/etc/subuid` too); records storage driver and
   cgroup manager into `m6-podman-info.json` for the export.
2. **Fixture copy**: `/usr/share/punar/fixtures/projects/atlas/` →
   `/home/punar/atlas/`, chown punar; the copied
   `project-environment.yaml` is byte-identical to the staged one
   (`cmp`).
3. **`init` idempotence**: `punar-env init` in `~punar/atlas` → exit 0,
   output contains `already initialized`, manifest **byte-identical**
   after (sha256 before/after). Scaffold path: `init` in a fresh empty
   `~punar/m6-scratch` → creates `punar-env.yaml`; `punar-env status`
   there parses it (proves the scaffold is valid by the binary's own
   strict parser); dir removed after.
4. **`up`**: preloaded archive exists at
   `/usr/share/punar/oci/punar-env-base.tar` (mode 0644); `up` in
   `~punar/atlas` → exit 0; `podman image exists
   localhost/punar-env-base:m6` (the load happened); container
   `punar-env-atlas` running with both `dev.punar.*` labels; `podman
   inspect` shows network mode none and the `/workspace` bind from
   `/home/punar/atlas`. Second `up` → exit 0, `already up` (idempotence).
5. **`shell` passthrough + workspace writable**:
   `shell -c 'cat /etc/punar-env-base-release'` → exit 0, output matches
   the staged marker (§6.2 — proof the staged archive is what runs);
   `shell -c 'exit 42'` → **exit 42**; `shell -c 'touch
   /workspace/.m6-write'` → exit 0 and `/home/punar/atlas/.m6-write`
   exists on the host **owned by punar** (rootless uid-mapping proof).
6. **`status`**: rendered output (captured to `m6-status.txt` for export)
   contains: project `ATLAS`/`atlas`, state `running`, `node` + `24`,
   `rust` + `stable`, `postgres` + `not started in M6`, and the
   permissions rows with the fixture's values **verbatim** (`read_write`,
   `internet` `allow`, `corp_dev` `allow`, `corp_prod` `deny`, `github`
   `allow`, `aws_dev` `request`, `aws_prod` `deny`) each alongside a
   `declared` label; no `Organization` row. `status --json` parses with
   `jq` and the enforcement object is present.
7. **`agent` stub honesty**: `punar-env agent claude-code` → exit 1,
   stderr cites Milestone 7; `agent not-in-manifest` → also nonzero with
   the not-declared error (proves the list check is real).
8. **`destroy`**: exit 0; `podman ps -a` shows no `punar-env-atlas`;
   `~punar/atlas/project-environment.yaml` byte-identical to the staged
   fixture and `.m6-write` still present (project files intact). Second
   `destroy` → exit 0, `nothing to destroy`.
9. **Verdict**: write the final `PUNAR_M6_OK`/`PUNAR_M6_FAIL` line.
   No screenshots — this is a CLI milestone; the exported `m6-status.txt`
   is the human evidence.

Exports (all under `/run/punar`, swept by the existing tar):
`m6-report.txt`, `m6-status.txt`, `m6-status.json`,
`m6-podman-info.json`, `m6-podman-ps.txt` (before/after-destroy ps
evidence, uploaded by CI alongside the report), plus per-step `m6-*.txt`
command captures (init/up/shell/agent/destroy outputs) as diagnostics.

## 11. Workspace/shell tie-in — none in M6 (decision)

The M2 named workspace "Atlas" (`crates/punar-workspace`,
`~/.local/state/punar/workspaces.json`) and the M6 environment
`punar-env-atlas` are **conceptually the same project** (spec 14 + 17) but
share **no code or state in M6** — deliberately. The join arrives in M7:
`punar-env agent <name>` launches a managed session attributed to the
project identity (spec 19.2 `project` field, section 27), which is when a
shared project-identity notion must be promoted (likely into
`punar-common`, §4.3). Wiring shell/workspace UI to environment state
before there is an agent to show would be speculative surface. Scope
stays tight; this section is the documented link.

## 12. Schema deltas — none (again)

`schemas/project/project-environment.json` already models section 17
field-for-field (it was written for this milestone); the Atlas fixture
already validates against it; `punar-env`'s structs conform to the schema
rather than the reverse. The scaffold template lands as an additional
`schemas/project/examples/` file (validator-covered, §4.4). No shared-def
changes, no version bump.

## 13. Deferred, tracked

- **Toolchain provisioning** (§5.5) — needs the product network story;
  target: post-M11/M12, real devcontainer image pull/build.
- **Service containers** (§5.6) — postgres et al. declared-only; revisit
  with the first consumer (post-M7).
- **Network/credential/agent enforcement** — M12 / M9 / M7 respectively;
  labels baked into status (§7).
- **`devcontainer.json` interop** (spec 16 "devcontainers") — the
  manifest's `environment.type: devcontainer` names the model; reading
  actual `devcontainer.json` files is deferred to the provisioning
  milestone above.
- **Struct promotion to `punar-common`** when M7 needs the manifest types
  (§4.3, §11).
- **`punar-env` in the RSS gate** — only if punar-env ever grows a
  resident component (nothing planned; noted so absence is not
  oversight).

## 14. Verification status (spec 1.22)

This document began as the M6 design plan; the implementation has now
landed and the plan text above has been reconciled to the as-built
reality where they diverged (unknown-field warn-not-fail §4.3; fixture
staged at `fixtures/projects/atlas/` §8/§10; `-C` flag instead of a cd
wrapper §10; idle-ram timeout 110 min §8).

Verified at implementation time (each by the agent that owned the piece):

- **Crate** (`crates/punar-env`): `cargo fmt --check`, `cargo clippy
  --workspace --all-targets -D warnings`, `cargo test --workspace` all
  green in the pinned `rust:1` container — including the table-driven
  argv tests, the Atlas byte-verbatim round-trip, init idempotence,
  the §7 target-render snapshot, and engine flows on a scripted podman
  mock; live non-root smoke against a fake podman confirmed the exact
  render, `--json`, and every exit-code path. `serde_norway` advisory
  review: no RUSTSEC entries (fallback documented in the workspace
  Cargo.toml).
- **Offline base image**: `stage_env_base_oci` executed for real inside
  the pinned builder — byte-identical across rebuilds (1,320,960 bytes,
  well under the 16 MiB tripwire), the pinned podman loads it as
  `localhost/punar-env-base:m6` with digests matching the staged note,
  and the extracted rootfs executes under chroot (exit-42 passthrough
  proven). `podman run` itself cannot be exercised under the arm64-Mac
  emulation path (crun memfd re-exec fails under Rosetta — host-env
  limit); the in-VM m6-check is the authoritative podman-run proof.
- **Image wiring + m6-check** (this change): `shellcheck` v0.11.0 clean
  on every touched script including the new `m6-check.sh`; `actionlint`
  clean on ci.yml; `PUNAR_BUILD_MODE=summary ./tools/build-image.sh all`
  exit 0 for both images; `./tools/validate-schemas.sh` green; cargo
  workspace gates re-run green.

**Not yet claimed** (honesty, spec 1.22): the full CI image build with
the staged `punar-env` binary and base archive, and the in-VM boot-test
with phase 8 green — that proof only exists once the M6 tree is
committed, pushed, and run on the x86_64 runners. The M4+M5 CI that was
still in flight when M6 landed has since resolved (status audit,
2026-08-25): after run 32846674987 went red on exactly one case-sensitive
verdict grep in m5-check, run 32849448721 (commit 408b51d — the current
HEAD, which contains nothing M6) is fully green with `PUNAR_M4_OK` and
`PUNAR_M5_OK`, so the base M6 will land on is green; the working tree on
top of it is the M6 tree (plus status-doc updates), none of it CI-run. The
schemas-side scaffold copy in `schemas/project/examples/` (§4.4) ships
separately with the schemas-owning change; until it lands, the crate's
own unit test that the embedded scaffold parses cleanly is the guard.
