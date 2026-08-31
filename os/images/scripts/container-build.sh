#!/usr/bin/env bash
# Runs INSIDE the punar image-builder container (see builder/Containerfile),
# invoked by tools/build-image.sh with the REPO ROOT mounted (the desktop
# profile stages files from os/modules and shell/, so os/images alone is not
# enough). Not intended to run on a host directly, though it only assumes:
# bash, mkosi, qemu-img, sha256sum, base64, and the repo layout.
#
# Images (milestone-1.md §3):
#   punar-dev      — minimal M0 image (mkosi profile "dev"; PUNAR_BOOT_OK).
#   punar-desktop  — graphical development workstation (profiles
#                    "desktop,dev";
#                    --profile/--image-id/--hostname passed on the CLI so no
#                    profile scalar-merge ambiguity).
#   punar-release  — production-safe graphical workstation (profile
#                    "desktop" only; hostname and first user are onboarding
#                    outputs, never baked into the image).
#
# Env knobs:
#   PUNAR_IMAGES     dev | desktop | release | iso | all   (default: all; `all`
#                    means the historical CI pair, not release)
#   PUNAR_BUILD_MODE build | summary | stage (default: build; summary runs
#                    staging + `mkosi summary`; stage refreshes only the
#                    architecture-neutral desktop tree for the native ARM
#                    adapter — neither mode builds an image)
set -euo pipefail

IMAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
cd "${IMAGES_DIR}"

# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

MIRROR="https://archive.archlinux.org/repos/${PUNAR_SNAPSHOT_DATE}"
IMAGES="${PUNAR_IMAGES:-all}"
MODE="${PUNAR_BUILD_MODE:-build}"

case "${IMAGES}" in
    dev|desktop|release|iso|all) ;;
    *) echo "error: PUNAR_IMAGES must be dev, desktop, release, iso, or all (got: ${IMAGES})" >&2; exit 2 ;;
esac
case "${MODE}" in
    build|summary) ;;
    stage)
        [ "${IMAGES}" = "desktop" ] \
            || { echo "error: stage mode requires PUNAR_IMAGES=desktop" >&2; exit 2; }
        ;;
    *) echo "error: PUNAR_BUILD_MODE must be build, summary, or stage (got: ${MODE})" >&2; exit 2 ;;
esac

MKOSI_REPART_DIR="$(mktemp -d /run/punar-mkosi-repart.XXXXXX)"
MKOSI_RAW_OUTPUT_DIR="$(mktemp -d /var/tmp/punar-mkosi-output-x86_64.XXXXXX)"
# Generated output roots are gitignored and therefore absent in a clean
# checkout. Create the host-mounted destination before the first conversion.
install -d "${IMAGES_DIR}/out"
# UUIDv5(URL, https://punar.org/filesystem-device/PUNAR-DATA). mkfs.btrfs
# otherwise randomizes its single-device UUID even when repart supplies a
# stable filesystem UUID. This stabilizes that identity only; btrfs still
# generates per-subvolume UUIDs, so it is not a bit-reproducibility claim.
# The value is a direct-image input, not a production-install rule.
BTRFS_DEVICE_UUID="ef4a2286-ac11-53c0-a40d-8d2bae7511cc"
cleanup_build() {
    rm -rf "${MKOSI_REPART_DIR}"

    # Keep sparse raw disks on Docker's native Linux filesystem. Streaming a
    # compressed qcow2 to the host avoids a full-size VirtioFS copy and also
    # keeps rootfs assembly on a filesystem with working POSIX ACLs.
    local raw
    for raw in "${MKOSI_RAW_OUTPUT_DIR}"/*.raw; do
        [ -f "${raw}" ] || continue
        truncate --size 0 -- "${raw}" || true
        rm -f -- "${raw}"
    done
    rm -rf "${MKOSI_RAW_OUTPUT_DIR}"

    # Docker Desktop's VirtioFS process may retain a read descriptor after a
    # generated raw image is unlinked. Zero the disposable intermediate first
    # so those open descriptors cannot pin tens of gigabytes on the host.
    for raw in "${IMAGES_DIR}/out"/punar-*.raw; do
        [ -f "${raw}" ] || continue
        truncate --size 0 -- "${raw}" || true
        rm -f -- "${raw}"
    done
}
trap cleanup_build EXIT
"${REPO_ROOT}/tools/render-mkosi-repart.sh" \
    "${MKOSI_REPART_DIR}" "${IMAGES_DIR}/repart.d/install"

# Copy the desktop configuration/assets from their source-of-truth trees
# into the desktop profile's mkosi.extra. These staged paths are gitignored
# (os/images/.gitignore) — os/modules/desktop and shell/ stay the single
# source of truth; this staging is re-done fresh on every build.
stage_desktop_extra() {
    local mod="${REPO_ROOT}/os/modules/desktop"
    local shell_src="${REPO_ROOT}/shell/punar-shell"
    local tokens="${REPO_ROOT}/shell/theme/punar-tokens.json"
    local themes="${REPO_ROOT}/shell/theme/themes"
    local repart_src="${IMAGES_DIR}/repart.d"
    local extra="${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local dev_extra="${IMAGES_DIR}/mkosi.profiles/dev/mkosi.extra"

    echo "==> Verifying vendored font manifest"
    (cd "${mod}/fonts" && sha256sum --quiet -c MANIFEST.sha256)

    echo "==> Staging desktop configs/assets into ${extra}"
    # Only the STAGED subtrees are wiped: usr/share/punar/nftables (the
    # vendored punar-base.nft, M3) is versioned and must survive staging.
    rm -f "${extra}/etc/chromium-flags.conf"
    rm -rf "${extra}/etc/xdg" "${extra}/etc/fonts" \
           "${extra}/usr/share/fonts" "${extra}/usr/share/punar/shell" \
           "${extra}/usr/share/punar/theme" \
           "${extra}/usr/share/punar/network" \
           "${extra}/usr/share/punar/repart.d" \
           "${extra}/usr/share/punar/fixtures" \
           "${dev_extra}/usr/share/punar/fixtures"
    mkdir -p "${extra}/etc/xdg/hypr" "${extra}/etc/xdg/foot" \
             "${extra}/etc/fonts/conf.d" "${extra}/usr/share/fonts/punar" \
             "${extra}/usr/share/punar/shell" "${extra}/usr/share/punar/theme" \
             "${extra}/usr/share/punar/theme/themes" \
             "${extra}/usr/share/punar/network/zones" \
             "${extra}/usr/share/punar/repart.d/install" \
             "${extra}/usr/share/punar/repart.d/install-raspberry-pi" \
             "${extra}/usr/share/punar/repart.d/install-encrypted" \
             "${extra}/usr/share/punar/repart.d/install-streaming" \
             "${dev_extra}/usr/share/punar/fixtures/acme" \
             "${dev_extra}/usr/share/punar/fixtures/projects/atlas"

    # Hyprland config. Lua is the supported provider from 0.55 onward; 0.56
    # warns on every legacy .conf session and 0.57 removes that parser.
    cp "${mod}"/hypr/*.lua "${extra}/etc/xdg/hypr/"
    # Product hook: deliberately empty. The dev profile overlays this exact
    # file with the desktop-ready CI marker; a release session starts no test
    # process merely because Hyprland launched.
    : > "${extra}/etc/xdg/hypr/punar-session-profile.lua"
    # Session helpers: source of truth lives beside the Hyprland config.
    # All are staged (gitignored) into the otherwise-versioned
    # usr/lib/punar directory.
    rm -f "${extra}/usr/lib/punar/punar-layout.sh" \
          "${extra}/usr/lib/punar/punar-scratchpad.sh" \
          "${extra}/usr/lib/punar/punar-terminal-app.sh" \
          "${extra}/usr/lib/punar/punar-graphics-env.sh"
    install -m 0755 "${mod}/hypr/punar-layout.sh" \
        "${extra}/usr/lib/punar/punar-layout.sh"
    install -m 0755 "${mod}/hypr/punar-scratchpad.sh" \
        "${extra}/usr/lib/punar/punar-scratchpad.sh"
    install -m 0755 "${mod}/hypr/punar-terminal-app.sh" \
        "${extra}/usr/lib/punar/punar-terminal-app.sh"
    install -m 0755 "${mod}/hypr/punar-graphics-env.sh" \
        "${extra}/usr/lib/punar/punar-graphics-env.sh"
    # foot system-wide config (first-found-wins; overwrites the packaged
    # commented example at the same path — intended, see module README).
    cp "${mod}/foot/foot.ini" "${extra}/etc/xdg/foot/foot.ini"
    # Chromium launch defaults + the system default-handler map.
    # /etc/chromium-flags.conf is ADDITIVE with the user's own file (both are
    # read, in order) — the opposite of foot.ini's first-found-wins rule, so
    # this is a floor and not a cage. /etc/xdg/mimeapps.list is what makes
    # xdg-open answer an http(s) URL at all; a user's ~/.config/mimeapps.list
    # outranks it. Neither is enterprise policy: writing
    # /etc/chromium/policies/managed/ would brand an UNENROLLED device
    # "Managed by your organization" (DESIGN_LANGUAGE.md section 8).
    cp "${mod}/chromium/chromium-flags.conf" "${extra}/etc/chromium-flags.conf"
    cp "${mod}/chromium/mimeapps.list" "${extra}/etc/xdg/mimeapps.list"
    # fontconfig defaults (sorts before 60-latin so preferences win).
    cp "${mod}/fonts/50-punar-fonts.conf" "${extra}/etc/fonts/conf.d/"
    # Vendored fonts, OFL.txt alongside each family (license requirement).
    cp -R "${mod}/fonts/instrument-sans" "${mod}/fonts/geist-mono" \
          "${extra}/usr/share/fonts/punar/"
    # punar-shell QML + design tokens (paths baked into Theme.qml and the
    # Hyprland exec-once: qs -p /usr/share/punar/shell).
    cp -R "${shell_src}/." "${extra}/usr/share/punar/shell/"
    rm -f "${extra}/usr/share/punar/shell/README.md"
    cp "${tokens}" "${extra}/usr/share/punar/theme/punar-tokens.json"
    # Theme documents + the shipped pointer (docs/design/theme-system.md
    # §3.2/§3.4). Theme.qml's resolution order is
    #   ~/.config/punar/themes -> /etc/punar/themes ->
    #   /usr/share/punar/theme/themes -> the repo dev dir
    # so THIS is the path the image serves, and the pointer it falls back
    # to is themes/default.json. Without this copy the shell resolves none
    # of them and silently renders the built-in paper palette with no theme
    # selectable — a surface that exists in the tree and not on the
    # machine. Same staged-not-committed-twice rule as the QML beside it:
    # shell/theme/themes stays the single source of truth (the contrast
    # gate in Theme/ThemeContrast.qml runs against these exact bytes).
    cp -R "${themes}/." "${extra}/usr/share/punar/theme/themes/"
    # The internal installer executor accepts no caller-provided layout.
    # Stage the immutable definition layers it merges: the UEFI and native
    # Raspberry Pi A/B layouts, the LUKS2 data overlay and root-A streaming
    # overlay.
    # The eventual live profile inherits this same desktop tree, preventing a
    # second hand-maintained installer layout from drifting from image builds.
    install -m 0644 "${repart_src}/install/"*.conf \
        "${extra}/usr/share/punar/repart.d/install/"
    install -m 0644 "${repart_src}/install-raspberry-pi/"*.conf \
        "${extra}/usr/share/punar/repart.d/install-raspberry-pi/"
    install -m 0644 "${repart_src}/install-encrypted/"*.conf \
        "${extra}/usr/share/punar/repart.d/install-encrypted/"
    install -m 0644 "${repart_src}/install-streaming/"*.conf \
        "${extra}/usr/share/punar/repart.d/install-streaming/"
    # M5: Acme organization fixtures for the dev/CI mock control plane
    # (milestone-5.md §4.4) — served VERBATIM by punar-mock-smplify from
    # /usr/share/punar/fixtures/acme. Same staged-not-committed-twice
    # pattern as the shell QML: fixtures/organizations/acme stays the single
    # source of truth (host cargo tests and ./tools/validate-schemas.sh run
    # against the same bytes the image ships). Only the three JSON files the
    # mock reads (org.json + policy-source + desired-state); the referenced
    # ai_policy_file lives outside the fixture dir and is deliberately not
    # served until AI capabilities land (M7+).
    cp "${REPO_ROOT}/fixtures/organizations/acme/"*.json \
       "${dev_extra}/usr/share/punar/fixtures/acme/"
    # M6: Atlas project fixture for the in-VM developer-environment
    # exercise (milestone-6.md §8) — m6-check copies it from
    # /usr/share/punar/fixtures/projects/atlas to ~punar/atlas and asserts
    # byte-identity through the whole init/up/destroy journey. Same
    # staged-not-committed-twice pattern: fixtures/projects/atlas stays
    # the single source of truth (host cargo tests parse the same bytes,
    # ./tools/validate-schemas.sh validates them). Only the two contract
    # files (the spec-17-verbatim manifest + the section 36 network policy
    # declaration); the README is repo documentation, not fixture data.
    cp "${REPO_ROOT}/fixtures/projects/atlas/project-environment.yaml" \
       "${REPO_ROOT}/fixtures/projects/atlas/project-network-policy.json" \
       "${dev_extra}/usr/share/punar/fixtures/projects/atlas/"
    # M8: the comm -> process-class table for the AI Access Ledger
    # (milestone-8.md §3.2). Staged, never committed twice, for a reason
    # stronger than tidiness: punar-agentd compiles THIS FILE in with
    # include_str! as its fallback, so shipping a second hand-maintained
    # copy under mkosi.extra would create exactly the drift the compiled-in
    # fallback exists to prevent. crates/punar-agentd/data stays the single
    # source of truth; the adapters and signatures beside it in
    # usr/share/punar/agents are versioned data with no compiled twin and
    # are deliberately NOT touched here.
    rm -f "${extra}/usr/share/punar/agents/process-classes.json"
    install -m 0644 "${REPO_ROOT}/crates/punar-agentd/data/process-classes.json" \
        "${extra}/usr/share/punar/agents/process-classes.json"

    # On-demand application catalog. Only identities, pins, disclosures and
    # the remote signing key ship here — no application or runtime payload is
    # preinstalled, so Spotify support does not tax boot, RAM or the base
    # image. Runtime permissions are re-derived from the pinned Flatpak
    # metadata by punard before every install.
    rm -rf "${extra}/usr/share/punar/catalog"
    install -d "${extra}/usr/share/punar/catalog/remotes" \
        "${extra}/usr/share/punar/catalog/icons"
    install -m 0644 "${REPO_ROOT}/catalog/catalog.json" \
        "${extra}/usr/share/punar/catalog/catalog.json"
    install -m 0644 "${REPO_ROOT}/catalog/remotes/flathub.flatpakrepo" \
        "${extra}/usr/share/punar/catalog/remotes/flathub.flatpakrepo"
    install -m 0644 "${REPO_ROOT}"/catalog/icons/*.svg \
        "${extra}/usr/share/punar/catalog/icons/"
    install -m 0644 "${REPO_ROOT}"/catalog/icons/*.png \
        "${extra}/usr/share/punar/catalog/icons/"

    # M12 network policy data. Zone definitions are product vocabulary;
    # membership is site data and deliberately starts empty. A missing CIDR
    # for a blocked zone makes punar-netd fall back to deny-all for the
    # affected managed session rather than pretending a name is enforceable.
    install -m 0644 "${REPO_ROOT}"/crates/punar-netd/data/zones/*.json \
        "${extra}/usr/share/punar/network/zones/"
    install -m 0644 "${REPO_ROOT}/crates/punar-netd/data/zone-members.json" \
        "${extra}/usr/share/punar/network/zone-members.json"

    # M9: the two data files the approval gate and the credential broker
    # read at runtime (milestone-9.md §5.2, §6.1). Staged for exactly the
    # M8 process-classes.json reason — both are ALSO compiled in with
    # include_str! as the daemons' fallbacks, so a second hand-maintained
    # copy under mkosi.extra would create the drift the compiled-in
    # fallback exists to prevent.
    #
    #   ai-defaults.yaml  the SHIPPED section 20 AI authority document
    #                     (fixtures/policies/ai-policy-personal-defaults.yaml
    #                     is the single source of truth; it is already
    #                     schema-validated by the fixtures/policies/
    #                     ai-policy-*.yaml glob in tools/validate_schemas.py,
    #                     which is why staging it needs no manifest entry).
    #                     punar-secrets REFUSES TO START without this file —
    #                     starting would mean silently answering every
    #                     credential from a fail-closed default.
    #   classes.yaml      the credential class catalog. The classes are DATA:
    #                     a class not listed here does not exist, and the
    #                     broker refuses to start on a malformed catalog.
    rm -rf "${extra}/usr/share/punar/policy" "${extra}/usr/share/punar/secrets"
    install -d "${extra}/usr/share/punar/policy" "${extra}/usr/share/punar/secrets"
    install -m 0644 \
        "${REPO_ROOT}/fixtures/policies/ai-policy-personal-defaults.yaml" \
        "${extra}/usr/share/punar/policy/ai-defaults.yaml"
    install -m 0644 "${REPO_ROOT}/crates/punar-secrets/share/classes.yaml" \
        "${extra}/usr/share/punar/secrets/classes.yaml"
}

# Compile punard + punarctl from the workspace with the snapshot's own Rust
# toolchain and stage them into the desktop profile's extra tree
# (milestone-3.md §7, hermetic in-container build — decision (a)). Called
# only when MODE=build and the desktop image is selected: `mkosi summary`
# needs no extra-tree contents, so the cheap validation path never compiles.
#
# Honest hermeticity limit: crates.io is fetched HERE at image-build time —
# the one build input not served from the Arch snapshot. It is pinned by the
# committed Cargo.lock (--locked refuses drift) and checksummed by cargo;
# CARGO_HOME + the target dir live under os/images/cache (gitignored), riding
# the same CI cache as the pacman packages, so warm builds fetch ~nothing.
# The RUNTIME image needs no network: the binaries are dynamically linked
# against the snapshot glibc installed by mkosi (hard CI constraint:
# the test VM runs -nic none).
stage_punar_binaries() {
    local extra="${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local dev_extra="${IMAGES_DIR}/mkosi.profiles/dev/mkosi.extra"
    local cargo_target="${IMAGES_DIR}/cache/cargo-target"

    # punar-mock-smplify is the M5 dev/CI mock control plane (milestone-5.md
    # §4) — built and staged alongside the product binaries because the CI VM
    # has no network and the M5 exercise needs an in-VM counterparty. It is a
    # test harness, not a product component: its unit is never enabled and
    # only m5-check.sh starts/stops it.
    # punar-env is the M6 developer-environment manager (milestone-6.md §3)
    # — a user CLI, staged like punarctl; it drives the podman already in
    # the image and needs no unit of its own.
    # punar-agentd is the M7 AI agent registry service (milestone-7.md §3,
    # SPEC section 11.3) — a real always-on daemon like punard, enabled by
    # the vendor-level wants symlink shipped in the extra tree; its socket
    # and state directories come from tmpfiles.d/punar-agentd.conf.
    # punar-secrets is the M9 credential broker (milestone-9.md §3.1, SPEC
    # section 11.4) — the third always-on daemon, same vendor-wants pattern,
    # socket directory from tmpfiles.d/punar-secrets.conf and NO state
    # directory at all (that absence is the milestone's central promise).
    # It is counted honestly in the services-RSS gate: idle-ram.sh sums all
    # punar-netd is M12's fourth least-privilege daemon. It owns only the
    # punar-net nftables table and the bounded on-demand network view.
    # idle-ram.sh counts all four service cgroups in the one services budget.
    echo "==> Building Punar product services, onboarding and CLIs + dev mock (release, --locked; $(rustc --version))"
    (
        cd "${REPO_ROOT}" &&
            CARGO_HOME="${IMAGES_DIR}/cache/cargo" \
                CARGO_TARGET_DIR="${cargo_target}" \
                cargo build --release --locked \
                    -p punard -p punarctl -p punar-env -p punar-agentd \
                    -p punar-secrets -p punar-netd -p punar-onboard \
                    -p punar-mock-smplify
    )

    echo "==> Staging product binaries into ${extra}/usr/bin and the mock into ${dev_extra}/usr/bin"
    install -d "${extra}/usr/bin"
    install -m 0755 \
        "${cargo_target}/release/punard" \
        "${cargo_target}/release/punarctl" \
        "${cargo_target}/release/punar-env" \
        "${cargo_target}/release/punar-agentd" \
        "${cargo_target}/release/punar-secrets" \
        "${cargo_target}/release/punar-netd" \
        "${cargo_target}/release/punar-onboard" \
        "${cargo_target}/release/punar-onboardd" \
        "${cargo_target}/release/punar-greet" \
        "${extra}/usr/bin/"
    install -d "${dev_extra}/usr/bin"
    install -m 0755 "${cargo_target}/release/punar-mock-smplify" \
        "${dev_extra}/usr/bin/"

    "${REPO_ROOT}/tests/images/check-staged-service-executables.sh" \
        "${extra}" "${dev_extra}" "${extra}" "${dev_extra}" \
        'Advanced Micro Devices X86-64'
}

stage_installer_build_tool() {
    local cargo_target="${IMAGES_DIR}/cache/cargo-target"
    echo "==> Building the detached-release signing/verifier tool for installer assembly"
    (
        cd "${REPO_ROOT}" &&
            CARGO_HOME="${IMAGES_DIR}/cache/cargo" \
                CARGO_TARGET_DIR="${cargo_target}" \
                cargo build --release --locked \
                    -p punar-common --bin punar-release-tool
    )
    [ -x "${cargo_target}/release/punar-release-tool" ]
}

reset_staged_binaries() {
    # Generated and gitignored. Clear them before the minimal build so an old
    # desktop build can never leak product/mock binaries into punar-dev.
    rm -rf "${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra/usr/bin" \
           "${IMAGES_DIR}/mkosi.profiles/dev/mkosi.extra/usr/bin"
}

# M6 offline container base image (milestone-6.md §6): `punar-env up` needs
# an OCI image, but the CI VM has no network (-nic none), so the image is
# built HERE — where the pinned snapshot is reachable — and staged into the
# desktop extra tree for `podman load -i` at first use. Hand-assembled
# deterministically, no docker/podman nesting (fragile under the arm64-Mac
# emulation path, non-deterministic metadata): an uncompressed sorted
# fixed-mtime layer tar from the snapshot's statically linked busybox,
# sha256-addressed blobs, config/manifest/index emitted with fixed key
# order, re-tarred with the same flags into an oci-archive. Everything is
# clamped to the snapshot date (gzip is avoided entirely — it embeds
# timestamps), so the archive is byte-identical across rebuilds of the same
# snapshot pin; the build logs its sha256 for exactly that comparison.
# Called in build mode only, like stage_punar_binaries: `mkosi summary`
# needs no extra-tree contents.
stage_env_base_oci() {
    local extra="${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local cache_dir="${IMAGES_DIR}/cache/punar-env-base"

    # busybox pin, from the SAME ALA snapshot every other build input comes
    # from — exactly one upstream provenance (milestone-6.md §6.3 rejects
    # docker.io/alpine/skopeo alternatives). Filename + sha256 verified
    # against the snapshot's PGP-signed extra.db (busybox 1.36.1-4, extra
    # repo, recorded 2026-08-25); the sha256 is re-checked on every build,
    # on cache hit and after download alike. Fetched with curl (a hard
    # runtime dependency of the builder's pacman) rather than `pacman -Sw`
    # so the pin lives here in one greppable place. Updating
    # PUNAR_SNAPSHOT_DATE means re-verifying this pair against the new
    # snapshot's extra.db (see image-pipeline.md, "Updating the snapshot
    # pin").
    local pkg="busybox-1.36.1-4-x86_64.pkg.tar.zst"
    local pkg_sha256="14b14151bbc901c6e0c7cbb21fa73db2540df91cdea2a0ff1caf20be2cd8c333"
    local pkg_url="${MIRROR}/extra/os/x86_64/${pkg}"
    local ref="localhost/punar-env-base:m6"
    # Size tripwire (milestone-6.md §6.4): far below the ~80 MB milestone
    # allowance, so accidental fat (a future glibc contingency, a stray
    # layer) fails the build, not the review.
    local max_bytes=$((16 * 1024 * 1024))

    # The single clamped timestamp: snapshot date, midnight UTC — used for
    # every tar member and the image config's `created`.
    local snap_iso="${PUNAR_SNAPSHOT_DATE//\//-}"
    local snap_epoch
    snap_epoch="$(date -u -d "${snap_iso} 00:00:00 UTC" +%s)"

    echo "==> Building punar-env-base OCI archive (${pkg}, ref ${ref})"

    # 1. Fetch the pinned package. The download rides os/images/cache (the
    #    same CI cache entry as the pacman/cargo caches, keyed on
    #    snapshot.env); scratch work lives in an ephemeral tmpdir so archive
    #    churn never bloats that cache.
    mkdir -p "${cache_dir}"
    if ! echo "${pkg_sha256}  ${cache_dir}/${pkg}" | sha256sum --quiet -c - \
        >/dev/null 2>&1; then
        echo "==> Fetching ${pkg_url}"
        curl -fsSL --retry 3 -o "${cache_dir}/${pkg}" "${pkg_url}"
    fi
    echo "${pkg_sha256}  ${cache_dir}/${pkg}" | sha256sum --quiet -c -

    local work
    work="$(mktemp -d /tmp/punar-env-base.XXXXXX)"

    # 2. Assemble the rootfs: /bin/busybox plus symlinks for the applets the
    #    M6 contract needs, /workspace and /tmp mountpoints, and the release
    #    marker m6-check reads back from INSIDE the running container —
    #    proof the staged archive is what ran.
    mkdir -p "${work}/rootfs/bin" "${work}/rootfs/etc" \
             "${work}/rootfs/workspace" "${work}/rootfs/tmp"
    tar --zstd -xf "${cache_dir}/${pkg}" -C "${work}" usr/bin/busybox
    install -m 0755 "${work}/usr/bin/busybox" "${work}/rootfs/bin/busybox"
    local applet
    for applet in sh sleep cat echo ls touch env id uname; do
        ln -s busybox "${work}/rootfs/bin/${applet}"
    done
    printf 'punar-env-base m6 %s\n' "${PUNAR_SNAPSHOT_DATE}" \
        > "${work}/rootfs/etc/punar-env-base-release"

    # Static-linkage assertion (milestone-6.md §6.2): Arch's busybox is a
    # statically linked musl rescue binary, which is why the rootfs needs no
    # libc. If a future snapshot ever links it dynamically, the documented
    # contingency is adding the snapshot glibc (~+40 MB, still under the
    # milestone allowance) — fail HERE at build time, not in the offline VM.
    local ldd_out
    ldd_out="$(ldd "${work}/rootfs/bin/busybox" 2>&1 || true)"
    if ! grep -q "not a dynamic executable" <<< "${ldd_out}"; then
        echo "error: snapshot busybox is not statically linked (ldd: ${ldd_out})" >&2
        echo "error: see milestone-6.md §6.2 for the glibc contingency" >&2
        exit 1
    fi

    # Normalize modes so the archive never depends on the builder's umask.
    chmod 0755 "${work}/rootfs" "${work}/rootfs/bin" "${work}/rootfs/etc" \
               "${work}/rootfs/workspace"
    chmod 1777 "${work}/rootfs/tmp"
    chmod 0644 "${work}/rootfs/etc/punar-env-base-release"

    # 3. Deterministic tar flags, used for the layer AND the outer archive.
    #    posix format for the pax-options; exthdr.name is pinned because GNU
    #    tar's default extended-header name embeds the process PID.
    local tar_flags=(
        --format=posix
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime"
        --sort=name
        --numeric-owner --owner=0 --group=0
        --mtime="@${snap_epoch}"
    )

    tar "${tar_flags[@]}" -C "${work}/rootfs" -cf "${work}/layer.tar" .
    local layer_sha layer_size
    layer_sha="$(sha256sum "${work}/layer.tar" | cut -d' ' -f1)"
    layer_size="$(stat -c %s "${work}/layer.tar")"

    # 4. OCI image layout, by hand: uncompressed layer (diff_id == blob
    #    digest), config with fixed `created`, manifest, index carrying the
    #    ref.name annotation `podman load` tags from, oci-layout marker.
    #    JSON via printf with fixed key order — byte-stable by construction.
    local created="${snap_iso}T00:00:00Z"
    printf '{"created":"%s","architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["/bin/sh"]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
        "${created}" "${layer_sha}" > "${work}/config.json"
    local config_sha config_size
    config_sha="$(sha256sum "${work}/config.json" | cut -d' ' -f1)"
    config_size="$(stat -c %s "${work}/config.json")"

    printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:%s","size":%s}]}' \
        "${config_sha}" "${config_size}" "${layer_sha}" "${layer_size}" \
        > "${work}/manifest.json"
    local manifest_sha manifest_size
    manifest_sha="$(sha256sum "${work}/manifest.json" | cut -d' ' -f1)"
    manifest_size="$(stat -c %s "${work}/manifest.json")"

    local layout="${work}/layout"
    mkdir -p "${layout}/blobs/sha256"
    cp "${work}/layer.tar" "${layout}/blobs/sha256/${layer_sha}"
    cp "${work}/config.json" "${layout}/blobs/sha256/${config_sha}"
    cp "${work}/manifest.json" "${layout}/blobs/sha256/${manifest_sha}"
    printf '{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:%s","size":%s,"annotations":{"org.opencontainers.image.ref.name":"%s"}}]}' \
        "${manifest_sha}" "${manifest_size}" "${ref}" > "${layout}/index.json"
    printf '{"imageLayoutVersion":"1.0.0"}' > "${layout}/oci-layout"
    chmod -R u=rwX,go=rX "${layout}"

    tar "${tar_flags[@]}" -C "${layout}" -cf "${work}/punar-env-base.tar" .

    local archive_sha archive_size
    archive_sha="$(sha256sum "${work}/punar-env-base.tar" | cut -d' ' -f1)"
    archive_size="$(stat -c %s "${work}/punar-env-base.tar")"
    if [ "${archive_size}" -gt "${max_bytes}" ]; then
        echo "error: punar-env-base.tar is ${archive_size} bytes (tripwire: ${max_bytes})" >&2
        echo "error: see milestone-6.md §6.4 before raising this limit" >&2
        exit 1
    fi
    echo "==> punar-env-base.tar: ${archive_size} bytes, sha256 ${archive_sha}"
    echo "    (deterministic for snapshot ${PUNAR_SNAPSHOT_DATE} — compare across rebuilds)"

    # 5. Stage, mode 0644 — the rootless user must read it for `podman load`
    #    (gitignored staging, like the shell QML and fixtures). The sidecar
    #    note records the digests for debugging and for comparing against
    #    `podman images --digests` in the VM; it is deterministic too (no
    #    build timestamp by design).
    rm -rf "${extra}/usr/share/punar/oci"
    install -d "${extra}/usr/share/punar/oci"
    install -m 0644 "${work}/punar-env-base.tar" \
        "${extra}/usr/share/punar/oci/punar-env-base.tar"
    {
        echo "ref: ${ref}"
        echo "snapshot: ${PUNAR_SNAPSHOT_DATE}"
        echo "archive-sha256: ${archive_sha}"
        echo "archive-bytes: ${archive_size}"
        echo "oci-manifest-digest: sha256:${manifest_sha}"
        echo "config-digest: sha256:${config_sha}"
        echo "layer-digest: sha256:${layer_sha} (uncompressed, so diff_id is identical)"
        echo "input: ${pkg} sha256:${pkg_sha256} (ALA ${PUNAR_SNAPSHOT_DATE}, extra repo)"
        echo "built-by: container-build.sh stage_env_base_oci (milestone-6.md §6)"
    } > "${work}/punar-env-base.note.txt"
    install -m 0644 "${work}/punar-env-base.note.txt" \
        "${extra}/usr/share/punar/oci/punar-env-base.note.txt"

    rm -rf "${work}"
}

# run_mkosi <image-id> [extra mkosi args...]
run_mkosi() {
    local image_id="$1"; shift
    echo "==> mkosi ${MODE} for ${image_id} (mirror: ${MIRROR})"
    # archive.archlinux.org rate-limits large pulls and pacman aborts on a
    # 10s low-speed window; downloads resume from CacheDirectory across
    # attempts, so a short retry loop makes throttling non-fatal.
    local attempt
    for attempt in 1 2 3; do
        if mkosi --force \
            --mirror "${MIRROR}" \
            --output-directory "${MKOSI_RAW_OUTPUT_DIR}" \
            --environment "SYSTEMD_REPART_MKFS_OPTIONS_BTRFS=--device-uuid=${BTRFS_DEVICE_UUID}" \
            --repart-directory "${MKOSI_REPART_DIR}" \
            "$@" "${MODE}"; then
            return 0
        fi
        echo "==> mkosi attempt ${attempt}/3 failed for ${image_id}" >&2
        [ "${attempt}" -lt 3 ] && sleep 25
    done
    echo "==> mkosi failed after 3 attempts for ${image_id}" >&2
    return 1
}

# convert_output <image-id>: raw -> compressed qcow2, delete the raw.
convert_output() {
    local image_id="$1"
    local qcow="out/${image_id}-x86_64.qcow2"
    local tmp_qcow="${qcow}.tmp"
    local raw="${MKOSI_RAW_OUTPUT_DIR}/${image_id}.raw"

    # mkosi names the disk output <ImageId>.raw; glob defensively in case a
    # future mkosi appends version/architecture suffixes.
    if [ ! -f "${raw}" ]; then
        shopt -s nullglob
        for candidate in "${MKOSI_RAW_OUTPUT_DIR}/${image_id}"*.raw; do
            raw="${candidate}"
            break
        done
        shopt -u nullglob
    fi
    if [ ! -f "${raw}" ]; then
        echo "error: no .raw output for ${image_id} found in ${MKOSI_RAW_OUTPUT_DIR}" >&2
        ls -la "${MKOSI_RAW_OUTPUT_DIR}" >&2 || true
        exit 1
    fi

    echo "==> Verifying A/B layout and shared-state mounts in ${raw}"
    "${REPO_ROOT}/tests/images/check-repart-layout.sh" "${raw}" x86_64

    echo "==> Converting ${raw} -> ${qcow} (compressed qcow2)"
    rm -f -- "${tmp_qcow}"
    qemu-img convert -O qcow2 -c "${raw}" "${tmp_qcow}"
    mv -f -- "${tmp_qcow}" "${qcow}"
    truncate --size 0 -- "${raw}"
    rm -f -- "${raw}" "${MKOSI_RAW_OUTPUT_DIR}/${image_id}"
}

BUILT=()
reset_staged_binaries

if [ "${IMAGES}" = "dev" ] || [ "${IMAGES}" = "all" ]; then
    run_mkosi punar-dev --profile dev
    if [ "${MODE}" = "build" ]; then
        convert_output punar-dev
        BUILT+=("punar-dev")
    fi
fi

if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "release" ] \
    || [ "${IMAGES}" = "iso" ] \
    || [ "${IMAGES}" = "all" ]; then
    stage_desktop_extra
    if [ "${MODE}" = "stage" ]; then
        echo "==> Architecture-neutral desktop staging complete"
        exit 0
    fi
    if [ "${MODE}" = "build" ]; then
        stage_punar_binaries
        stage_env_base_oci
        if [ "${IMAGES}" = "iso" ]; then
            stage_installer_build_tool
        fi
    fi
    if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "all" ]; then
        run_mkosi punar-desktop \
            --profile desktop,dev \
            --image-id punar-desktop \
            --hostname punar-desktop
        if [ "${MODE}" = "build" ]; then
            convert_output punar-desktop
            BUILT+=("punar-desktop")
        fi
    fi
fi

if [ "${IMAGES}" = "release" ] || [ "${IMAGES}" = "iso" ]; then
    run_mkosi punar-release \
        --profile desktop \
        --image-id punar-release
    # Summary mode must validate both trees used by the installer assembly,
    # not only the installed release tree.  Keep this outside the build-only
    # block so an invalid live kernel command line or initrd module list fails
    # the cheap preflight before native CI spends time building either disk.
    if [ "${IMAGES}" = "iso" ] && [ "${MODE}" = "summary" ]; then
        run_mkosi punar-installer-root \
            --profile desktop,installer \
            --image-id punar-installer-root
    fi
    if [ "${MODE}" = "build" ]; then
        if [ "${IMAGES}" = "iso" ]; then
            run_mkosi punar-installer-root \
                --profile desktop,installer \
                --image-id punar-installer-root
            installer_version="${PUNAR_INSTALLER_VERSION:?PUNAR_INSTALLER_VERSION is required for an ISO build}"
            installer_built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            installer_ci_run_id="${PUNAR_CI_RUN_ID:-local-${PUNAR_GIT_SHA:0:12}}"
            "${IMAGES_DIR}/scripts/assemble-installer-iso.sh" \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-release.raw" \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root.raw" \
                "${installer_version}" \
                "${IMAGES_DIR}/out/punar-installer-${installer_version}-x86_64.iso" \
                "${PUNAR_GIT_SHA}" "${installer_built_at}" "${installer_ci_run_id}"
            truncate --size 0 -- "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root.raw"
            rm -f -- "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root.raw" \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root"
            BUILT+=("punar-installer-${installer_version}-x86_64.iso")
        fi
        convert_output punar-release
        BUILT+=("punar-release")
    fi
fi

if [ "${MODE}" = "summary" ]; then
    echo "==> Summary mode complete (no image built)"
    exit 0
fi

echo "==> Writing build metadata"
{
    echo "images: ${BUILT[*]} (minimal Arch payload, mkosi; ADR-001)"
    echo "snapshot: ${PUNAR_SNAPSHOT_DATE} (Arch Linux Archive date snapshot)"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "note: unsigned development artifacts; release and installer trees include the pinned bare-hardware firmware and CPU/GPU support floor"
    echo "note: punar-desktop is the M1 graphical workstation (Hyprland + punar-shell) + M3 control plane (punard/punarctl, hermetic in-container build) + M5 enrollment exercise scaffolding (punar-mock-smplify dev/CI mock + staged Acme fixtures — never enabled, m5-check-only) + M6 developer environments (punar-env + preloaded punar-env-base OCI archive + staged Atlas project fixture) + M7 AI agent registry (punar-agentd daemon + vendored adapter/signature data + the punar-mock-agent and foo-agent dev/CI fixtures — the mock stands in for a real agent binary, which the offline VM cannot have) + M9 approval gates and the short-lived credential broker (punar-secrets daemon + the staged AI authority document and credential-class catalog — the provider is a MOCK and every surface says so; the CI VM has no network and no real credential authority exists)"
} > out/build-info.txt

# Bare filenames (no ./ prefix) — CI re-verifies with `sha256sum -c` against
# the artifact names.
(
    cd out
    shopt -s nullglob
    artifacts=(*.qcow2 *.iso)
    [ "${#artifacts[@]}" -gt 0 ]
    sha256sum -- "${artifacts[@]}" > SHA256SUMS
    shopt -u nullglob
)

echo "==> Build complete"
ls -lh out/
