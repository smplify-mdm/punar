#!/usr/bin/env bash
# Runs INSIDE the punar image-builder container (see builder/Containerfile),
# invoked by tools/build-image.sh with the REPO ROOT mounted (the desktop
# profile stages files from os/modules and shell/, so os/images alone is not
# enough). Not intended to run on a host directly, though it only assumes:
# bash, mkosi, qemu-img, sha256sum, base64, and the repo layout.
#
# Images (milestone-1.md §3):
#   punar-dev      — minimal M0 image, unchanged (PUNAR_BOOT_OK gate).
#   punar-desktop  — M1 graphical workstation (mkosi profile "desktop";
#                    --profile/--image-id/--hostname passed on the CLI so no
#                    profile scalar-merge ambiguity).
#
# Env knobs:
#   PUNAR_IMAGES     dev | desktop | all   (default: all)
#   PUNAR_BUILD_MODE build | summary       (default: build; summary runs
#                    staging + `mkosi summary` only — the cheap local
#                    config-validation path, no image build)
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
    dev|desktop|all) ;;
    *) echo "error: PUNAR_IMAGES must be dev, desktop, or all (got: ${IMAGES})" >&2; exit 2 ;;
esac
case "${MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${MODE})" >&2; exit 2 ;;
esac

# Copy the desktop configuration/assets from their source-of-truth trees
# into the desktop profile's mkosi.extra. These staged paths are gitignored
# (os/images/.gitignore) — os/modules/desktop and shell/ stay the single
# source of truth; this staging is re-done fresh on every build.
stage_desktop_extra() {
    local mod="${REPO_ROOT}/os/modules/desktop"
    local shell_src="${REPO_ROOT}/shell/punar-shell"
    local tokens="${REPO_ROOT}/shell/theme/punar-tokens.json"
    local extra="${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra"

    echo "==> Verifying vendored font manifest"
    (cd "${mod}/fonts" && sha256sum --quiet -c MANIFEST.sha256)

    echo "==> Staging desktop configs/assets into ${extra}"
    # Only the STAGED subtrees are wiped: usr/share/punar/nftables (the
    # vendored punar-base.nft, M3) is versioned and must survive staging.
    rm -rf "${extra}/etc/xdg" "${extra}/etc/fonts" \
           "${extra}/usr/share/fonts" "${extra}/usr/share/punar/shell" \
           "${extra}/usr/share/punar/theme" \
           "${extra}/usr/share/punar/fixtures"
    mkdir -p "${extra}/etc/xdg/hypr" "${extra}/etc/xdg/foot" \
             "${extra}/etc/fonts/conf.d" "${extra}/usr/share/fonts/punar" \
             "${extra}/usr/share/punar/shell" "${extra}/usr/share/punar/theme" \
             "${extra}/usr/share/punar/fixtures/acme" \
             "${extra}/usr/share/punar/fixtures/projects/atlas"

    # Hyprland config (hyprlang files; install path per their headers).
    cp "${mod}"/hypr/*.conf "${extra}/etc/xdg/hypr/"
    # Layout preset engine (milestone-2.md §4): source of truth lives
    # beside the hypr configs; binds, exec-once and m2-check.sh all
    # reference /usr/lib/punar/punar-layout.sh. Staged (gitignored) into
    # the otherwise-versioned usr/lib/punar directory.
    rm -f "${extra}/usr/lib/punar/punar-layout.sh"
    install -m 0755 "${mod}/hypr/punar-layout.sh" \
        "${extra}/usr/lib/punar/punar-layout.sh"
    # foot system-wide config (first-found-wins; overwrites the packaged
    # commented example at the same path — intended, see module README).
    cp "${mod}/foot/foot.ini" "${extra}/etc/xdg/foot/foot.ini"
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
       "${extra}/usr/share/punar/fixtures/acme/"
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
       "${extra}/usr/share/punar/fixtures/projects/atlas/"
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
    echo "==> Building punard + punarctl + punar-env + punar-agentd + punar-mock-smplify (release, --locked; $(rustc --version))"
    (
        cd "${REPO_ROOT}" &&
            CARGO_HOME="${IMAGES_DIR}/cache/cargo" \
                CARGO_TARGET_DIR="${cargo_target}" \
                cargo build --release --locked \
                    -p punard -p punarctl -p punar-env -p punar-agentd \
                    -p punar-mock-smplify
    )

    echo "==> Staging punard + punarctl + punar-env + punar-agentd + punar-mock-smplify into ${extra}/usr/bin (gitignored)"
    install -d "${extra}/usr/bin"
    install -m 0755 \
        "${cargo_target}/release/punard" \
        "${cargo_target}/release/punarctl" \
        "${cargo_target}/release/punar-env" \
        "${cargo_target}/release/punar-agentd" \
        "${cargo_target}/release/punar-mock-smplify" \
        "${extra}/usr/bin/"
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
        if mkosi --force --mirror "${MIRROR}" "$@" "${MODE}"; then
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
    local raw="out/${image_id}.raw"

    # mkosi names the disk output <ImageId>.raw; glob defensively in case a
    # future mkosi appends version/architecture suffixes.
    if [ ! -f "${raw}" ]; then
        shopt -s nullglob
        for candidate in "out/${image_id}"*.raw; do
            raw="${candidate}"
            break
        done
        shopt -u nullglob
    fi
    if [ ! -f "${raw}" ]; then
        echo "error: no .raw output for ${image_id} found in out/" >&2
        ls -la out/ >&2 || true
        exit 1
    fi

    echo "==> Converting ${raw} -> ${qcow} (compressed qcow2)"
    qemu-img convert -O qcow2 -c "${raw}" "${qcow}"
    rm -f "${raw}"
}

BUILT=()

if [ "${IMAGES}" = "dev" ] || [ "${IMAGES}" = "all" ]; then
    run_mkosi punar-dev
    if [ "${MODE}" = "build" ]; then
        convert_output punar-dev
        BUILT+=("punar-dev")
    fi
fi

if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "all" ]; then
    stage_desktop_extra
    if [ "${MODE}" = "build" ]; then
        stage_punar_binaries
        stage_env_base_oci
    fi
    run_mkosi punar-desktop \
        --profile desktop \
        --image-id punar-desktop \
        --hostname punar-desktop
    if [ "${MODE}" = "build" ]; then
        convert_output punar-desktop
        BUILT+=("punar-desktop")
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
    echo "note: unsigned development images; VM-only (no linux-firmware)"
    echo "note: punar-desktop is the M1 graphical workstation (Hyprland + punar-shell) + M3 control plane (punard/punarctl, hermetic in-container build) + M5 enrollment exercise scaffolding (punar-mock-smplify dev/CI mock + staged Acme fixtures — never enabled, m5-check-only) + M6 developer environments (punar-env + preloaded punar-env-base OCI archive + staged Atlas project fixture) + M7 AI agent registry (punar-agentd daemon + vendored adapter/signature data + the punar-mock-agent and foo-agent dev/CI fixtures — the mock stands in for a real agent binary, which the offline VM cannot have)"
} > out/build-info.txt

# Bare filenames (no ./ prefix) — CI re-verifies with `sha256sum -c` against
# the artifact names.
(
    cd out
    sha256sum -- *.qcow2 > SHA256SUMS
)

echo "==> Build complete"
ls -lh out/
