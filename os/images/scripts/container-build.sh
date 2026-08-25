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
           "${extra}/usr/share/punar/theme"
    mkdir -p "${extra}/etc/xdg/hypr" "${extra}/etc/xdg/foot" \
             "${extra}/etc/fonts/conf.d" "${extra}/usr/share/fonts/punar" \
             "${extra}/usr/share/punar/shell" "${extra}/usr/share/punar/theme"

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

    echo "==> Building punard + punarctl (release, --locked; $(rustc --version))"
    (
        cd "${REPO_ROOT}" &&
            CARGO_HOME="${IMAGES_DIR}/cache/cargo" \
                CARGO_TARGET_DIR="${cargo_target}" \
                cargo build --release --locked -p punard -p punarctl
    )

    echo "==> Staging punard + punarctl into ${extra}/usr/bin (gitignored)"
    install -d "${extra}/usr/bin"
    install -m 0755 \
        "${cargo_target}/release/punard" \
        "${cargo_target}/release/punarctl" \
        "${extra}/usr/bin/"
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
    echo "note: punar-desktop is the M1 graphical workstation (Hyprland + punar-shell) + M3 control plane (punard/punarctl, hermetic in-container build)"
} > out/build-info.txt

# Bare filenames (no ./ prefix) — CI re-verifies with `sha256sum -c` against
# the artifact names.
(
    cd out
    sha256sum -- *.qcow2 > SHA256SUMS
)

echo "==> Build complete"
ls -lh out/
