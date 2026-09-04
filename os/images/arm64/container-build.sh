#!/usr/bin/env bash
# Runs inside the native Debian builder container. The minimal image remains
# the CI default while the desktop lane crosses the same runtime gates as the
# x86_64 image. Architecture-neutral desktop files are staged by the shared
# helper path; compiled binaries and the offline OCI base stay ARM-local so a
# stale x86_64 cache can never enter this image.
set -euo pipefail

ARM64_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$(cd "${ARM64_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
cd "${ARM64_DIR}"

# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

MODE="${PUNAR_BUILD_MODE:-build}"
IMAGES="${PUNAR_ARM64_IMAGES:-minimal}"
case "${MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${MODE})" >&2; exit 2 ;;
esac
case "${IMAGES}" in
    minimal|desktop|release|all) ;;
    *) echo "error: PUNAR_ARM64_IMAGES must be minimal, desktop, release, or all (got: ${IMAGES})" >&2; exit 2 ;;
esac

MKOSI_REPART_DIR="$(mktemp -d /run/punar-mkosi-repart-arm64.XXXXXX)"
MKOSI_RAW_OUTPUT_DIR="$(mktemp -d /var/tmp/punar-mkosi-output-arm64.XXXXXX)"
# Generated output roots are gitignored and therefore absent in a clean
# checkout. Create the host-mounted destination before the first conversion.
install -d "${IMAGES_DIR}/out"
# UUIDv5(URL, https://punar.org/filesystem-device/PUNAR-DATA). See the shared
# x86 build script: this stabilizes the device identity, not btrfs's separate
# subvolume UUIDs. A production installer may provide a per-device value.
BTRFS_DEVICE_UUID="ef4a2286-ac11-53c0-a40d-8d2bae7511cc"
cleanup_build() {
    rm -rf "${MKOSI_REPART_DIR}"

    # Keep the sparse raw disk on Docker's native Linux filesystem. Only the
    # compressed qcow2 crosses VirtioFS; otherwise mkosi's output handoff can
    # materialize all 33 GiB on the host.
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
    for raw in "${IMAGES_DIR}/out"/punar-*-arm64.raw; do
        [ -f "${raw}" ] || continue
        truncate --size 0 -- "${raw}" || true
        rm -f -- "${raw}"
    done
}
trap cleanup_build EXIT
"${REPO_ROOT}/tools/render-mkosi-repart.sh" \
    "${MKOSI_REPART_DIR}" "${IMAGES_DIR}/repart.d/install"

stage_desktop_content() {
    echo "==> Staging shared architecture-neutral desktop content"
    PUNAR_IMAGES=desktop PUNAR_BUILD_MODE=stage \
        "${IMAGES_DIR}/scripts/container-build.sh"
}

stage_punar_binaries() {
    local extra="${ARM64_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local dev_extra="${ARM64_DIR}/mkosi.profiles/dev/mkosi.extra"
    local cargo_target="${IMAGES_DIR}/cache/cargo-target-arm64"

    echo "==> Building native ARM64 Punar binaries (--release --locked; $(rustc --version))"
    (
        cd "${REPO_ROOT}"
        CARGO_HOME="${IMAGES_DIR}/cache/cargo-arm64" \
            CARGO_TARGET_DIR="${cargo_target}" \
            cargo build --release --locked \
                -p punard -p punarctl -p punar-env -p punar-agentd \
                -p punar-secrets -p punar-netd -p punar-onboard \
                -p punar-mock-smplify
    )

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

    local binary
    for binary in punard punarctl punar-env punar-agentd punar-secrets \
        punar-netd punar-onboard punar-onboardd punar-greet; do
        readelf -h "${extra}/usr/bin/${binary}" \
            | grep -q 'Machine:.*AArch64' || {
            echo "error: ${binary} is not an AArch64 binary" >&2
            exit 1
        }
    done
    readelf -h "${dev_extra}/usr/bin/punar-mock-smplify" \
        | grep -q 'Machine:.*AArch64' || {
        echo "error: punar-mock-smplify is not an AArch64 binary" >&2
        exit 1
    }

    "${REPO_ROOT}/tests/images/check-staged-service-executables.sh" \
        "${extra}" "${dev_extra}" \
        "${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra" \
        "${IMAGES_DIR}/mkosi.profiles/dev/mkosi.extra" AArch64
}

# Assemble the M6 offline base from Debian's pinned static BusyBox. This is
# the ARM equivalent of the Arch/x86_64 builder's hand-authored OCI archive:
# no registry, no nested container engine, fixed metadata and a verified
# package digest.
stage_env_base_oci() {
    local extra="${ARM64_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local cache_dir="${IMAGES_DIR}/cache/debian-arm64-pkgs"
    local pkg='busybox-static_1%3a1.38.0-3+b1_arm64.deb'
    local pkg_version='1:1.38.0-3+b1'
    local pkg_sha256='968d1aa8f579fa1ac59c26afa365454369e13cf29848e6400b50028fed0ffda0'
    local ref='localhost/punar-env-base:m6'
    local max_bytes=$((16 * 1024 * 1024))
    local created='2026-08-20T00:00:00Z'

    install -d "${cache_dir}"
    if ! echo "${pkg_sha256}  ${cache_dir}/${pkg}" \
        | sha256sum --quiet -c - >/dev/null 2>&1; then
        echo "==> Fetching pinned ARM64 BusyBox from Debian snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
        apt-get update -qq
        (
            cd "${cache_dir}"
            apt-get download "busybox-static=${pkg_version}"
        )
    fi
    echo "${pkg_sha256}  ${cache_dir}/${pkg}" | sha256sum --quiet -c -

    local work
    work="$(mktemp -d /tmp/punar-env-base-arm64.XXXXXX)"
    install -d "${work}/pkg" "${work}/rootfs/bin" "${work}/rootfs/etc" \
        "${work}/rootfs/workspace" "${work}/rootfs/tmp"
    dpkg-deb --extract "${cache_dir}/${pkg}" "${work}/pkg"
    install -m 0755 "${work}/pkg/usr/bin/busybox" \
        "${work}/rootfs/bin/busybox"

    local applet
    for applet in sh sleep cat echo ls touch env id uname; do
        ln -s busybox "${work}/rootfs/bin/${applet}"
    done
    printf 'punar-env-base m6 %s\n' "${PUNAR_DEBIAN_SNAPSHOT}" \
        > "${work}/rootfs/etc/punar-env-base-release"

    local ldd_out
    ldd_out="$(ldd "${work}/rootfs/bin/busybox" 2>&1 || true)"
    grep -Eq 'not a dynamic executable|statically linked' <<< "${ldd_out}" || {
        echo "error: pinned ARM64 BusyBox is not static (ldd: ${ldd_out})" >&2
        exit 1
    }

    chmod 0755 "${work}/rootfs" "${work}/rootfs/bin" \
        "${work}/rootfs/etc" "${work}/rootfs/workspace"
    chmod 1777 "${work}/rootfs/tmp"
    chmod 0644 "${work}/rootfs/etc/punar-env-base-release"

    local tar_flags=(
        --format=posix
        "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime"
        --sort=name
        --numeric-owner --owner=0 --group=0
        "--mtime=@${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}"
    )
    tar "${tar_flags[@]}" -C "${work}/rootfs" -cf "${work}/layer.tar" .

    local layer_sha layer_size config_sha config_size manifest_sha manifest_size
    layer_sha="$(sha256sum "${work}/layer.tar" | cut -d' ' -f1)"
    layer_size="$(stat -c %s "${work}/layer.tar")"
    printf '{"created":"%s","architecture":"arm64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["/bin/sh"]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
        "${created}" "${layer_sha}" > "${work}/config.json"
    config_sha="$(sha256sum "${work}/config.json" | cut -d' ' -f1)"
    config_size="$(stat -c %s "${work}/config.json")"
    printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":%s},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:%s","size":%s}]}' \
        "${config_sha}" "${config_size}" "${layer_sha}" "${layer_size}" \
        > "${work}/manifest.json"
    manifest_sha="$(sha256sum "${work}/manifest.json" | cut -d' ' -f1)"
    manifest_size="$(stat -c %s "${work}/manifest.json")"

    local layout="${work}/layout"
    install -d "${layout}/blobs/sha256"
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
    [ "${archive_size}" -le "${max_bytes}" ] || {
        echo "error: ARM64 OCI archive exceeds ${max_bytes} bytes" >&2
        exit 1
    }

    install -d "${extra}/usr/share/punar/oci"
    install -m 0644 "${work}/punar-env-base.tar" \
        "${extra}/usr/share/punar/oci/punar-env-base.tar"
    {
        echo "ref: ${ref}"
        echo "architecture: arm64"
        echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
        echo "archive-sha256: ${archive_sha}"
        echo "archive-bytes: ${archive_size}"
        echo "oci-manifest-digest: sha256:${manifest_sha}"
        echo "config-digest: sha256:${config_sha}"
        echo "layer-digest: sha256:${layer_sha} (uncompressed, so diff_id is identical)"
        echo "input: ${pkg} sha256:${pkg_sha256} (Debian snapshot ${PUNAR_DEBIAN_SNAPSHOT})"
        echo "built-by: arm64/container-build.sh stage_env_base_oci"
    } > "${extra}/usr/share/punar/oci/punar-env-base.note.txt"
    echo "==> ARM64 offline OCI base: ${archive_size} bytes, sha256 ${archive_sha}"
    rm -rf "${work}"
}

reset_staged_architecture_content() {
    # Generated and gitignored. The previous layout placed the two generated
    # subtrees at the ARM config root beside VERSIONED Debian product
    # adapters. Clear only those legacy subtrees, never the whole extra tree,
    # then clear the three profile-local destinations before mkosi runs.
    rm -rf "${ARM64_DIR}/mkosi.extra/usr/bin" \
           "${ARM64_DIR}/mkosi.extra/usr/share/punar/oci" \
           "${ARM64_DIR}/mkosi.profiles/desktop/mkosi.extra/usr/bin" \
           "${ARM64_DIR}/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/oci" \
           "${ARM64_DIR}/mkosi.profiles/dev/mkosi.extra/usr/bin"

    # Empty directories are not represented by git. A clean checkout has no
    # ARM profile-local extra trees until staging runs, but the minimal image
    # is intentionally built before desktop staging. Keep both profile roots
    # present so mkosi's profile discovery never depends on residue from an
    # earlier local build.
    install -d \
        "${ARM64_DIR}/mkosi.profiles/desktop/mkosi.extra" \
        "${ARM64_DIR}/mkosi.profiles/dev/mkosi.extra"
}

run_mkosi() {
    local image_id="$1"
    shift
    echo "==> mkosi ${MODE}: ${image_id}, native arm64, Debian snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
    mkosi --force \
        --snapshot "${PUNAR_DEBIAN_SNAPSHOT}" \
        --source-date-epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
        --output-directory "${MKOSI_RAW_OUTPUT_DIR}" \
        --environment "SYSTEMD_REPART_MKFS_OPTIONS_BTRFS=--device-uuid=${BTRFS_DEVICE_UUID}" \
        --environment "PUNAR_IMAGE_ID=punar-desktop" \
        --environment "PUNAR_IMAGE_VERSION=${PUNAR_BASE_IMAGE_VERSION}" \
        --environment "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
        --repart-directory "${MKOSI_REPART_DIR}" \
        "$@" "${MODE}"
}

convert_output() {
    local image_id="$1"
    local raw="${MKOSI_RAW_OUTPUT_DIR}/${image_id}.raw"
    local qcow="${IMAGES_DIR}/out/${image_id}.qcow2"
    local tmp_qcow="${qcow}.tmp"
    [ -f "${raw}" ] || {
        echo "error: expected ${raw}" >&2
        exit 1
    }
    echo "==> Verifying A/B layout and shared-state mounts in ${raw}"
    "${REPO_ROOT}/tests/images/check-repart-layout.sh" "${raw}" arm64
    echo "==> Converting ${raw} -> ${qcow}"
    rm -f -- "${tmp_qcow}"
    qemu-img convert -O qcow2 -c "${raw}" "${tmp_qcow}"
    mv -f -- "${tmp_qcow}" "${qcow}"
    truncate --size 0 -- "${raw}"
    rm -f -- "${raw}" "${MKOSI_RAW_OUTPUT_DIR}/${image_id}"
}

BUILT=()
reset_staged_architecture_content
if [ "${IMAGES}" = "minimal" ] || [ "${IMAGES}" = "all" ]; then
    run_mkosi punar-dev-arm64 --profile dev
    if [ "${MODE}" = "build" ]; then
        convert_output punar-dev-arm64
        BUILT+=("punar-dev-arm64")
    fi
fi

if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "release" ] \
    || [ "${IMAGES}" = "all" ]; then
    stage_desktop_content
    if [ "${MODE}" = "build" ]; then
        stage_punar_binaries
        stage_env_base_oci
    fi
    if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "all" ]; then
        run_mkosi punar-desktop-arm64 \
            --profile desktop,dev \
            --image-id punar-desktop-arm64 \
            --hostname punar-desktop-arm64
        if [ "${MODE}" = "build" ]; then
            convert_output punar-desktop-arm64
            BUILT+=("punar-desktop-arm64")
        fi
    fi
fi

if [ "${IMAGES}" = "release" ] || [ "${IMAGES}" = "all" ]; then
    run_mkosi punar-release-arm64 \
        --profile desktop \
        --image-id punar-release-arm64
    if [ "${MODE}" = "build" ]; then
        convert_output punar-release-arm64
        BUILT+=("punar-release-arm64")
    fi
fi

if [ "${MODE}" = "summary" ]; then
    echo "==> Native ARM64 summary mode complete"
    exit 0
fi

{
    echo "images: ${BUILT[*]}"
    echo "substrate: Debian sid"
    echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
    echo "architecture: arm64"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "scope: generic UEFI/QEMU ARM64; Raspberry Pi firmware and peripherals remain a separate gate"
    if [ "${IMAGES}" = "desktop" ] || [ "${IMAGES}" = "all" ]; then
        echo "desktop-artifact: CI exercise image; contains dev fixtures and must not be shown as a product demo"
    fi
    if [ "${IMAGES}" = "release" ] || [ "${IMAGES}" = "all" ]; then
        echo "release-artifact: product image; release-image policy rejects dev fixtures and synthetic test harnesses"
    fi
} > "${IMAGES_DIR}/out/arm64-build-info.txt"

(
    cd "${IMAGES_DIR}/out"
    sha256sum -- "${BUILT[@]/%/.qcow2}" > SHA256SUMS.arm64
)

# A privileged builder is root inside Linux CI, while the following QEMU
# steps run as the host runner. Keep the large image artifacts untouched, but
# pre-create every write target with the caller's numeric ownership so the
# boot harnesses can retain serial/runtime proof. The host cannot create a new
# sibling beneath the root-owned out directory after this container exits.
# Docker Desktop maps these IDs back to the invoking macOS user as well.
HOST_UID="${PUNAR_HOST_UID:-0}"
HOST_GID="${PUNAR_HOST_GID:-0}"
[[ "${HOST_UID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_UID: ${HOST_UID}" >&2; exit 2; }
[[ "${HOST_GID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_GID: ${HOST_GID}" >&2; exit 2; }
install -d -m 0755 -o "${HOST_UID}" -g "${HOST_GID}" \
    "${IMAGES_DIR}/out/arm64-boot-proof" \
    "${IMAGES_DIR}/out/arm64-update-rollback-proof" \
    "${IMAGES_DIR}/out/arm64-desktop-proof"

# mkosi/apt create private root-owned metadata directories. The cache archive
# is written later by the unprivileged Actions runner, so return ownership of
# generated inputs after the privileged build has finished with them.
for cache_path in \
    "${IMAGES_DIR}/cache/debian-arm64" \
    "${IMAGES_DIR}/cache/debian-arm64-pkgs" \
    "${IMAGES_DIR}/cache/cargo-arm64" \
    "${IMAGES_DIR}/cache/cargo-target-arm64"; do
    [ ! -e "${cache_path}" ] \
        || chown -R "${HOST_UID}:${HOST_GID}" "${cache_path}"
done

echo "==> Native ARM64 image build complete"
ls -lh "${IMAGES_DIR}/out/arm64-build-info.txt" \
    "${IMAGES_DIR}/out/SHA256SUMS.arm64"
