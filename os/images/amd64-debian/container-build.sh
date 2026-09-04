#!/usr/bin/env bash
# Build the isolated Debian/amd64 substrate candidate inside the pinned Debian
# builder. The shipping Arch artifacts are neither read nor overwritten.
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$(cd "${TARGET_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
cd "${TARGET_DIR}"

# shellcheck source=/dev/null
. "${TARGET_DIR}/snapshot.env"

MODE="${PUNAR_BUILD_MODE:-build}"
IMAGES="${PUNAR_AMD64_DEBIAN_IMAGES:-minimal}"
case "${MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${MODE})" >&2; exit 2 ;;
esac
case "${IMAGES}" in
    minimal|desktop|release|iso|all) ;;
    *) echo "error: PUNAR_AMD64_DEBIAN_IMAGES must be minimal, desktop, release, iso, or all (got: ${IMAGES})" >&2; exit 2 ;;
esac

MKOSI_REPART_DIR="$(mktemp -d /run/punar-mkosi-repart-amd64-debian.XXXXXX)"
MKOSI_RAW_OUTPUT_DIR="$(mktemp -d /var/tmp/punar-mkosi-output-amd64-debian.XXXXXX)"
BTRFS_DEVICE_UUID="ef4a2286-ac11-53c0-a40d-8d2bae7511cc"

cleanup_build() {
    rm -rf "${MKOSI_REPART_DIR}"
    local raw
    for raw in "${MKOSI_RAW_OUTPUT_DIR}"/*.raw; do
        [ -f "${raw}" ] || continue
        truncate --size 0 -- "${raw}" || true
        rm -f -- "${raw}"
    done
    rm -rf "${MKOSI_RAW_OUTPUT_DIR}"
}
trap cleanup_build EXIT

install -d "${IMAGES_DIR}/out"
"${REPO_ROOT}/tools/render-mkosi-repart.sh" \
    "${MKOSI_REPART_DIR}" "${IMAGES_DIR}/repart.d/install"

stage_desktop_content() {
    echo "==> Staging shared architecture-neutral desktop content"
    PUNAR_IMAGES=desktop PUNAR_BUILD_MODE=stage \
        "${IMAGES_DIR}/scripts/container-build.sh"
}

stage_punar_binaries() {
    local extra="${TARGET_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local dev_extra="${TARGET_DIR}/mkosi.profiles/dev/mkosi.extra"
    local cargo_target="${IMAGES_DIR}/cache/cargo-target-amd64-debian"

    echo "==> Building native Debian/amd64 Punar binaries (--release --locked; $(rustc --version))"
    (
        cd "${REPO_ROOT}"
        CARGO_HOME="${IMAGES_DIR}/cache/cargo-amd64-debian" \
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

    "${REPO_ROOT}/tests/images/check-staged-service-executables.sh" \
        "${extra}" "${dev_extra}" \
        "${IMAGES_DIR}/mkosi.profiles/desktop/mkosi.extra" \
        "${IMAGES_DIR}/mkosi.profiles/dev/mkosi.extra" \
        'Advanced Micro Devices X86-64'
}

stage_installer_build_tool() {
    local cargo_target="${IMAGES_DIR}/cache/cargo-target-amd64-debian"
    echo "==> Building native Debian/amd64 release verifier for ISO assembly"
    (
        cd "${REPO_ROOT}"
        CARGO_HOME="${IMAGES_DIR}/cache/cargo-amd64-debian" \
            CARGO_TARGET_DIR="${cargo_target}" \
            cargo build --release --locked \
                -p punar-common --bin punar-release-tool
    )
    [ -x "${cargo_target}/release/punar-release-tool" ]
}

stage_env_base_oci() {
    local extra="${TARGET_DIR}/mkosi.profiles/desktop/mkosi.extra"
    local cache_dir="${IMAGES_DIR}/cache/debian-amd64-pkgs"
    local pkg='busybox-static_1%3a1.38.0-3+b1_amd64.deb'
    local pkg_version='1:1.38.0-3+b1'
    local pkg_sha256='26801f17e6c88e813be104effc0ea3b43d912bd59ca6295fcd1260528ebb4d41'
    local ref='localhost/punar-env-base:m6'
    local max_bytes=$((16 * 1024 * 1024))
    local created='2026-08-20T00:00:00Z'

    install -d "${cache_dir}"
    if ! echo "${pkg_sha256}  ${cache_dir}/${pkg}" \
        | sha256sum --quiet -c - >/dev/null 2>&1; then
        echo "==> Fetching pinned amd64 BusyBox from Debian snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
        apt-get update -qq
        (
            cd "${cache_dir}"
            apt-get download "busybox-static=${pkg_version}"
        )
    fi
    echo "${pkg_sha256}  ${cache_dir}/${pkg}" | sha256sum --quiet -c -

    local work
    work="$(mktemp -d /tmp/punar-env-base-amd64-debian.XXXXXX)"
    install -d "${work}/pkg" "${work}/rootfs/bin" \
        "${work}/rootfs/etc" "${work}/rootfs/workspace" \
        "${work}/rootfs/tmp"
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
        echo "error: pinned amd64 BusyBox is not static (ldd: ${ldd_out})" >&2
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
    printf '{"created":"%s","architecture":"amd64","os":"linux","config":{"Env":["PATH=/bin"],"Cmd":["/bin/sh"]},"rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}' \
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
        "${manifest_sha}" "${manifest_size}" "${ref}" \
        > "${layout}/index.json"
    printf '{"imageLayoutVersion":"1.0.0"}' > "${layout}/oci-layout"
    chmod -R u=rwX,go=rX "${layout}"
    tar "${tar_flags[@]}" -C "${layout}" -cf "${work}/punar-env-base.tar" .

    local archive_sha archive_size
    archive_sha="$(sha256sum "${work}/punar-env-base.tar" | cut -d' ' -f1)"
    archive_size="$(stat -c %s "${work}/punar-env-base.tar")"
    [ "${archive_size}" -le "${max_bytes}" ] || {
        echo "error: amd64 OCI archive exceeds ${max_bytes} bytes" >&2
        exit 1
    }

    install -d "${extra}/usr/share/punar/oci"
    install -m 0644 "${work}/punar-env-base.tar" \
        "${extra}/usr/share/punar/oci/punar-env-base.tar"
    {
        echo "ref: ${ref}"
        echo "architecture: amd64"
        echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
        echo "archive-sha256: ${archive_sha}"
        echo "archive-bytes: ${archive_size}"
        echo "oci-manifest-digest: sha256:${manifest_sha}"
        echo "config-digest: sha256:${config_sha}"
        echo "layer-digest: sha256:${layer_sha} (uncompressed, so diff_id is identical)"
        echo "input: ${pkg} sha256:${pkg_sha256} (Debian snapshot ${PUNAR_DEBIAN_SNAPSHOT})"
        echo "built-by: amd64-debian/container-build.sh stage_env_base_oci"
    } > "${extra}/usr/share/punar/oci/punar-env-base.note.txt"
    echo "==> amd64 offline OCI base: ${archive_size} bytes, sha256 ${archive_sha}"
    rm -rf "${work}"
}

reset_staged_architecture_content() {
    rm -rf \
        "${TARGET_DIR}/mkosi.profiles/desktop/mkosi.extra/usr/bin" \
        "${TARGET_DIR}/mkosi.profiles/desktop/mkosi.extra/usr/share/punar/oci" \
        "${TARGET_DIR}/mkosi.profiles/dev/mkosi.extra/usr/bin"
    install -d \
        "${TARGET_DIR}/mkosi.profiles/desktop/mkosi.extra" \
        "${TARGET_DIR}/mkosi.profiles/dev/mkosi.extra"
}

run_mkosi() {
    local image_id=$1
    shift
    echo "==> mkosi ${MODE}: ${image_id}, Debian/amd64 snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
    mkosi --force \
        --snapshot "${PUNAR_DEBIAN_SNAPSHOT}" \
        --source-date-epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
        --output-directory "${MKOSI_RAW_OUTPUT_DIR}" \
        --environment "SYSTEMD_REPART_MKFS_OPTIONS_BTRFS=--device-uuid=${BTRFS_DEVICE_UUID}" \
        --environment "PUNAR_IMAGE_ID=punar-desktop" \
        --environment "PUNAR_IMAGE_VERSION=${PUNAR_BASE_IMAGE_VERSION}" \
        --environment "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
        --environment "PUNAR_ENABLED_UNITS_MANIFEST=expected-enabled-units.x86_64-debian.txt" \
        --repart-directory "${MKOSI_REPART_DIR}" \
        "$@" "${MODE}"
}

convert_output() {
    local image_id=$1
    local raw="${MKOSI_RAW_OUTPUT_DIR}/${image_id}.raw"
    local qcow="${IMAGES_DIR}/out/${image_id}.qcow2"
    local tmp_qcow="${qcow}.tmp"
    [ -f "${raw}" ] || { echo "error: expected ${raw}" >&2; exit 1; }

    echo "==> Verifying candidate A/B layout and shared-state mounts in ${raw}"
    "${REPO_ROOT}/tests/images/check-repart-layout.sh" "${raw}" x86_64
    rm -f -- "${tmp_qcow}"
    qemu-img convert -O qcow2 -c "${raw}" "${tmp_qcow}"
    mv -f -- "${tmp_qcow}" "${qcow}"
    CHECKSUM_ARTIFACTS+=("${image_id}.qcow2")
    truncate --size 0 -- "${raw}"
    rm -f -- "${raw}" "${MKOSI_RAW_OUTPUT_DIR}/${image_id}"
}

BUILT=()
CHECKSUM_ARTIFACTS=()
reset_staged_architecture_content

if [ "${IMAGES}" = minimal ] || [ "${IMAGES}" = all ]; then
    run_mkosi punar-dev-debian-x86_64 \
        --profile dev \
        --image-id punar-dev-debian-x86_64 \
        --hostname punar-dev-debian-x86-64
    if [ "${MODE}" = build ]; then
        convert_output punar-dev-debian-x86_64
        BUILT+=(punar-dev-debian-x86_64)
    fi
fi

if [ "${IMAGES}" = desktop ] || [ "${IMAGES}" = release ] \
    || [ "${IMAGES}" = iso ] \
    || [ "${IMAGES}" = all ]; then
    stage_desktop_content
    if [ "${MODE}" = build ]; then
        stage_punar_binaries
        stage_env_base_oci
        if [ "${IMAGES}" = iso ]; then
            stage_installer_build_tool
        fi
    fi
    if [ "${IMAGES}" = desktop ] || [ "${IMAGES}" = all ]; then
        run_mkosi punar-desktop-debian-x86_64 \
            --profile desktop,hardware-x86,dev \
            --image-id punar-desktop-debian-x86_64 \
            --hostname punar-desktop-debian-x86-64
        if [ "${MODE}" = build ]; then
            convert_output punar-desktop-debian-x86_64
            BUILT+=(punar-desktop-debian-x86_64)
        fi
    fi
fi

if [ "${IMAGES}" = release ] || [ "${IMAGES}" = iso ]; then
    run_mkosi punar-release-debian-x86_64 \
        --profile desktop,hardware-x86 \
        --image-id punar-release-debian-x86_64
    if [ "${IMAGES}" = iso ] && [ "${MODE}" = summary ]; then
        run_mkosi punar-installer-root-debian-x86_64 \
            --profile desktop,hardware-x86,installer \
            --image-id punar-installer-root-debian-x86_64
    fi
    if [ "${MODE}" = build ]; then
        if [ "${IMAGES}" = iso ]; then
            run_mkosi punar-installer-root-debian-x86_64 \
                --profile desktop,hardware-x86,installer \
                --image-id punar-installer-root-debian-x86_64
            installer_version="${PUNAR_INSTALLER_VERSION:?PUNAR_INSTALLER_VERSION is required for an ISO build}"
            installer_name="punar-installer-debian-${installer_version}-x86_64.iso"
            installer_built_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            installer_ci_run_id="${PUNAR_CI_RUN_ID:-local-${PUNAR_GIT_SHA:0:12}}"
            PUNAR_RELEASE_SNAPSHOT_PIN="${PUNAR_DEBIAN_SNAPSHOT}" \
            PUNAR_RELEASE_BUILDER_BASE="${PUNAR_DEBIAN_BUILDER_BASE}" \
            PUNAR_RELEASE_SOURCE_DATE_EPOCH="${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
            PUNAR_RELEASE_TOOL="${IMAGES_DIR}/cache/cargo-target-amd64-debian/release/punar-release-tool" \
                "${IMAGES_DIR}/scripts/assemble-installer-iso.sh" \
                    "${MKOSI_RAW_OUTPUT_DIR}/punar-release-debian-x86_64.raw" \
                    "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root-debian-x86_64.raw" \
                    "${installer_version}" \
                    "${IMAGES_DIR}/out/${installer_name}" \
                    "${PUNAR_GIT_SHA}" "${installer_built_at}" "${installer_ci_run_id}"
            truncate --size 0 -- \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root-debian-x86_64.raw"
            rm -f -- \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root-debian-x86_64.raw" \
                "${MKOSI_RAW_OUTPUT_DIR}/punar-installer-root-debian-x86_64"
            BUILT+=("${installer_name}")
            CHECKSUM_ARTIFACTS+=("${installer_name}")
        fi
        convert_output punar-release-debian-x86_64
        BUILT+=(punar-release-debian-x86_64)
    fi
fi

if [ "${MODE}" = summary ]; then
    echo "==> Debian/amd64 candidate summary complete"
    exit 0
fi

{
    echo "images: ${BUILT[*]}"
    echo "substrate: Debian sid"
    echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
    echo "architecture: x86_64"
    echo "status: migration candidate; shipping Arch baseline remains authoritative"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [ "${IMAGES}" = desktop ] || [ "${IMAGES}" = all ]; then
        echo "desktop-artifact: CI exercise image; contains dev fixtures and must not be shown as a product demo"
        echo "hardware-profile: signed Debian snapshot firmware/microcode for the selected Intel/AMD matrix; physical qualification remains open"
    fi
    if [ "${IMAGES}" = release ]; then
        echo "release-artifact: product image; release-image policy rejects dev fixtures and synthetic test harnesses"
        echo "hardware-profile: signed Debian snapshot firmware/microcode for the selected Intel/AMD matrix; physical qualification remains open"
    fi
} > "${IMAGES_DIR}/out/debian-amd64-build-info.txt"
(
    cd "${IMAGES_DIR}/out"
    sha256sum -- "${CHECKSUM_ARTIFACTS[@]}" > SHA256SUMS.debian-amd64
)

HOST_UID="${PUNAR_HOST_UID:-0}"
HOST_GID="${PUNAR_HOST_GID:-0}"
[[ "${HOST_UID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_UID: ${HOST_UID}" >&2; exit 2; }
[[ "${HOST_GID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_GID: ${HOST_GID}" >&2; exit 2; }
install -d -m 0755 -o "${HOST_UID}" -g "${HOST_GID}" \
    "${IMAGES_DIR}/out/debian-amd64-boot-proof" \
    "${IMAGES_DIR}/out/debian-amd64-desktop-proof"
chown "${HOST_UID}:${HOST_GID}" \
    "${IMAGES_DIR}/out/SHA256SUMS.debian-amd64" \
    "${IMAGES_DIR}/out/debian-amd64-build-info.txt"
for artifact in "${CHECKSUM_ARTIFACTS[@]}"; do
    chown "${HOST_UID}:${HOST_GID}" "${IMAGES_DIR}/out/${artifact}"
done
for cache_path in \
    "${IMAGES_DIR}/cache/debian-amd64" \
    "${IMAGES_DIR}/cache/debian-amd64-pkgs" \
    "${IMAGES_DIR}/cache/cargo-amd64-debian" \
    "${IMAGES_DIR}/cache/cargo-target-amd64-debian"; do
    [ ! -e "${cache_path}" ] \
        || chown -R "${HOST_UID}:${HOST_GID}" "${cache_path}"
done

echo "==> Debian/amd64 candidate image build complete"
ls -lh "${IMAGES_DIR}/out/SHA256SUMS.debian-amd64"
for artifact in "${CHECKSUM_ARTIFACTS[@]}"; do
    ls -lh "${IMAGES_DIR}/out/${artifact}"
done
