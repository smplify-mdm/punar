#!/usr/bin/env bash
# Evaluate Punar's Hyprland Lua configuration with the SAME Hyprland the image
# ships, without a display: `Hyprland --verify-config` runs every file through
# the real Lua API and reports the first error (an unknown dispatcher, a
# misspelt option, a rule field that does not exist).
#
# WHY. A Hyprland Lua error is not a build failure: mkosi copies the files in
# verbatim and the defect appears at login as a desktop with no key binds, or
# — the 2026-09 pointer back-out — a throw half-way through punar-binds.lua
# that silently removed every bind after it. This gate runs in about a minute
# against the pinned compositor, before any image is built.
#
# WHAT IT RUNS, as an unprivileged user (Hyprland refuses root):
#   1. hyprland.lua with no keyboard file (first boot, a failed render);
#   2. with a rendered two-layout file (the `us,ru` acceptance case);
#   3. with the Mac-style clipboard keys on (the other bind set);
#   4. punar-greeter.lua;
#   5. punar-input.lua's DATA-ONLY reader, through assertion configs that
#      `error()` on a wrong answer: a valid file is read, a hostile file and a
#      malformed one fall back to US English, and none of them is executed;
#   6. foot.ini, through `foot --check-config`, which rejects a key binding
#      that names no real key (the terminal's clipboard keys live there).
#
# Image: the pinned Arch snapshot with hyprland, built on first use like
# tools/qmllint.sh. On an arm64 development machine, where that snapshot has
# no packages, point PUNAR_HYPR_VERIFY_IMAGE at any image with the same
# Hyprland (0.56.x) installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "${REPO_ROOT}/os/images/snapshot.env"

SNAP="${PUNAR_SNAPSHOT_DATE}"
IMAGE_TAG="${PUNAR_HYPR_VERIFY_IMAGE:-punar-hyprverify:${SNAP//\//-}}"
PLATFORM_ARGS=()

if [ -z "${PUNAR_HYPR_VERIFY_IMAGE:-}" ]; then
    PLATFORM_ARGS=(--platform linux/amd64)
    if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
        echo "==> building the Hyprland verify container (${IMAGE_TAG})"
        docker build --platform linux/amd64 -t "${IMAGE_TAG}" -f - "${REPO_ROOT}" <<CONTAINERFILE
FROM ${PUNAR_BUILDER_BASE}
RUN printf 'Server=https://archive.archlinux.org/repos/${SNAP}/\$repo/os/\$arch\n' \
      > /etc/pacman.d/mirrorlist \\
 && sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf \\
 && echo 'DisableSandbox' >> /etc/pacman.conf \\
 && echo 'DisableDownloadTimeout' >> /etc/pacman.conf \\
 && pacman -Sy --noconfirm --needed hyprland foot util-linux \\
 && pacman -Scc --noconfirm
CONTAINERFILE
    fi
fi

echo "==> Hyprland --verify-config ($(basename "${IMAGE_TAG}"))"
docker run --rm ${PLATFORM_ARGS[@]+"${PLATFORM_ARGS[@]}"} \
    -v "${REPO_ROOT}/os/modules/desktop/hypr:/src:ro" \
    -v "${REPO_ROOT}/os/modules/desktop/foot:/foot:ro" "${IMAGE_TAG}" \
    bash -c '
set -euo pipefail
id person >/dev/null 2>&1 || useradd -m -u 1000 person
RUNTIME=/run/user/1000
install -d -o person -m 0700 "${RUNTIME}" "${RUNTIME}/punar" "${RUNTIME}/punar/session"
install -d /etc/xdg/hypr
cp /src/*.lua /etc/xdg/hypr/
: > /etc/xdg/hypr/punar-session-profile.lua
failed=0

verify() {
    label="$1"
    config="$2"
    out="$(su person -s /bin/sh -c "XDG_RUNTIME_DIR=${RUNTIME} HOME=/home/person Hyprland --verify-config -c ${config}" 2>&1 || true)"
    result="$(printf "%s\n" "${out}" | sed -n "/Config parsing result/,\$p" | tail -n +2 | sed "/^$/d")"
    if [ "${result}" = "config ok" ]; then
        echo "ok   ${label}"
    else
        echo "FAIL ${label}: ${result:-no verdict}"
        failed=1
    fi
}

session_file() {
    printf "%s\n" "$1" > "${RUNTIME}/punar/session/input.lua"
    chown person "${RUNTIME}/punar/session/input.lua"
}

rm -f "${RUNTIME}/punar/session/input.lua"
verify "desktop config, no keyboard file" /etc/xdg/hypr/hyprland.lua
session_file "return {
    kb_layout = \"us,ru\",
    kb_variant = \",phonetic\",
    kb_options = \"grp:alts_toggle\",
}"
verify "desktop config, rendered us,ru" /etc/xdg/hypr/hyprland.lua
install -d -o person /home/person/.config/punar
printf "%s\n" "{\"version\": 1, \"clipboardKeys\": \"mac\"}" > /home/person/.config/punar/keyboard.json
chown person /home/person/.config/punar/keyboard.json
verify "desktop config, Mac-style clipboard keys" /etc/xdg/hypr/hyprland.lua
rm -f /home/person/.config/punar/keyboard.json
verify "greeter config" /etc/xdg/hypr/punar-greeter.lua

# The reader, held to its contract by configs that fail on a wrong answer.
expect() {
    label="$1"
    layout="$2"
    variant="$3"
    options="$4"
    cat > /etc/xdg/hypr/expect-input.lua <<LUA
local c = require("/etc/xdg/hypr/punar-input.lua").config()
if c.kb_layout ~= "${layout}" or c.kb_variant ~= "${variant}" or c.kb_options ~= "${options}" then
    error("punar-input.lua read " .. tostring(c.kb_layout) .. " / " .. tostring(c.kb_variant) .. " / " .. tostring(c.kb_options))
end
if c.follow_mouse ~= 0 or c.repeat_rate ~= 40 or c.repeat_delay ~= 250 or not c.touchpad.clickfinger_behavior then
    error("punar-input.lua lost its pointer defaults")
end
if punar_hostile_ran then
    error("the keyboard file was executed")
end
LUA
    verify "reader: ${label}" /etc/xdg/hypr/expect-input.lua
}

session_file "return {
    kb_layout = \"us,ru\",
    kb_variant = \",phonetic\",
    kb_options = \"grp:alts_toggle\",
}"
expect "a rendered file is read" "us,ru" ",phonetic" "grp:alts_toggle"
session_file "punar_hostile_ran = true
return {
    kb_layout = \"us\\\"; punar_hostile_ran = true --\",
    kb_variant = \"\",
    kb_options = \"\",
}"
expect "a hostile file is neither run nor used" "us" "" ""
session_file "return { kb_layout = \"de\" }"
expect "a malformed file falls back to US" "us" "" ""
rm -f "${RUNTIME}/punar/session/input.lua"
expect "no file is US English" "us" "" ""
rm -f /etc/xdg/hypr/expect-input.lua

if foot_out="$(su person -s /bin/sh -c "XDG_RUNTIME_DIR=${RUNTIME} LANG=C.UTF-8 foot --check-config --config=/foot/foot.ini" 2>&1)"; then
    echo "ok   foot.ini"
else
    echo "FAIL foot.ini: ${foot_out}"
    failed=1
fi

exit "${failed}"
'
echo "==> Hyprland configuration verified"
