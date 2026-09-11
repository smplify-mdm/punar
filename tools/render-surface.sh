#!/usr/bin/env bash
# Render a Punar QML surface headlessly and save a PNG.
#
#   ./tools/render-surface.sh Mail            → /tmp/punar-render/Mail.png
#   ./tools/render-surface.sh Mail 1400 900
#   PUNAR_RENDER_THEME=panel ./tools/render-surface.sh Mail   → Mail.panel.png
#   PUNAR_RENDER_IPC="mail open 1" ./tools/render-surface.sh Mail
#
# PUNAR_RENDER_IPC drives the surface through its own IpcHandler before the
# screenshot, so a state that only exists after interaction can be seen. It is
# deliberately IPC and not synthetic keystrokes: a headless compositor delivers
# keys to the wrong surface often enough (wl_keyboard.leave does not match the
# current focus) that a wtype-based harness reports success while pressing
# nothing, which is worse than not having the feature.
#
# THE THEME ARGUMENT IS NOT A CONVENIENCE. Punar ships two moods and the token
# set flips wholesale between them: `shellRaise2` collapses to `panelSurface` on
# panel, so a fill that separates on paper becomes the ground; and panelInk3
# measures 3.39:1 against a panel tint, below the 4.5 text floor, so text that
# passes on paper fails there. A surface reviewed in one mood is half reviewed.
#
# WHY THIS EXISTS. Punar's QML runs only under Quickshell on a Wayland
# compositor, so for a long time the only way to see a surface was to build an
# image and boot a VM — roughly thirty minutes per look. Four consecutive CI
# cycles were spent debugging a Mail window nobody could see, and three of the
# four faults would have been obvious in a screenshot: an id shadowing a
# property, a missing graphics environment, and an inline component nested
# below its file root. qmllint reported the file clean for all three.
#
# So: a Debian sid container with the same `quickshell` package the image
# installs, a headless wlroots compositor, and grim. It stages the tree exactly
# where the image does — /usr/share/punar/shell and /usr/share/punar/theme —
# because Theme resolves its tokens by absolute path and the app's own
# `//@ pragma Env QML_IMPORT_PATH` names that root. Staging it anywhere else
# would test a layout the product does not have.
#
# The package list mirrors the image's own (os/images/arm64/mkosi.profiles/
# desktop/mkosi.conf): quickshell alone is not enough, because the shell imports
# Qt.labs.folderlistmodel and Debian ships that separately from qt6-declarative.
# A missing QML module is invisible until the engine refuses the file.
#
# It is NOT a substitute for the in-VM gate. There is no punard here, no D-Bus
# session, no real compositor policy and no window management; a surface that
# needs any of those will not render and should not be judged here. This
# answers one question only, and it is the question that was costing the most:
# does it draw, and does it look right.
set -euo pipefail

SURFACE="${1:?usage: render-surface.sh <SurfaceDir> [width] [height]}"
WIDTH="${2:-1400}"
HEIGHT="${3:-900}"
# A theme id from shell/theme/themes/<id>.theme.json. Empty means the shipped
# default pointer, which is `paper`.
THEME="${PUNAR_RENDER_THEME:-}"
SUFFIX=""
[ -z "${THEME}" ] || SUFFIX=".${THEME}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${PUNAR_RENDER_OUT:-/tmp/punar-render}"
IMAGE="${PUNAR_RENDER_IMAGE:-punar-render}"

[ -d "${REPO_ROOT}/shell/punar-shell/${SURFACE}" ] \
    || { echo "no such surface: shell/punar-shell/${SURFACE}" >&2; exit 1; }

if ! docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    echo "==> building ${IMAGE} (once)"
    docker build -t "${IMAGE}" - <<'DOCKERFILE'
FROM debian:sid
RUN apt-get update && apt-get install -y --no-install-recommends \
      quickshell sway grim wayland-utils qt6-wayland \
      libqt6svg6 qml6-module-qt-labs-folderlistmodel \
      wtype fontconfig ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

mkdir -p "${OUT_DIR}"

# `sleep` before grim: Quickshell compiles QML, resolves the Theme singleton and
# maps the window asynchronously, and a screenshot taken before the first frame
# is a blank output that looks exactly like a surface that failed to draw.
docker run --rm \
    --volume "${REPO_ROOT}:/work:ro" \
    --volume "${OUT_DIR}:/out" \
    --env "PUNAR_SURFACE=${SURFACE}" \
    --env "PUNAR_W=${WIDTH}" \
    --env "PUNAR_H=${HEIGHT}" \
    --env "PUNAR_THEME=${THEME}" \
    --env "PUNAR_IPC=${PUNAR_RENDER_IPC:-}" \
    --env "PUNAR_SUFFIX=${SUFFIX}" \
    "${IMAGE}" sh -eu -c '
      # Stage exactly as the image does, so absolute paths resolve.
      mkdir -p /usr/share/punar/theme/themes /usr/share/fonts/punar
      cp -R /work/shell/punar-shell /usr/share/punar/shell
      cp /work/shell/theme/punar-tokens.json /usr/share/punar/theme/
      cp -R /work/shell/theme/themes/. /usr/share/punar/theme/themes/ 2>/dev/null || true
      cp -R /work/os/modules/desktop/fonts/instrument-sans \
            /work/os/modules/desktop/fonts/geist-mono /usr/share/fonts/punar/
      fc-cache -f >/dev/null 2>&1 || true

      # /etc/punar/theme.json is the first system pointer candidate Theme.qml
      # consults, so writing one selects the theme without touching the tree.
      # The mood is stated explicitly rather than left to the theme document
      # defaultMood, so the render names the mood it asked for.
      # NO SINGLE QUOTES ANYWHERE IN THIS BLOCK, in a comment or in code: the
      # whole container script is one single-quoted sh -c argument, so a lone
      # apostrophe terminates it and spills the remainder into the host shell.
      # The first version of this block used printf with a single-quoted format
      # string, which broke the quoting silently: the pointer was never written,
      # the render succeeded, and it was byte-identical to the paper one. Only
      # comparing the two hashes caught it.
      if [ -n "${PUNAR_THEME}" ]; then
        mkdir -p /etc/punar
        printf "{\"kind\":\"PunarThemePointer\",\"active\":\"%s\",\"mood\":\"%s\"}\n" \
          "${PUNAR_THEME}" "${PUNAR_THEME}" > /etc/punar/theme.json
      fi

      export XDG_RUNTIME_DIR=/tmp/xdg
      mkdir -p "$XDG_RUNTIME_DIR" && chmod 0700 "$XDG_RUNTIME_DIR"
      export WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1
      export LIBGL_ALWAYS_SOFTWARE=1 QT_QUICK_BACKEND=software
      export WLR_RENDERER=pixman
      export LANG=C.UTF-8

      # THE SHOT SCRIPT IS A FILE, NOT AN INLINE exec. sway parses its config
      # and expands $name itself, so a loop variable written inline is eaten
      # before sh ever sees it: the first version produced "Missing argument to
      # -k" and silently screenshotted the un-keyed state. A separate file has
      # no sway parsing applied to it at all.
      cat > /tmp/shot.sh <<SHOT
sleep 12
if [ -n "${PUNAR_IPC}" ]; then
  qs -p /usr/share/punar/shell/${PUNAR_SURFACE} ipc call ${PUNAR_IPC} \
    >>/out/${PUNAR_SURFACE}${PUNAR_SUFFIX}.log 2>&1 || true
  sleep 3
fi
sleep 1
grim /out/${PUNAR_SURFACE}${PUNAR_SUFFIX}.png 2>>/out/${PUNAR_SURFACE}${PUNAR_SUFFIX}.log
swaymsg exit
SHOT

      cat > /tmp/sway.cfg <<CFG
output HEADLESS-1 resolution ${PUNAR_W}x${PUNAR_H}
exec sh -c "qs -p /usr/share/punar/shell/${PUNAR_SURFACE} >/out/${PUNAR_SURFACE}${PUNAR_SUFFIX}.log 2>&1"
exec sh /tmp/shot.sh
CFG
      sway -c /tmp/sway.cfg >/out/sway.log 2>&1 || true
    ' || true

if [ -s "${OUT_DIR}/${SURFACE}${SUFFIX}.png" ]; then
    echo "==> ${OUT_DIR}/${SURFACE}${SUFFIX}.png ($(wc -c < "${OUT_DIR}/${SURFACE}${SUFFIX}.png" | tr -d ' ') bytes)"
else
    echo "==> no image produced; quickshell said:" >&2
    sed 's/\x1b\[[0-9;]*m//g' "${OUT_DIR}/${SURFACE}${SUFFIX}.log" 2>/dev/null | tail -25 >&2
    exit 1
fi
