#!/usr/bin/env python3
"""Tiny dependency-free probes for QEMU P6 framebuffer captures.

This intentionally recognizes structural states, not product copy: the
pre-login card occupies the centre of the frame while the desktop owns a
near-white full-width top bar. It never performs OCR and therefore never reads
or persists passwords or recovery material.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib
from pathlib import Path


def read_token(stream) -> bytes:
    token = bytearray()
    while True:
        byte = stream.read(1)
        if not byte:
            raise ValueError("truncated PPM header")
        if byte == b"#":
            stream.readline()
            continue
        if not byte.isspace():
            token.extend(byte)
            break
    while True:
        byte = stream.read(1)
        if not byte or byte.isspace():
            return bytes(token)
        token.extend(byte)


def read_ppm(path: Path) -> tuple[int, int, bytes]:
    with path.open("rb") as stream:
        magic = read_token(stream)
        width = int(read_token(stream))
        height = int(read_token(stream))
        maximum = int(read_token(stream))
        if magic != b"P6" or maximum != 255:
            raise ValueError("expected an 8-bit binary P6 framebuffer")
        pixels = stream.read()
    expected = width * height * 3
    if width < 320 or height < 240 or len(pixels) != expected:
        raise ValueError(
            f"invalid framebuffer geometry {width}x{height} ({len(pixels)} bytes)"
        )
    return width, height, pixels


def near_white_fraction(
    width: int,
    height: int,
    pixels: bytes,
    left: float,
    top: float,
    right: float,
    bottom: float,
) -> float:
    x0 = max(0, min(width - 1, int(width * left)))
    x1 = max(x0 + 1, min(width, int(width * right)))
    y0 = max(0, min(height - 1, int(height * top)))
    y1 = max(y0 + 1, min(height, int(height * bottom)))
    white = 0
    total = (x1 - x0) * (y1 - y0)
    for y in range(y0, y1):
        row = y * width * 3
        for x in range(x0, x1):
            offset = row + x * 3
            red, green, blue = pixels[offset : offset + 3]
            if red >= 220 and green >= 220 and blue >= 220:
                white += 1
    return white / total


def green_action_fraction(
    width: int,
    height: int,
    pixels: bytes,
    left: float,
    top: float,
    right: float,
    bottom: float,
) -> float:
    """Return the fraction occupied by Punar's green primary action."""
    x0 = max(0, min(width - 1, int(width * left)))
    x1 = max(x0 + 1, min(width, int(width * right)))
    y0 = max(0, min(height - 1, int(height * top)))
    y1 = max(y0 + 1, min(height, int(height * bottom)))
    green = 0
    total = (x1 - x0) * (y1 - y0)
    for y in range(y0, y1):
        row = y * width * 3
        for x in range(x0, x1):
            offset = row + x * 3
            red, channel, blue = pixels[offset : offset + 3]
            if channel >= 70 and channel > red * 1.25 and channel > blue * 1.25:
                green += 1
    return green / total


def write_png(path: Path, width: int, height: int, pixels: bytes) -> None:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        checksum = zlib.crc32(kind)
        checksum = zlib.crc32(payload, checksum) & 0xFFFFFFFF
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", checksum)
        )

    stride = width * 3
    scanlines = b"".join(
        b"\x00" + pixels[offset : offset + stride]
        for offset in range(0, len(pixels), stride)
    )
    body = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(scanlines, level=9))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "state", choices=("onboarding", "receipt", "desktop", "info", "png")
    )
    parser.add_argument("frame", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()

    try:
        width, height, pixels = read_ppm(args.frame)
    except (OSError, ValueError) as error:
        print(f"framebuffer probe: {error}", file=sys.stderr)
        return 2

    if args.state == "png":
        if args.output is None:
            parser.error("png requires an output path")
        try:
            write_png(args.output, width, height, pixels)
        except OSError as error:
            print(f"framebuffer probe: {error}", file=sys.stderr)
            return 2
        print(args.output)
        return 0

    # The shipped shell bar is intentionally lean: 30 px at the canonical
    # 1280x800 proof resolution. Sample only its actual vertical band instead
    # of averaging it with the wallpaper immediately below it.
    top = near_white_fraction(width, height, pixels, 0.0, 0.0, 1.0, 0.04)
    centre = near_white_fraction(width, height, pixels, 0.05, 0.20, 0.95, 0.86)
    lower_action = green_action_fraction(
        width, height, pixels, 0.70, 0.79, 0.86, 0.91
    )
    print(
        f"PUNAR_FRAMEBUFFER width={width} height={height} "
        f"top_white={top:.4f} centre_white={centre:.4f} "
        f"lower_action_green={lower_action:.4f}"
    )
    if args.state == "info":
        return 0
    if args.state == "onboarding":
        return 0 if centre >= 0.55 and top < 0.55 else 1
    if args.state == "receipt":
        return 0 if centre >= 0.55 and top < 0.55 and lower_action < 0.02 else 1
    return 0 if top >= 0.70 else 1


if __name__ == "__main__":
    raise SystemExit(main())
