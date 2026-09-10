#!/usr/bin/env python3
"""Create end-to-end plaintext filter fixtures using real libdedsec carriers."""
from __future__ import annotations

import argparse
import base64
import re
from pathlib import Path


def bits(payload: bytes) -> list[int]:
    return [(byte >> (7 - bit)) & 1 for byte in payload for bit in range(8)]


def zero_width(cover: str, payload_bits: list[int]) -> str:
    positions = [i for i, char in enumerate(cover) if char.isalpha()]
    if len(positions) < len(payload_bits):
        raise ValueError("cover has too few alphabetic characters")
    values = dict(zip(positions, payload_bits))
    return "".join(char + ("\u200c" if values[i] else "\u200b")
                   if i in values else char for i, char in enumerate(cover))


def variation(cover: str, payload_bits: list[int]) -> str:
    if len(payload_bits) % 4:
        raise ValueError("variation-selector payload is not nibble aligned")
    values = [sum(payload_bits[i + j] << (3 - j) for j in range(4))
              for i in range(0, len(payload_bits), 4)]
    positions = [i for i, char in enumerate(cover) if char.isalpha()]
    if len(positions) < len(values):
        raise ValueError("cover has too few alphabetic characters")
    insertions = dict(zip(positions, values))
    return "".join(char + chr(0xFE00 + insertions[i])
                   if i in insertions else char for i, char in enumerate(cover))


def gap_width(cover: str, payload_bits: list[int]) -> str:
    cover = re.sub(r"[ \t]+", " ", cover)
    positions = [i for i, char in enumerate(cover)
                 if char == " " and i > 0 and i + 1 < len(cover)
                 and cover[i - 1] != "\n" and cover[i + 1] != "\n"]
    if len(positions) < len(payload_bits):
        raise ValueError("cover has too few word gaps")
    # The gap decoder emits every eligible gap. End the carrier immediately
    # after the final payload gap so the extraction has no synthetic zero tail.
    cover = cover[:positions[len(payload_bits) - 1] + 2]
    positions = positions[:len(payload_bits)]
    values = dict(zip(positions, payload_bits))
    return "".join("  " if values.get(i) else " " if i in values else char
                   for i, char in enumerate(cover))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cover", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--message", default="Meet at the loading dock at midnight.")
    args = parser.parse_args()

    cover = args.cover.read_text(encoding="utf-8")
    message = args.message.encode("utf-8")
    payloads = {
        "raw": message,
        "base32": base64.b32encode(message),
        "base64": base64.b64encode(message),
    }
    carriers = {
        "zero_width": zero_width,
        "variation": variation,
        "gap_width": gap_width,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = ["file\tcarrier\tpayload_encoding\tpayload_bytes"]
    for encoding, payload in payloads.items():
        for carrier, encode in carriers.items():
            path = args.output / f"{carrier}_{encoding}.txt"
            path.write_text(encode(cover, bits(payload)), encoding="utf-8")
            manifest.append(f"{path.name}\t{carrier}\t{encoding}\t{len(payload)}")
    (args.output / "manifest.tsv").write_text("\n".join(manifest) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
