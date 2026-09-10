#!/usr/bin/env python3
"""Make deterministic paired text-stego fixtures from a UTF-8 cover text.

The payload is pseudorandom on purpose: it is a calibration signal for entropy
metrics, not an example of meaningful hidden content.
"""
from __future__ import annotations

import argparse
import binascii
import re
from pathlib import Path


def random_bits(count: int) -> list[int]:
    state = 0x6D2B79F5
    result = []
    for _ in range(count):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        result.append(state & 1)
    return result


def framed_bits(count: int) -> list[int]:
    """DSC1 + length + deterministic body + CRC-32, then one partial tail if needed."""
    full_bytes = count // 8
    if full_bytes < 10:
        raise ValueError("payload needs at least 80 bits for a DSC1 frame")
    body = pack(random_bits((full_bytes - 10) * 8))
    header = b"DSC1" + len(body).to_bytes(2, "big")
    frame = header + body + binascii.crc32(header + body).to_bytes(4, "big")
    bits = [byte >> (7 - bit) & 1 for byte in frame for bit in range(8)]
    return bits + random_bits(count - len(bits))


def pack(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        out[i // 8] |= bit << (7 - (i % 8))
    return bytes(out)


def zero_width(cover: str, bits: list[int]) -> str:
    positions = [i for i, char in enumerate(cover) if char.isalpha()]
    if len(positions) < len(bits):
        raise ValueError("cover has too few alphabetic characters")
    insertions = dict(zip(positions, bits))
    return "".join(char + ("\u200c" if insertions.get(i) else "\u200b")
                   if i in insertions else char for i, char in enumerate(cover))


def variation_selector(cover: str, bits: list[int]) -> str:
    if len(bits) % 4:
        raise ValueError("variation-selector payload must be a multiple of four bits")
    positions = [i for i, char in enumerate(cover) if char.isalpha()]
    nibbles = [sum(bits[i + j] << (3 - j) for j in range(4))
               for i in range(0, len(bits), 4)]
    if len(positions) < len(nibbles):
        raise ValueError("cover has too few alphabetic characters")
    insertions = dict(zip(positions, nibbles))
    return "".join(char + chr(0xfe00 + insertions[i])
                   if i in insertions else char for i, char in enumerate(cover))


def gap_width(cover: str, bits: list[int]) -> str:
    positions = [i for i, char in enumerate(cover)
                 if char == " " and i > 0 and i + 1 < len(cover)
                 and cover[i - 1] != "\n" and cover[i + 1] != "\n"]
    if len(positions) < len(bits):
        raise ValueError("cover has too few ASCII spaces")
    insertions = dict(zip(positions, bits))
    return "".join("  " if insertions.get(i) else " "
                   if i in insertions else char for i, char in enumerate(cover))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cover", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--bits", type=int, default=1024,
                        help="payload bits for the zero-width and selector lanes")
    args = parser.parse_args()
    cover = args.cover.read_text(encoding="utf-8")
    if args.bits % 4:
        parser.error("--bits must be a multiple of four for variation selectors")
    bits = framed_bits(args.bits)
    # Normalize pre-existing multi-space runs: the decoder treats a run as one
    # symbol, whereas encoding individual characters in an existing run would
    # make an ambiguous width greater than two.
    gap_cover = re.sub(r" +", " ", cover)
    gap_count = sum(1 for i, char in enumerate(gap_cover)
                    if char == " " and i > 0 and i + 1 < len(gap_cover)
                    and gap_cover[i - 1] != "\n" and gap_cover[i + 1] != "\n")
    gap_bits = framed_bits(gap_count)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "payload.zero_width.bin").write_bytes(pack(bits))
    (args.output / "payload.zero_width.bit_length").write_text(f"{len(bits)}\n", encoding="ascii")
    # The selector decoder emits four equal bits for each selector value.
    selector_bits = [bit for bit in bits for _ in range(4)]
    (args.output / "payload.variation_selector.bin").write_bytes(pack(selector_bits))
    (args.output / "payload.variation_selector.bit_length").write_text(
        f"{len(selector_bits)}\n", encoding="ascii")
    (args.output / "payload.gap_width.bin").write_bytes(pack(gap_bits))
    (args.output / "payload.gap_width.bit_length").write_text(
        f"{len(gap_bits)}\n", encoding="ascii")
    (args.output / "zero_width.txt").write_text(zero_width(cover, bits), encoding="utf-8")
    (args.output / "variation_selector.txt").write_text(variation_selector(cover, bits), encoding="utf-8")
    (args.output / "gap_width.txt").write_text(gap_width(gap_cover, gap_bits), encoding="utf-8")


if __name__ == "__main__":
    main()
