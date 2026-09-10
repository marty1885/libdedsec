#!/usr/bin/env python3
"""Paired Arabic bidi-control carrier experiment for libdedsec."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


MESSAGE = b"Meet at the loading dock at midnight."


def load_sentences(path: Path) -> list[str]:
    return [line[len("# text = "):]
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("# text = ")]


def windows(sentences: list[str], target_chars: int, limit: int) -> list[str]:
    result: list[str] = []
    current: list[str] = []
    length = 0
    for sentence in sentences:
        current.append(sentence)
        length += len(sentence) + 1
        if length >= target_chars:
            result.append("\n".join(current) + "\n")
            current = []
            length = 0
            if len(result) == limit:
                break
    return result


def payload_bits(payload: bytes) -> list[int]:
    return [(byte >> (7 - bit)) & 1 for byte in payload for bit in range(8)]


def embed_bidi(cover: str, bits: list[int]) -> str:
    positions = [i for i, char in enumerate(cover)
                 if 0x0600 <= ord(char) <= 0x06FF and char.isalpha()]
    if len(positions) < len(bits):
        raise ValueError("Arabic window is too short for payload")
    values = dict(zip(positions, bits))
    # U+2066 LEFT-TO-RIGHT ISOLATE encodes zero, U+2067 RIGHT-TO-LEFT
    # ISOLATE encodes one, and every opener is immediately balanced by U+2069.
    return "".join(char + ("\u2067" if values[i] else "\u2066") + "\u2069"
                   if i in values else char for i, char in enumerate(cover))


def legitimate_bidi_formatting(cover: str) -> str:
    """Isolate genuine LTR tokens inside the RTL Arabic text."""
    return re.sub(r"[A-Za-z0-9][A-Za-z0-9.+:/_-]*",
                  lambda match: "\u2066" + match.group(0) + "\u2069", cover)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument("--window-chars", type=int, default=2048)
    parser.add_argument("--probe", type=Path, default=Path("build/dedsec_bidi_probe"))
    args = parser.parse_args()

    source_sentences = load_sentences(args.corpus)
    covers = windows(source_sentences, args.window_chars, args.samples)
    if len(covers) < args.samples:
        raise SystemExit(f"only constructed {len(covers)} Arabic windows")
    payloads = {"raw": MESSAGE, "base32": base64.b32encode(MESSAGE)}
    rows: list[dict[str, str | int | float]] = []
    metadata: list[tuple[str, str, int]] = []

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dedsec-arabic-bidi-") as temporary:
        root = Path(temporary)
        paths: list[Path] = []
        for index, cover in enumerate(covers):
            cover_path = root / f"cover-{index}.txt"
            cover_path.write_text(cover, encoding="utf-8")
            paths.append(cover_path)
            metadata.append(("cover", "none", len(cover)))
            formatted_path = root / f"cover-formatted-{index}.txt"
            formatted = legitimate_bidi_formatting(cover)
            formatted_path.write_text(formatted, encoding="utf-8")
            paths.append(formatted_path)
            metadata.append(("cover", "legitimate-bidi", len(cover)))
            for encoding, payload in payloads.items():
                stego = embed_bidi(cover, payload_bits(payload))
                stego_path = root / f"stego-{encoding}-{index}.txt"
                stego_path.write_text(stego, encoding="utf-8")
                paths.append(stego_path)
                metadata.append(("stego", encoding, len(cover)))
                if index == 0:
                    (args.output / f"sample_stego_{encoding}.txt").write_text(
                        stego, encoding="utf-8")
            if index == 0:
                (args.output / "sample_cover.txt").write_text(cover, encoding="utf-8")
                (args.output / "sample_cover_legitimate_bidi.txt").write_text(
                    formatted, encoding="utf-8")

        output = subprocess.check_output([str(args.probe), *map(str, paths)], text=True)
        parsed = list(csv.DictReader(output.splitlines(), delimiter="\t"))
        if len(parsed) != len(metadata):
            raise SystemExit("probe output count mismatch")
        for (label, encoding, cover_chars), result in zip(metadata, parsed):
            row: dict[str, str | int | float] = {
                "label": label, "encoding": encoding, "cover_chars": cover_chars
            }
            for key, value in result.items():
                if key == "file":
                    continue
                row[key] = value if key == "plaintext_verdict" else int(value)
            row["bidi_controls_per_1000_chars"] = (
                1000.0 * int(result["bidi_evidence"]) / cover_chars)
            rows.append(row)

    fields = list(rows[0])
    with (args.output / "results.tsv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)

    summary = ["label\tencoding\tsamples\tbinary_candidates\tbidi_nonzero\tbidi_score_75\t"
               "bidi_score_min\tbidi_score_max\tbidi_evidence_min\t"
               "bidi_evidence_max\tbidi_evidence_mean\textracted_bits_min\t"
               "extracted_bits_max\tbidi_controls_per_1000_min\t"
               "bidi_controls_per_1000_max\tinsufficient\treject\tpossible\tlikely"]
    for label, encoding in (("cover", "none"), ("cover", "legitimate-bidi"),
                            ("stego", "raw"), ("stego", "base32")):
        group = [row for row in rows if row["label"] == label and row["encoding"] == encoding]
        def bounds(field: str) -> tuple[int, int]:
            values = [int(row[field]) for row in group]
            return min(values), max(values)
        bidi_score = bounds("bidi_score")
        evidence = bounds("bidi_evidence")
        extracted = bounds("extracted_bits")
        densities = [float(row["bidi_controls_per_1000_chars"]) for row in group]
        nonzero = sum(int(row["bidi_evidence"]) > 0 for row in group)
        saturated = sum(int(row["bidi_score"]) == 75 for row in group)
        binary_candidates = sum(int(row["binary_evidence"]) > 0 for row in group)
        verdicts = {name: sum(row["plaintext_verdict"] == name for row in group)
                    for name in ("insufficient", "reject", "possible", "likely")}
        summary.append(f"{label}\t{encoding}\t{len(group)}\t{binary_candidates}\t"
                       f"{nonzero}\t{saturated}\t"
                       f"{bidi_score[0]}\t"
                       f"{bidi_score[1]}\t{evidence[0]}\t{evidence[1]}\t"
                       f"{sum(int(row['bidi_evidence']) for row in group) / len(group):.3f}\t"
                       f"{extracted[0]}\t{extracted[1]}\t{min(densities):.3f}\t"
                       f"{max(densities):.3f}\t{verdicts['insufficient']}\t"
                       f"{verdicts['reject']}\t{verdicts['possible']}\t{verdicts['likely']}")
    (args.output / "summary.tsv").write_text("\n".join(summary) + "\n", encoding="utf-8")
    digest = hashlib.sha256(args.corpus.read_bytes()).hexdigest()
    (args.output / "provenance.txt").write_text(
        "source=https://github.com/UniversalDependencies/UD_Arabic-PADT\n"
        f"file={args.corpus}\nsha256={digest}\n"
        f"sentences={len(source_sentences)}\nwindows={len(covers)}\n"
        f"message={MESSAGE.decode('ascii')}\n",
        encoding="utf-8")


if __name__ == "__main__":
    main()
