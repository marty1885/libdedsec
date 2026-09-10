#!/usr/bin/env python3
"""Evaluate dedsec_bitstream_filter on real text encodings and binary negatives."""
from __future__ import annotations

import argparse
import base64
import csv
import os
import subprocess
import tempfile
from pathlib import Path


TEST_KEY = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)


def messages(corpus: Path, limit: int) -> list[bytes]:
    result: list[bytes] = []
    for path in sorted(corpus.glob("*.txt")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = " ".join(line.split()).strip()
            encoded = line.encode("utf-8")
            if 12 <= len(encoded) <= 160 and sum(char.isalpha() for char in line) * 2 >= len(line):
                result.append(encoded)
                if len(result) == limit:
                    return result
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--samples", type=int, default=300)
    parser.add_argument("--filter", type=Path, default=Path("build/dedsec_plaintext_filter"))
    args = parser.parse_args()
    source = messages(args.corpus, args.samples)
    if len(source) < args.samples:
        raise SystemExit(f"only found {len(source)} eligible messages")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    transforms = {
        "raw": lambda value: value,
        "base16": lambda value: value.hex().encode("ascii"),
        "base32": base64.b32encode,
        "base32hex": base64.b32hexencode,
        "base64": base64.b64encode,
        "base64-base32": lambda value: base64.b64encode(base64.b32encode(value)),
    }
    rows: list[dict[str, str | int]] = []
    with tempfile.TemporaryDirectory(prefix="dedsec-plaintext-filter-") as temporary:
        root = Path(temporary)
        files: list[Path] = []
        metadata: list[tuple[str, str, int]] = []
        aes = AESGCM(TEST_KEY)
        for index, message in enumerate(source):
            for encoding, transform in transforms.items():
                path = root / f"p-{index}-{encoding}.bin"
                path.write_bytes(transform(message))
                files.append(path)
                metadata.append(("plaintext", encoding, len(message)))
            random_value = os.urandom(len(message))
            for encoding, transform in {
                "random": lambda value: value,
                "random-base16": lambda value: value.hex().encode("ascii"),
                "random-base32": base64.b32encode,
                "random-base64": base64.b64encode,
            }.items():
                random_path = root / f"n-{index}-{encoding}.bin"
                random_path.write_bytes(transform(random_value))
                files.append(random_path)
                metadata.append(("negative", encoding, len(message)))
            nonce = index.to_bytes(12, "big")
            aes_value = nonce + aes.encrypt(nonce, message, b"libdedsec-filter-v1")
            for encoding, transform in {
                "aes-gcm": lambda value: value,
                "aes-gcm-base16": lambda value: value.hex().encode("ascii"),
                "aes-gcm-base32": base64.b32encode,
                "aes-gcm-base64": base64.b64encode,
            }.items():
                aes_path = root / f"n-{index}-{encoding}.bin"
                aes_path.write_bytes(transform(aes_value))
                files.append(aes_path)
                metadata.append(("negative", encoding, len(message)))

        results: list[list[str]] = []
        for start in range(0, len(files), 200):
            chunk = files[start:start + 200]
            output = subprocess.check_output([str(args.filter), *map(str, chunk)], text=True)
            results.extend(list(csv.reader(output.splitlines()[1:], delimiter="\t")))
        if len(results) != len(metadata):
            raise SystemExit("filter output count mismatch")
        for meta, result in zip(metadata, results):
            label, encoding, original_bytes = meta
            rows.append({
                "label": label,
                "encoding": encoding,
                "original_bytes": original_bytes,
                "verdict": result[1],
                "score": int(result[2]),
                "flags": int(result[3]),
                "bit_offset": int(result[4]),
                "transform_depth": int(result[5]),
                "decoded_bytes": int(result[6]),
            })

    args.output.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with (args.output / "results.tsv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
    summary = ["label\tencoding\tsamples\treject\tinsufficient\tpossible\tlikely"]
    for label in ("plaintext", "negative"):
        encodings = transforms if label == "plaintext" else {
            "random": None, "random-base16": None, "random-base32": None,
            "random-base64": None, "aes-gcm": None, "aes-gcm-base16": None,
            "aes-gcm-base32": None, "aes-gcm-base64": None,
        }
        for encoding in encodings:
            group = [row for row in rows if row["label"] == label and row["encoding"] == encoding]
            counts = {name: sum(row["verdict"] == name for row in group)
                      for name in ("reject", "insufficient", "possible", "likely")}
            summary.append(f"{label}\t{encoding}\t{len(group)}\t{counts['reject']}\t"
                           f"{counts['insufficient']}\t{counts['possible']}\t{counts['likely']}")
    (args.output / "summary.tsv").write_text("\n".join(summary) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
