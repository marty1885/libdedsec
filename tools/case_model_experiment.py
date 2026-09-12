#!/usr/bin/env python3
"""Paired raw-KT and bounded-PPM experiment for word-initial case lanes."""

import argparse
import hashlib
import math
from collections import defaultdict


def case_events(data):
    events = []
    i = 0
    while i < len(data):
        byte = data[i]
        if not (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57 or byte >= 128):
            i += 1
            continue
        start = i
        while i < len(data):
            byte = data[i]
            if not (65 <= byte <= 90 or 97 <= byte <= 122 or 48 <= byte <= 57 or byte >= 128):
                break
            i += 1
        first = data[start]
        if 65 <= first <= 90:
            events.append((start, 1))
        elif 97 <= first <= 122:
            events.append((start, 0))
    return events


def synthetic_bits(count, seed):
    output = []
    counter = 0
    while len(output) < count:
        block = hashlib.sha256(seed.encode("utf-8") + counter.to_bytes(8, "big")).digest()
        for byte in block:
            for shift in range(7, -1, -1):
                output.append((byte >> shift) & 1)
                if len(output) == count:
                    return output
        counter += 1
    return output


def kt_cost(bits, order):
    counts = defaultdict(lambda: [0, 0])
    cost = 0.0
    for i, bit in enumerate(bits):
        context = tuple(bits[max(0, i - order):i])
        row = counts[context]
        probability = (row[bit] + 0.5) / (row[0] + row[1] + 1.0)
        cost -= math.log2(probability)
        row[bit] += 1
    return cost


def ppm_cost(bits, depth):
    """PPM-style longest-context coding with method-C-like escapes.

    Orders >=1 encode a previously observed symbol directly, or emit an
    escape and back off. Order zero uses a KT binary distribution so both
    symbols always retain support. All tables and work are depth-bounded.
    """
    tables = [defaultdict(lambda: [0, 0]) for _ in range(depth + 1)]
    cost = 0.0
    for i, bit in enumerate(bits):
        encoded = False
        for order in range(min(depth, i), 0, -1):
            context = tuple(bits[i - order:i])
            row = tables[order][context]
            total = row[0] + row[1]
            if not total:
                continue
            distinct = int(row[0] > 0) + int(row[1] > 0)
            denominator = total + distinct
            if row[bit]:
                cost -= math.log2(row[bit] / denominator)
                encoded = True
                break
            cost -= math.log2(distinct / denominator)
        if not encoded:
            row = tables[0][()]
            cost -= math.log2((row[bit] + 0.5) / (row[0] + row[1] + 1.0))
        for order in range(0, min(depth, i) + 1):
            context = tuple(bits[i - order:i]) if order else ()
            tables[order][context][bit] += 1
    return cost


def report(path, label, bits, orders, depths):
    ones = sum(bits)
    for order in orders:
        cost = kt_cost(bits, order)
        print(f"{path}\t{label}\tkt\t{order}\t{len(bits)}\t{ones}\t{cost:.3f}\t{cost/len(bits):.6f}")
    for depth in depths:
        cost = ppm_cost(bits, depth)
        print(f"{path}\t{label}\tppm\t{depth}\t{len(bits)}\t{ones}\t{cost:.3f}\t{cost/len(bits):.6f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument("--seed", default="libdedsec-case-control-v1")
    parser.add_argument("--orders", default="0,1,2,4,8,12")
    parser.add_argument("--depths", default="4,8,12,16")
    args = parser.parse_args()
    orders = [int(value) for value in args.orders.split(",")]
    depths = [int(value) for value in args.depths.split(",")]
    print("file\tstream\tmodel\torder_or_depth\tbits\tones\tcode_bits\tbits_per_bit")
    for path in args.files:
        with open(path, "rb") as source:
            data = source.read()
        events = case_events(data)
        observed = [bit for _, bit in events]
        if not observed:
            continue
        randomized = synthetic_bits(len(observed), args.seed + "\0" + path)
        report(path, "observed", observed, orders, depths)
        report(path, "randomized-case-control", randomized, orders, depths)


if __name__ == "__main__":
    main()
