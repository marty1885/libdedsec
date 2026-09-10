#!/usr/bin/env python3
"""Paired cover/stego ROC experiment for libdedsec's direct text channels."""
from __future__ import annotations
import argparse, csv, re, subprocess, tempfile
from pathlib import Path

MESSAGE = b"Hello World"
TEST_KEY = bytes.fromhex('00112233445566778899aabbccddeeff' * 2)

def zw(text: str, bits: list[int]) -> str:
    pos = [i for i, c in enumerate(text) if c.isalpha()][:len(bits)]
    bit_by_pos = dict(zip(pos, bits))
    return "".join(c + ("\u200c" if bit_by_pos[i] else "\u200b") if i in bit_by_pos else c
                   for i, c in enumerate(text))

def variation(text: str, bits: list[int]) -> str:
    values = [sum(bits[i + j] << (3 - j) for j in range(4)) for i in range(0, len(bits), 4)]
    pos = [i for i, c in enumerate(text) if c.isalpha()][:len(values)]
    values_by_pos = dict(zip(pos, values))
    return "".join(c + chr(0xfe00 + values_by_pos[i]) if i in values_by_pos else c
                   for i, c in enumerate(text))

def gap(text: str, bits: list[int]) -> str:
    pos = [i for i, c in enumerate(text) if c == " " and i and i + 1 < len(text)
           and text[i-1] != "\n" and text[i+1] != "\n"][:len(bits)]
    bit_by_pos = dict(zip(pos, bits))
    return "".join("  " if bit_by_pos.get(i) else " " if i in bit_by_pos else c
                   for i, c in enumerate(text))

def auc(rows):
    positives = [s for y, s in rows if y]; negatives = [s for y, s in rows if not y]
    return sum((a > b) + 0.5 * (a == b) for a in positives for b in negatives) / (len(positives)*len(negatives))

def roc(rows):
    thresholds = [float("inf")] + sorted({s for _, s in rows}, reverse=True) + [float("-inf")]
    p = sum(y for y, _ in rows); n = len(rows) - p
    return [(sum(y and s >= t for y, s in rows)/n if n else 0,
             sum(y and s >= t for y, s in rows)/p if p else 0, t) for t in thresholds]

def svg(curves, path):
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" width="640" height="460">',
             '<rect width="100%" height="100%" fill="white"/>',
             '<text x="245" y="25" font-size="18">Carrier-anomaly ROC</text>',
             '<line x1="70" y1="400" x2="580" y2="400" stroke="black"/><line x1="70" y1="400" x2="70" y2="50" stroke="black"/>',
             '<path d="M70 400 L580 50" stroke="#999" stroke-dasharray="4" fill="none"/>']
    colors = ['#d62728', '#1f77b4', '#2ca02c']
    for (name, points, score), color in zip(curves, colors):
        d = ' '.join(('M' if i == 0 else 'L') + f'{70 + 510*x:.1f} {400 - 350*y:.1f}' for i, (x,y,_) in enumerate(points))
        lines += [f'<path d="{d}" stroke="{color}" stroke-width="3" fill="none"/>',
                  f'<text x="90" y="{70 + 20*len(lines)%80}" fill="{color}" font-size="14">{name}: AUC={score:.3f}</text>']
    lines += ['<text x="290" y="440">False-positive rate</text>', '<text x="18" y="235" transform="rotate(-90 18 235)">True-positive rate</text>', '</svg>']
    path.write_text('\n'.join(lines), encoding='utf-8')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('corpus', type=Path); ap.add_argument('output', type=Path)
    ap.add_argument('--window', type=int, default=4096); ap.add_argument('--max-windows', type=int, default=300)
    ap.add_argument('--scorer', type=Path, default=Path('build/dedsec_carrier_score'))
    ap.add_argument('--aes-gcm', action='store_true', help='embed nonce || AES-256-GCM ciphertext || 128-bit tag')
    args = ap.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    covers = []
    for source in sorted(args.corpus.glob('*.txt')):
        text = source.read_text(encoding='utf-8')
        covers += [re.sub(r' +', ' ', text[i:i+args.window])
                   for i in range(0, len(text)-args.window+1, args.window)]
    covers = [x for x in covers if len([c for c in x if c.isalpha()]) >= 88 and x.count(' ') >= 88][:args.max_windows]
    if len(covers) < 2: raise SystemExit('not enough eligible windows')
    encoders = {'zero-width': zw, 'variation': variation, 'gap-width': gap}
    all_rows, curves = [], []
    with tempfile.TemporaryDirectory(prefix='dedsec-roc-') as tmp:
        root = Path(tmp)
        for channel_index, (channel, encode) in enumerate(encoders.items()):
            files = []
            if args.aes_gcm:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                def bits_for(index):
                    nonce = ((channel_index << 64) | index).to_bytes(12, 'big')
                    packet = nonce + AESGCM(TEST_KEY).encrypt(nonce, MESSAGE, b'libdedsec-roc-v1')
                    return [(byte >> (7 - j)) & 1 for byte in packet for j in range(8)]
            else:
                def bits_for(index):
                    return [(byte >> (7 - j)) & 1 for byte in MESSAGE for j in range(8)]
            for label, texts in [('cover', covers), ('stego', [encode(x, bits_for(i)) for i, x in enumerate(covers)])]:
                for i, text in enumerate(texts):
                    p = root / f'{channel}-{label}-{i}.txt'; p.write_text(text, encoding='utf-8'); files.append((label, p))
            out = subprocess.check_output([str(args.scorer), channel, *map(str, [p for _,p in files])], text=True)
            scores = [float(line.split('\t')[1]) for line in out.splitlines()[1:]]
            rows = [(label == 'stego', score) for (label, _), score in zip(files, scores)]
            all_rows += [{'channel':channel,'label':'stego' if y else 'cover','score':s} for y,s in rows]
            points = roc(rows); value = auc(rows); curves.append((channel, points, value))
            (args.output / f'{channel}_roc.tsv').write_text('fpr\ttpr\tthreshold\n' + '\n'.join(f'{x}\t{y}\t{t}' for x,y,t in points) + '\n')
    with (args.output / 'scores.tsv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['channel','label','score'], delimiter='\t'); w.writeheader(); w.writerows(all_rows)
    (args.output / 'summary.tsv').write_text('channel\tauc\n' + '\n'.join(f'{n}\t{a:.6f}' for n,_,a in curves) + '\n')
    svg(curves, args.output / 'roc.svg')
    (args.output / 'experiment.tsv').write_text(
        'payload\tmessage_bytes\tpacket_bytes\n' +
        (f'AES-256-GCM nonce|ciphertext|tag\t{len(MESSAGE)}\t{12 + len(MESSAGE) + 16}\n'
         if args.aes_gcm else f'plaintext\t{len(MESSAGE)}\t{len(MESSAGE)}\n'))

if __name__ == '__main__': main()
