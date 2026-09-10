# AES-GCM carrier-detection experiment

This repeats the paired direct-carrier ROC experiment with the plaintext
`Hello World` protected by AES-256-GCM. Each embedded packet is:

```text
96-bit nonce || 11-byte ciphertext || 128-bit authentication tag
```

for 39 bytes / 312 embedded bits. The experiment uses a fixed test key and a
unique deterministic 96-bit nonce per generated packet. It is test material,
not an encryption API or a production key-management design.

## Run

```sh
cmake -S . -B build -DDEDSEC_BUILD_TOOLS=ON && cmake --build build
python3 tools/roc_experiment.py corpus/gutenberg research/roc_aes_gcm \
  --max-windows 300 --aes-gcm
```

## Result, 2026-09-10

There are 300 clean and 300 paired AES-GCM stego windows for each carrier.

| Carrier | AUC | Clean maximum | Stego score range |
|---|---:|---:|---:|
| Zero-width | 1.000000 | 0 | 312–312 |
| Variation selector | 1.000000 | 0 | 78–78 |
| Gap width | 1.000000 | 0 | 89–131 |

The command generates the chart and raw numbers under `research/roc_aes_gcm`.
The `research/` tree is deliberately ignored; retain or archive those artifacts
separately when an experiment must be audited.
Encryption does not lower detection performance for these direct carriers: the
observable number of added Unicode symbols or alternate gaps is still large.
It only removes plaintext readability as a post-extraction confirmation signal.

With the correct key, nonce handling, and associated data, a successful GCM tag
verification is the strong confirmation stage. For a full 128-bit tag, a random
tag guess for specified data has probability `2^-128`, approximately
`2.94e-39`, per attempt. Across the 900 generated stego candidates in this
experiment, a simple union bound is about `2.64e-36`; this is not the carrier
false-positive rate. NIST notes that GCM targeted-forgery bounds also depend on
the authenticated ciphertext/AAD length and that implementations must enforce
nonce uniqueness and limit failed verification attempts. See [NIST SP
800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

Without a key, no comparable payload-validation number exists: a correctly
extracted AES-GCM packet and arbitrary random bits can both look random. In
that setting, report only the carrier-level ROC score.
