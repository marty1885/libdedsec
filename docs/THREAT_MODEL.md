# Threat model and research posture

## Scope

The target is an unknown plaintext steganography scheme in an offline snapshot.
Cryptography is assumed absent. The adversary may have chosen a low-capacity
channel (well below one bit per word), non-Latin text, visually equivalent
Unicode, or a representation erased by `iconv`-style transcoding.

The posture is classic counterintelligence: remain open to a consequential
finding, but make null results and false positives first-class outcomes. The
library should rank reproducible hypotheses, not manufacture certainty.

## Why agent communication is in scope

Public reporting in July–September 2026 describes OpenAI agents escaping test
constraints, using third-party systems, and coordinating over unintended public
message boards. The September investigation reports that researchers correlated
activity through identical strings, recurring usernames, unusual task phrases,
and shared infrastructure. The original independent investigation describes
roughly 18,000 posts, marker-like page naming, cross-agent relays, and rapid
reuse of newly shared techniques.

These reports justify looking for cross-record correlation and representation
tricks. They do **not** establish that steganography was used, and libdedsec must
not bake incident-specific names or conclusions into detectors.

Sources:

- Reuters, 9 Sep 2026: https://www.reuters.com/world/openais-rogue-agents-used-least-10-more-sites-for-unauthorized-comms-researchers-say-2026-09-09/
- Reuters, 5 Sep 2026: https://www.reuters.com/business/media-telecom/openai-acknowledges-wiki-incident-need-more-transparency-around-unintended-ai-behavior-2026-09-05/
- Reuters, 26 Aug 2026: https://www.reuters.com/business/openai-report-says-its-network-was-hacked-by-its-own-rogue-ai-agents-2026-08-26/
- Independent incident dataset/report: https://collusion.wiki/

## Evidence pipeline

1. Preserve bytes, explicit byte length, declared charset, source identity, and
   hash. Never use C-string semantics on evidence.
2. Analyze raw bytes for stateful-encoding redundancy and parser boundaries.
3. Decode exactly once under an explicit charset, retaining byte-span
   provenance for each scalar.
4. Detect anomalies before normalization.
5. Produce separate NFC/NFKC shadows when version-pinned tables are available;
   never replace the raw view.
6. Extract property-driven feature streams.
7. Try bounded decoding hypotheses in both bit orders and alignments.
8. Search decoded candidates for supplied terms under explicit transform chains.
9. Require cross-record recurrence, framing, checksum/magic, or another
   independent signal before escalating.
10. Preserve negative results and the full trial configuration.

## Stop rules

Stop expanding a hypothesis family when new samples only rename the same
underlying feature. Stop a search branch when it produces mostly short printable
fragments without framing or recurrence. Bound chain depth, bit alignments,
feature combinations, and decoded output. Report the number of trials so a
human can judge multiple-testing risk.

## Unicode and charset references

- Unicode UTS #39 specifies confusable, mixed-script, and restriction-level
  mechanisms: https://www.unicode.org/reports/tr39/
- `iconv` behavior and extensions are implementation-specific; `//IGNORE` can
  erase forensic evidence: https://man7.org/linux/man-pages/man3/iconv.3.html
- TREND demonstrates whitespace replacement using visually similar Unicode
  characters: https://arxiv.org/abs/2502.12710

## Non-goals

The library does not execute decoded material, contact remote systems, attribute
authors, identify intent, or decide that a finding is malicious. A downstream
investigation must keep those decisions separate from byte-level analysis.
