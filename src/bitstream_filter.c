#include "internal.h"

#include <string.h>

#define FILTER_MAX_DEPTH 2u
#define FILTER_MIN_BYTES 6u

typedef struct filter_best {
    dedsec_bitstream_filter_result result;
} filter_best;

static int ignore_scalar(void *user, const dedsec_scalar *scalar) {
    (void)user;
    (void)scalar;
    return 0;
}

static int ascii_alpha(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int ascii_punctuation(uint8_t c) {
    return (c >= 0x21 && c <= 0x2f) || (c >= 0x3a && c <= 0x40) ||
           (c >= 0x5b && c <= 0x60) || (c >= 0x7b && c <= 0x7e);
}

static uint8_t ascii_lower(uint8_t c) {
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
}

static int vowel(uint8_t c) {
    c = ascii_lower(c);
    return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y';
}

static int common_pair(uint8_t a, uint8_t b) {
    static const char pairs[] =
        "thheineranreonatenndtiesorteofedisitalarsttontngsehaasou"
        "iolevecodemehiriroicneearacelichllbemasiomurwopa";
    size_t i;
    a = ascii_lower(a);
    b = ascii_lower(b);
    for (i = 0; i + 1 < sizeof(pairs) - 1; i += 2)
        if ((uint8_t)pairs[i] == a && (uint8_t)pairs[i + 1] == b) return 1;
    return 0;
}

static uint32_t plaintext_score(dedsec_view input, uint32_t *text_flags) {
    size_t i, alpha = 0, vowels = 0, whitespace = 0, punctuation = 0;
    size_t high = 0, common = 0, letter_pairs = 0;
    uint32_t score = 0;
    double alpha_fraction, vowel_fraction, whitespace_fraction, punctuation_fraction;
    int previous_alpha = 0;
    uint8_t previous = 0;

    *text_flags = 0;
    if (input.len < FILTER_MIN_BYTES) return 0;
    if (dedsec_utf8_foreach(input, ignore_scalar, NULL, NULL) != DEDSEC_OK) return 0;
    *text_flags |= DEDSEC_PLAINTEXT_UTF8;

    for (i = 0; i < input.len; ++i) {
        uint8_t c = input.ptr[i];
        if (c >= 0x80) {
            ++high;
            previous_alpha = 0;
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++whitespace;
            previous_alpha = 0;
        } else if (c < 0x20 || c == 0x7f) {
            return 0;
        } else if (ascii_alpha(c)) {
            ++alpha;
            if (vowel(c)) ++vowels;
            if (previous_alpha) {
                ++letter_pairs;
                if (common_pair(previous, c)) ++common;
            }
            previous = c;
            previous_alpha = 1;
        } else {
            if (ascii_punctuation(c)) ++punctuation;
            previous_alpha = 0;
        }
    }

    if (!high) *text_flags |= DEDSEC_PLAINTEXT_ASCII;
    alpha_fraction = (double)alpha / (double)input.len;
    vowel_fraction = alpha ? (double)vowels / (double)alpha : 0.0;
    whitespace_fraction = (double)whitespace / (double)input.len;
    punctuation_fraction = (double)punctuation / (double)input.len;
    score = 40; /* Strict UTF-8 with no forbidden control bytes. */
    if (input.len >= 8) score += 5;
    if (alpha_fraction >= 0.45) score += 10;
    if (alpha && vowel_fraction >= 0.15 && vowel_fraction <= 0.60) score += 10;
    if (whitespace && whitespace_fraction <= 0.35) score += 15;
    if (common >= 2 && (!letter_pairs || (double)common / (double)letter_pairs >= 0.20))
        score += 20;
    else if (common) score += 10;
    if (punctuation_fraction <= 0.25) score += 5;
    if (high && input.len >= 8) score += 15;
    return score > 100 ? 100 : score;
}

static int hex_value(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_base16(dedsec_view input, dedsec_buffer *output) {
    size_t i;
    if (input.len < 12 || input.len % 2) return 0;
    for (i = 0; i < input.len; i += 2) {
        int hi = hex_value(input.ptr[i]), lo = hex_value(input.ptr[i + 1]);
        if (hi < 0 || lo < 0) return 0;
        if (dedsec_buffer_push(output, (uint8_t)((hi << 4) | lo)) != DEDSEC_OK) return -1;
    }
    return 1;
}

static int base32_value(uint8_t c, int hex) {
    c = ascii_lower(c);
    if (hex) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'v') return c - 'a' + 10;
    } else {
        if (c >= 'a' && c <= 'z') return c - 'a';
        if (c >= '2' && c <= '7') return c - '2' + 26;
    }
    return -1;
}

static int decode_base32(dedsec_view input, dedsec_buffer *output, int hex) {
    size_t i, symbols = 0, pads = 0, remainder;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    int seen_pad = 0;
    if (input.len < 8) return 0;
    for (i = 0; i < input.len; ++i) {
        int value;
        if (input.ptr[i] == '=') {
            seen_pad = 1;
            ++pads;
            continue;
        }
        value = base32_value(input.ptr[i], hex);
        if (seen_pad || value < 0) return 0;
        ++symbols;
        accumulator = (accumulator << 5) | (uint32_t)value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (dedsec_buffer_push(output, (uint8_t)(accumulator >> bits)) != DEDSEC_OK)
                return -1;
            accumulator &= bits ? (1u << bits) - 1u : 0u;
        }
    }
    remainder = symbols % 8;
    if (!(remainder == 0 || remainder == 2 || remainder == 4 ||
          remainder == 5 || remainder == 7)) return 0;
    if (pads) {
        size_t expected = remainder == 2 ? 6 : remainder == 4 ? 4 :
                          remainder == 5 ? 3 : remainder == 7 ? 1 : 0;
        if (input.len % 8 || pads != expected) return 0;
    }
    if (accumulator != 0) return 0; /* Reject non-canonical unused tail bits. */
    return output->len ? 1 : 0;
}

static int base64_value(uint8_t c, int url) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if ((!url && c == '+') || (url && c == '-')) return 62;
    if ((!url && c == '/') || (url && c == '_')) return 63;
    return -1;
}

static int decode_base64(dedsec_view input, dedsec_buffer *output, int url) {
    size_t i, symbols = 0, pads = 0, remainder;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    int seen_pad = 0;
    if (input.len < 8) return 0;
    for (i = 0; i < input.len; ++i) {
        int value;
        if (input.ptr[i] == '=') {
            seen_pad = 1;
            ++pads;
            continue;
        }
        value = base64_value(input.ptr[i], url);
        if (seen_pad || value < 0) return 0;
        ++symbols;
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (dedsec_buffer_push(output, (uint8_t)(accumulator >> bits)) != DEDSEC_OK)
                return -1;
            accumulator &= bits ? (1u << bits) - 1u : 0u;
        }
    }
    remainder = symbols % 4;
    if (remainder == 1) return 0;
    if (pads) {
        size_t expected = remainder == 2 ? 2 : remainder == 3 ? 1 : 0;
        if (input.len % 4 || pads != expected) return 0;
    }
    if (accumulator != 0) return 0;
    return output->len ? 1 : 0;
}

static int result_better(const dedsec_bitstream_filter_result *candidate,
                         const dedsec_bitstream_filter_result *best) {
    if (!best->decoded_length) return 1;
    if (candidate->score != best->score) return candidate->score > best->score;
    if (candidate->transform_depth != best->transform_depth)
        return candidate->transform_depth < best->transform_depth;
    return candidate->flags < best->flags;
}

static dedsec_status assess_bytes(dedsec_view input, unsigned depth,
                                  uint32_t inherited_flags, unsigned bit_offset,
                                  filter_best *best) {
    dedsec_bitstream_filter_result candidate;
    dedsec_buffer decoded;
    uint32_t text_flags = 0;
    uint32_t score = plaintext_score(input, &text_flags);
    int decoded_ok, encoding_valid = 0;

    memset(&candidate, 0, sizeof(candidate));
    candidate.score = score;
    if (bit_offset && candidate.score >= 5) candidate.score -= 5;
    if ((inherited_flags & DEDSEC_PLAINTEXT_BIT_REVERSED) && candidate.score >= 5)
        candidate.score -= 5;
    if ((inherited_flags & DEDSEC_PLAINTEXT_BIT_INVERTED) && candidate.score >= 5)
        candidate.score -= 5;
    candidate.flags = inherited_flags | text_flags;
    candidate.bit_offset = bit_offset;
    candidate.transform_depth = depth;
    candidate.decoded_length = input.len;
    if (depth >= FILTER_MAX_DEPTH) {
        if (result_better(&candidate, &best->result)) best->result = candidate;
        return DEDSEC_OK;
    }

#define TRY_DECODE(call_, flag_) do { \
    dedsec_buffer_init(&decoded); \
    decoded_ok = (call_); \
    if (decoded_ok < 0) { dedsec_buffer_free(&decoded); return DEDSEC_ENOMEM; } \
    if (decoded_ok > 0) { \
        encoding_valid = 1; \
        dedsec_status recurse_status = assess_bytes((dedsec_view){decoded.ptr, decoded.len}, \
            depth + 1, inherited_flags | (flag_), bit_offset, best); \
        dedsec_buffer_free(&decoded); \
        if (recurse_status != DEDSEC_OK) return recurse_status; \
    } else dedsec_buffer_free(&decoded); \
} while (0)

    TRY_DECODE(decode_base16(input, &decoded), DEDSEC_PLAINTEXT_BASE16);
    TRY_DECODE(decode_base32(input, &decoded, 0), DEDSEC_PLAINTEXT_BASE32);
    TRY_DECODE(decode_base32(input, &decoded, 1), DEDSEC_PLAINTEXT_BASE32HEX);
    TRY_DECODE(decode_base64(input, &decoded, 0), DEDSEC_PLAINTEXT_BASE64);
    TRY_DECODE(decode_base64(input, &decoded, 1), DEDSEC_PLAINTEXT_BASE64URL);
#undef TRY_DECODE
    /* A canonical dense radix token is evidence of an encoding, not evidence
     * that its printable wrapper is prose. Its decoded content must pass. */
    if (encoding_valid && candidate.score > 60) candidate.score = 60;
    if (result_better(&candidate, &best->result)) best->result = candidate;
    return DEDSEC_OK;
}

static unsigned stream_bit(const dedsec_bitstream *stream, size_t index) {
    return (stream->bytes.ptr[index / 8] >> (7u - (unsigned)(index % 8))) & 1u;
}

static dedsec_status make_interpretation(const dedsec_bitstream *stream,
                                         unsigned offset, int reverse, int invert,
                                         dedsec_buffer *bytes) {
    size_t count = (stream->bit_length - offset) / 8;
    size_t i;
    for (i = 0; i < count; ++i) {
        unsigned k;
        uint8_t value = 0;
        size_t base = offset + i * 8;
        for (k = 0; k < 8; ++k) {
            size_t source = base + (reverse ? 7u - k : k);
            unsigned bit = stream_bit(stream, source) ^ (unsigned)invert;
            value |= (uint8_t)(bit << (7u - k));
        }
        if (dedsec_buffer_push(bytes, value) != DEDSEC_OK) return DEDSEC_ENOMEM;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_filter(const dedsec_bitstream *stream,
                                      dedsec_bitstream_filter_result *result) {
    filter_best best;
    size_t required;
    unsigned offset;
    int reverse, invert;
    if (!stream || !result || (!stream->bytes.ptr && stream->bit_length))
        return DEDSEC_EINVAL;
    if (stream->bit_length > SIZE_MAX - 7) return DEDSEC_EINVAL;
    required = (stream->bit_length + 7) / 8;
    if (stream->bytes.len < required) return DEDSEC_EINVAL;
    memset(&best, 0, sizeof(best));
    best.result.verdict = DEDSEC_PLAINTEXT_INSUFFICIENT;
    for (offset = 0; offset < 8 && offset < stream->bit_length; ++offset) {
        if ((stream->bit_length - offset) / 8 < FILTER_MIN_BYTES) continue;
        for (reverse = 0; reverse <= 1; ++reverse) {
            for (invert = 0; invert <= 1; ++invert) {
                dedsec_buffer bytes;
                uint32_t flags = (reverse ? DEDSEC_PLAINTEXT_BIT_REVERSED : 0u) |
                                 (invert ? DEDSEC_PLAINTEXT_BIT_INVERTED : 0u);
                dedsec_status status;
                dedsec_buffer_init(&bytes);
                status = make_interpretation(stream, offset, reverse, invert, &bytes);
                if (status == DEDSEC_OK)
                    status = assess_bytes((dedsec_view){bytes.ptr, bytes.len}, 0,
                                          flags, offset, &best);
                dedsec_buffer_free(&bytes);
                if (status != DEDSEC_OK) return status;
            }
        }
    }
    if (best.result.decoded_length < FILTER_MIN_BYTES) {
        best.result.verdict = DEDSEC_PLAINTEXT_INSUFFICIENT;
    } else if (best.result.score >= 90) {
        best.result.verdict = DEDSEC_PLAINTEXT_LIKELY;
    } else if (best.result.score >= 70) {
        best.result.verdict = DEDSEC_PLAINTEXT_POSSIBLE;
    } else {
        best.result.verdict = DEDSEC_PLAINTEXT_REJECT;
    }
    *result = best.result;
    return DEDSEC_OK;
}
