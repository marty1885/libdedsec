#include "internal.h"

#define FILTER_MAX_DEPTH 2u
#define FILTER_MIN_BYTES 6u

typedef struct filter_best {
    dedsec_bitstream_filter_result result;
    size_t equal_score_interpretations;
    int has_result;
} filter_best;

typedef struct scalar_check {
    int forbidden_control;
} scalar_check;

typedef struct filter_path {
    uint32_t flags;
    unsigned encoding_depth;
    unsigned transform_count;
    dedsec_filter_transform transforms[DEDSEC_FILTER_MAX_TRANSFORMS];
} filter_path;

typedef struct filter_source {
    size_t bit_length;
    size_t complete_bits;
    unsigned bit_offset;
    unsigned tail_bits;
    unsigned tail_ones;
} filter_source;

static int check_scalar(void *user, const dedsec_scalar *scalar) {
    scalar_check *check = (scalar_check *)user;
    if ((scalar->value <= 0x1fu && scalar->value != '\t' &&
         scalar->value != '\n' && scalar->value != '\r') ||
        (scalar->value >= 0x7fu && scalar->value <= 0x9fu))
        check->forbidden_control = 1;
    return 0;
}

static unsigned byte_popcount(uint8_t value) {
    unsigned count = 0;
    while (value) {
        count += value & 1u;
        value = (uint8_t)(value >> 1);
    }
    return count;
}

/* Opaque high-entropy-looking bytes cannot be distinguished here from
 * ciphertext, compressed data, or random noise. Preserve them for backend
 * review when they are long, bit-balanced, and byte-diverse; this is a routing
 * decision, never an attribution or payload claim. */
static int looks_like_opaque_data(dedsec_view input, unsigned tail_ones,
                                  unsigned tail_bits) {
    uint32_t seen[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    size_t i, unique = 0, ones = 0, bits;
    if (input.len < 16u || input.len > (SIZE_MAX - tail_bits) / 8u) return 0;
    for (i = 0; i < input.len; ++i) {
        unsigned bucket = input.ptr[i] >> 5;
        uint32_t mask = (uint32_t)1u << (input.ptr[i] & 31u);
        ones += byte_popcount(input.ptr[i]);
        if (!(seen[bucket] & mask)) {
            seen[bucket] |= mask;
            ++unique;
        }
    }
    ones += tail_ones;
    bits = input.len * 8u + tail_bits;
    return unique >= 8u && ones >= bits / 4u && ones <= bits - bits / 4u;
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
    scalar_check check = {0};

    *text_flags = 0;
    if (input.len < FILTER_MIN_BYTES) return 0;
    if (dedsec_utf8_foreach(input, check_scalar, &check, NULL) != DEDSEC_OK ||
        check.forbidden_control) return 0;
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
    /* Strict UTF-8 alone supplies no bonus. Non-ASCII text must qualify from
     * the same surrounding word/whitespace evidence as ASCII text; this keeps
     * a lone accidental scalar at a shifted bit phase below LIKELY. */
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

static int path_append(filter_path *path, dedsec_filter_transform transform) {
    if (path->transform_count >= DEDSEC_FILTER_MAX_TRANSFORMS) return 0;
    path->transforms[path->transform_count++] = transform;
    return 1;
}

static unsigned bit_transform_count(const dedsec_bitstream_filter_result *result) {
    unsigned i, count = 0;
    for (i = 0; i < result->transform_count; ++i)
        if (result->transforms[i] == DEDSEC_FILTER_TRANSFORM_REVERSE_BITS ||
            result->transforms[i] == DEDSEC_FILTER_TRANSFORM_INVERT_BITS)
            ++count;
    return count;
}

static int result_better(const dedsec_bitstream_filter_result *candidate,
                         const dedsec_bitstream_filter_result *best) {
    unsigned candidate_bit_ops, best_bit_ops;
    if (candidate->score != best->score) return candidate->score > best->score;
    if (candidate->bit_offset != best->bit_offset)
        return candidate->bit_offset < best->bit_offset;
    if (candidate->source_bits_consumed != best->source_bits_consumed)
        return candidate->source_bits_consumed > best->source_bits_consumed;
    candidate_bit_ops = bit_transform_count(candidate);
    best_bit_ops = bit_transform_count(best);
    if (candidate_bit_ops != best_bit_ops) return candidate_bit_ops < best_bit_ops;
    if (candidate->transform_depth != best->transform_depth)
        return candidate->transform_depth > best->transform_depth;
    if ((candidate->flags & DEDSEC_PLAINTEXT_OPAQUE_DATA) !=
        (best->flags & DEDSEC_PLAINTEXT_OPAQUE_DATA))
        return (candidate->flags & DEDSEC_PLAINTEXT_OPAQUE_DATA) != 0;
    return 0;
}

static void consider_result(filter_best *best,
                            const dedsec_bitstream_filter_result *candidate) {
    if (!best->has_result || candidate->score > best->result.score) {
        best->result = *candidate;
        best->equal_score_interpretations = 1;
        best->has_result = 1;
        return;
    }
    if (candidate->score == best->result.score) {
        ++best->equal_score_interpretations;
        if (result_better(candidate, &best->result)) best->result = *candidate;
    }
}

static dedsec_status assess_variants(dedsec_view input, filter_path path,
                                     const filter_source *source,
                                     filter_best *best);

static dedsec_status assess_bytes(dedsec_view input, filter_path path,
                                  const filter_source *source,
                                  filter_best *best) {
    dedsec_bitstream_filter_result candidate = {0};
    dedsec_buffer decoded;
    uint32_t text_flags = 0;
    uint32_t score = plaintext_score(input, &text_flags);
    int decoded_ok, encoding_valid = 0;
    unsigned tail_bits = path.encoding_depth == 0 ? source->tail_bits : 0u;
    unsigned tail_ones = path.encoding_depth == 0 ? source->tail_ones : 0u;

    candidate.score = score;
    if (source->bit_offset && candidate.score >= 5) candidate.score -= 5;
    if ((path.flags & DEDSEC_PLAINTEXT_BIT_REVERSED) && candidate.score >= 5)
        candidate.score -= 5;
    if ((path.flags & DEDSEC_PLAINTEXT_BIT_INVERTED) && candidate.score >= 5)
        candidate.score -= 5;
    candidate.flags = path.flags | text_flags;
    if (source->tail_bits) candidate.flags |= DEDSEC_PLAINTEXT_PARTIAL_BITS;
    candidate.bit_offset = source->bit_offset;
    candidate.transform_depth = path.encoding_depth;
    candidate.decoded_length = input.len;
    candidate.source_bit_length = source->bit_length;
    candidate.source_bits_consumed = source->complete_bits;
    candidate.ignored_trailing_bits = source->tail_bits;
    candidate.transform_count = path.transform_count;
    if (path.transform_count) {
        unsigned i;
        for (i = 0; i < path.transform_count; ++i)
            candidate.transforms[i] = path.transforms[i];
    }

    /* Opaque routing is an independent qualification, not weak plaintext.
     * Alignment and bit-transform penalties may rank candidates, but must not
     * turn qualifying data into REJECT. At depth zero, partial trailing bits
     * participate in bit balance even though they cannot form a byte. */
    if (candidate.score < 70u &&
        looks_like_opaque_data(input, tail_ones, tail_bits)) {
        candidate.score = 70u;
        candidate.flags |= DEDSEC_PLAINTEXT_OPAQUE_DATA;
        if (path.encoding_depth == 0 && source->tail_bits) {
            candidate.source_bits_consumed += source->tail_bits;
            candidate.ignored_trailing_bits = 0;
            candidate.assessed_trailing_bits = source->tail_bits;
        }
    }

    if (path.encoding_depth >= FILTER_MAX_DEPTH) {
        consider_result(best, &candidate);
        return DEDSEC_OK;
    }

#define TRY_DECODE(call_, flag_, transform_) do { \
    dedsec_buffer_init(&decoded); \
    decoded_ok = (call_); \
    if (decoded_ok < 0) { dedsec_buffer_free(&decoded); return DEDSEC_ENOMEM; } \
    if (decoded_ok > 0) { \
        filter_path next_path = path; \
        encoding_valid = 1; \
        dedsec_status recurse_status; \
        next_path.flags |= (flag_); \
        ++next_path.encoding_depth; \
        if (!path_append(&next_path, (transform_))) { \
            dedsec_buffer_free(&decoded); return DEDSEC_EINVAL; \
        } \
        recurse_status = assess_variants((dedsec_view){decoded.ptr, decoded.len}, \
                                         next_path, source, best); \
        dedsec_buffer_free(&decoded); \
        if (recurse_status != DEDSEC_OK) return recurse_status; \
    } else dedsec_buffer_free(&decoded); \
} while (0)

    TRY_DECODE(decode_base16(input, &decoded), DEDSEC_PLAINTEXT_BASE16,
               DEDSEC_FILTER_TRANSFORM_BASE16);
    TRY_DECODE(decode_base32(input, &decoded, 0), DEDSEC_PLAINTEXT_BASE32,
               DEDSEC_FILTER_TRANSFORM_BASE32);
    TRY_DECODE(decode_base32(input, &decoded, 1), DEDSEC_PLAINTEXT_BASE32HEX,
               DEDSEC_FILTER_TRANSFORM_BASE32HEX);
    TRY_DECODE(decode_base64(input, &decoded, 0), DEDSEC_PLAINTEXT_BASE64,
               DEDSEC_FILTER_TRANSFORM_BASE64);
    TRY_DECODE(decode_base64(input, &decoded, 1), DEDSEC_PLAINTEXT_BASE64URL,
               DEDSEC_FILTER_TRANSFORM_BASE64URL);
#undef TRY_DECODE
    /* A canonical dense radix token is evidence of an encoding, not evidence
     * that its printable wrapper is prose. Its decoded content must pass. */
    if (encoding_valid && candidate.score > 60u &&
        !(candidate.flags & DEDSEC_PLAINTEXT_OPAQUE_DATA)) {
        candidate.score = 60u;
    }
    consider_result(best, &candidate);
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

static dedsec_status make_byte_variant(dedsec_view input, int reverse, int invert,
                                       dedsec_buffer *bytes) {
    size_t i;
    for (i = 0; i < input.len; ++i) {
        unsigned k;
        uint8_t value = 0;
        for (k = 0; k < 8; ++k) {
            unsigned source = reverse ? 7u - k : k;
            unsigned bit = ((input.ptr[i] >> (7u - source)) & 1u) ^
                           (unsigned)invert;
            value |= (uint8_t)(bit << (7u - k));
        }
        if (dedsec_buffer_push(bytes, value) != DEDSEC_OK) return DEDSEC_ENOMEM;
    }
    return DEDSEC_OK;
}

static dedsec_status assess_variants(dedsec_view input, filter_path path,
                                     const filter_source *source,
                                     filter_best *best) {
    int reverse, invert;
    dedsec_status status = assess_bytes(input, path, source, best);
    if (status != DEDSEC_OK) return status;
    for (reverse = 0; reverse <= 1; ++reverse) {
        for (invert = 0; invert <= 1; ++invert) {
            dedsec_buffer bytes;
            filter_path next_path = path;
            if (!reverse && !invert) continue;
            if (reverse) {
                next_path.flags |= DEDSEC_PLAINTEXT_BIT_REVERSED;
                if (!path_append(&next_path,
                                 DEDSEC_FILTER_TRANSFORM_REVERSE_BITS))
                    return DEDSEC_EINVAL;
            }
            if (invert) {
                next_path.flags |= DEDSEC_PLAINTEXT_BIT_INVERTED;
                if (!path_append(&next_path,
                                 DEDSEC_FILTER_TRANSFORM_INVERT_BITS))
                    return DEDSEC_EINVAL;
            }
            dedsec_buffer_init(&bytes);
            status = make_byte_variant(input, reverse, invert, &bytes);
            if (status == DEDSEC_OK)
                status = assess_bytes((dedsec_view){bytes.ptr, bytes.len},
                                      next_path, source, best);
            dedsec_buffer_free(&bytes);
            if (status != DEDSEC_OK) return status;
        }
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_filter(const dedsec_bitstream *stream,
                                      dedsec_bitstream_filter_result *result) {
    filter_best best = {0};
    size_t required;
    unsigned offset;
    int reverse, invert;
    if (!stream || !result || (!stream->bytes.ptr && stream->bit_length))
        return DEDSEC_EINVAL;
    if (stream->bit_length > SIZE_MAX - 7) return DEDSEC_EINVAL;
    required = (stream->bit_length + 7) / 8;
    if (stream->bytes.len != required || stream->bytes.len > stream->bytes.capacity)
        return DEDSEC_EINVAL;
    if (stream->bit_length % 8u) {
        unsigned unused = 8u - (unsigned)(stream->bit_length % 8u);
        uint8_t mask = (uint8_t)((1u << unused) - 1u);
        if (stream->bytes.ptr[required - 1u] & mask) return DEDSEC_EINVAL;
    }
    best.result.verdict = DEDSEC_PLAINTEXT_INSUFFICIENT;
    for (offset = 0; offset < 8 && offset < stream->bit_length; ++offset) {
        filter_source source;
        if ((stream->bit_length - offset) / 8 < FILTER_MIN_BYTES) continue;
        source.bit_length = stream->bit_length;
        source.bit_offset = offset;
        source.complete_bits = ((stream->bit_length - offset) / 8u) * 8u;
        source.tail_bits = (unsigned)((stream->bit_length - offset) % 8u);
        for (reverse = 0; reverse <= 1; ++reverse) {
            for (invert = 0; invert <= 1; ++invert) {
                dedsec_buffer bytes;
                filter_path path = {0};
                dedsec_status status;
                size_t tail_start, tail_index;
                source.tail_ones = 0;
                tail_start = offset + source.complete_bits;
                for (tail_index = tail_start;
                     tail_index < stream->bit_length; ++tail_index)
                    source.tail_ones += stream_bit(stream, tail_index);
                if (invert) source.tail_ones = source.tail_bits - source.tail_ones;
                if (reverse) {
                    path.flags |= DEDSEC_PLAINTEXT_BIT_REVERSED;
                    (void)path_append(&path, DEDSEC_FILTER_TRANSFORM_REVERSE_BITS);
                }
                if (invert) {
                    path.flags |= DEDSEC_PLAINTEXT_BIT_INVERTED;
                    (void)path_append(&path, DEDSEC_FILTER_TRANSFORM_INVERT_BITS);
                }
                dedsec_buffer_init(&bytes);
                status = make_interpretation(stream, offset, reverse, invert, &bytes);
                if (status == DEDSEC_OK)
                    status = assess_bytes((dedsec_view){bytes.ptr, bytes.len},
                                          path, &source, &best);
                dedsec_buffer_free(&bytes);
                if (status != DEDSEC_OK) return status;
            }
        }
    }
    if (!best.has_result || best.result.decoded_length < FILTER_MIN_BYTES) {
        best.result.verdict = DEDSEC_PLAINTEXT_INSUFFICIENT;
    } else if (best.result.score >= 90) {
        best.result.verdict = DEDSEC_PLAINTEXT_LIKELY;
    } else if (best.result.score >= 70) {
        best.result.verdict = DEDSEC_PLAINTEXT_POSSIBLE;
    } else {
        best.result.verdict = DEDSEC_PLAINTEXT_REJECT;
    }
    best.result.equal_score_interpretations = best.equal_score_interpretations;
    *result = best.result;
    return DEDSEC_OK;
}
