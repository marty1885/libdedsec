#include "internal.h"

static dedsec_status emit_one(dedsec_feature_fn emit, void *user,
                              int64_t value, size_t off, size_t len) {
    dedsec_feature f;
    f.value = value; f.byte_offset = off; f.byte_length = len;
    return emit(user, &f) ? DEDSEC_ESTOP : DEDSEC_OK;
}

static int ascii_word(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c >= 0x80;
}

typedef struct scalar_feature_bridge {
    dedsec_feature_fn fn;
    void *user;
} scalar_feature_bridge;

static int scalar_to_feature(void *opaque, const dedsec_scalar *scalar) {
    scalar_feature_bridge *b = (scalar_feature_bridge *)opaque;
    dedsec_feature f;
    f.value = (int64_t)scalar->value;
    f.byte_offset = scalar->byte_offset;
    f.byte_length = scalar->byte_length;
    return b->fn(b->user, &f);
}

static int validate_scalar(void *opaque, const dedsec_scalar *scalar) {
    (void)opaque; (void)scalar; return 0;
}

dedsec_status dedsec_extract_features(dedsec_feature_kind kind,
                                      dedsec_view input,
                                      dedsec_feature_fn emit, void *user) {
    size_t i = 0;
    dedsec_status s;
    if ((!input.ptr && input.len) || !emit) return DEDSEC_EINVAL;
    if (kind == DEDSEC_FEATURE_WORD_CODEPOINTS) {
        dedsec_status valid = dedsec_utf8_foreach(input, validate_scalar, NULL, NULL);
        if (valid != DEDSEC_OK) return valid;
    }
    if (kind == DEDSEC_FEATURE_CODEPOINT) {
        scalar_feature_bridge bridge = { emit, user };
        return dedsec_utf8_foreach(input, scalar_to_feature, &bridge, NULL);
    }
    while (i < input.len) {
        size_t start, end, count;
        if (kind == DEDSEC_FEATURE_LINE_BYTES || kind == DEDSEC_FEATURE_TRAILING_HSPACE) {
            start = i;
            while (i < input.len && input.ptr[i] != '\n') ++i;
            end = i;
            if (end > start && input.ptr[end - 1] == '\r') --end;
            if (kind == DEDSEC_FEATURE_LINE_BYTES) count = end - start;
            else {
                size_t p = end;
                while (p > start && dedsec_is_hspace(input.ptr[p - 1])) --p;
                count = end - p;
                /* A trailing-whitespace feature's provenance is the run
                 * itself, not the complete line that contains it. */
                start = p;
                end = p + count;
            }
            s = emit_one(emit, user, (int64_t)count, start, end - start);
            if (s != DEDSEC_OK) return s;
            if (i < input.len) ++i;
            continue;
        }
        if (kind == DEDSEC_FEATURE_GAP_WIDTH) {
            if (!dedsec_is_hspace(input.ptr[i])) { ++i; continue; }
            start = i; while (i < input.len && dedsec_is_hspace(input.ptr[i])) ++i;
            if (start > 0 && i < input.len && input.ptr[start - 1] != '\n' && input.ptr[i] != '\n') {
                s = emit_one(emit, user, (int64_t)(i - start), start, i - start);
                if (s != DEDSEC_OK) return s;
            }
            continue;
        }
        if (kind == DEDSEC_FEATURE_PUNCTUATION_CLASS) {
            int64_t v = -1;
            if (input.ptr[i] == ',') v = 0; else if (input.ptr[i] == ';') v = 1;
            else if (input.ptr[i] == '.') v = 2; else if (input.ptr[i] == '?') v = 3;
            if (v >= 0) { s = emit_one(emit, user, v, i, 1); if (s != DEDSEC_OK) return s; }
            ++i; continue;
        }
        if (!ascii_word(input.ptr[i])) { ++i; continue; }
        start = i; count = 0;
        while (i < input.len && ascii_word(input.ptr[i])) {
            if ((input.ptr[i] & 0xc0) != 0x80) ++count;
            ++i;
        }
        if (kind == DEDSEC_FEATURE_WORD_BYTES) count = i - start;
        else if (kind == DEDSEC_FEATURE_WORD_INITIAL_CASE) {
            if (input.ptr[start] >= 'A' && input.ptr[start] <= 'Z') count = 1;
            else if (input.ptr[start] >= 'a' && input.ptr[start] <= 'z') count = 0;
            else continue;
        }
        s = emit_one(emit, user, (int64_t)count, start, i - start);
        if (s != DEDSEC_OK) return s;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_features_decode_bits(const dedsec_feature *features,
                                          size_t feature_count,
                                          const dedsec_binary_rule *rule,
                                          dedsec_bitstream *output) {
    size_t i;
    unsigned width, j;
    if ((!features && feature_count) || !rule || !output ||
        rule->bit_width == 0 || rule->bit_width > 8) return DEDSEC_EINVAL;
    for (i = 0; i < feature_count; ++i) {
        uint64_t bits;
        int64_t v = features[i].value;
        width = rule->bit_width;
        if (rule->kind == DEDSEC_BINARY_EQUALS_PAIR) {
            if (v == rule->zero_value) bits = 0;
            else if (v == rule->one_value) bits = 1;
            else continue;
            width = 1;
        } else if (rule->kind == DEDSEC_BINARY_PARITY) { bits = (uint64_t)v & 1u; width = 1; }
        else if (rule->kind == DEDSEC_BINARY_THRESHOLD) { bits = v >= rule->one_value; width = 1; }
        else bits = ((uint64_t)v >> rule->bit_offset) & ((((uint64_t)1) << width) - 1u);
        for (j = 0; j < width; ++j) {
            unsigned shift = rule->lsb_first ? j : (width - 1u - j);
            {
                dedsec_status s = dedsec_bitstream_append_bits(output,
                    (uint8_t)((bits >> shift) & 1u), 1, 0);
                if (s != DEDSEC_OK) return s;
            }
        }
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

dedsec_status dedsec_features_decode(const dedsec_feature *features,
                                     size_t feature_count,
                                     const dedsec_binary_rule *rule,
                                     dedsec_buffer *output) {
    dedsec_bitstream bits;
    dedsec_status s;
    if (!output) return DEDSEC_EINVAL;
    output->len = 0;
    dedsec_bitstream_init(&bits);
    s = dedsec_features_decode_bits(features, feature_count, rule, &bits);
    if (s == DEDSEC_OK)
        s = dedsec_buffer_append(output, bits.bytes.ptr, bits.bit_length / 8);
    dedsec_bitstream_free(&bits);
    return s;
}
