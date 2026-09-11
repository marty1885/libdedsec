#include "internal.h"

#include <string.h>

static int hex_digit(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static int radix_value(uint8_t c, int radix) {
    if (radix == 64) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
    } else if (radix == 32) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= '2' && c <= '7') return c - '2' + 26;
    } else { /* Canonical Crockford: deliberately reject aliases I, L, O. */
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'H') return c - 'A' + 10;
        if (c >= 'J' && c <= 'K') return c - 'J' + 18;
        if (c >= 'M' && c <= 'N') return c - 'M' + 20;
        if (c >= 'P' && c <= 'T') return c - 'P' + 22;
        if (c >= 'V' && c <= 'Z') return c - 'V' + 27;
    }
    return -1;
}

static dedsec_status decode_radix(dedsec_view input, dedsec_bitstream *output,
                                  int radix, int bits, int padded) {
    size_t i, symbols = 0, pads = 0, whole_bits;
    int seen_pad = 0, last = 0;
    if (!input.len) return DEDSEC_ENOTFOUND;
    for (i = 0; i < input.len; ++i) {
        int v;
        if (input.ptr[i] == '=') { seen_pad = 1; ++pads; continue; }
        if (seen_pad || (v = radix_value(input.ptr[i], radix)) < 0) return DEDSEC_EINVAL;
        last = v; ++symbols;
    }
    if (symbols > SIZE_MAX / (size_t)bits) return DEDSEC_ENOMEM;
    if (padded) {
        size_t group = radix == 64 ? 4 : 8;
        if (input.len % group || (!pads && symbols % group)) return DEDSEC_EINVAL;
        if (radix == 64) {
            if (pads > 2 || (pads == 1 && symbols % 4 != 3) ||
                (pads == 2 && symbols % 4 != 2) || (pads && (last & (pads == 1 ? 3 : 15))))
                return DEDSEC_EINVAL;
        } else if (pads > 6 || (pads && !((pads == 6 && symbols % 8 == 2) ||
                   (pads == 4 && symbols % 8 == 4) || (pads == 3 && symbols % 8 == 5) ||
                   (pads == 1 && symbols % 8 == 7)))) return DEDSEC_EINVAL;
    } else if (pads) return DEDSEC_EINVAL;
    whole_bits = (symbols * (size_t)bits / 8) * 8;
    if (padded && symbols * (size_t)bits != whole_bits &&
        (last & ((1u << (symbols * (size_t)bits % 8)) - 1u))) return DEDSEC_EINVAL;
    for (i = 0; i < symbols; ++i) {
        int v = radix_value(input.ptr[i], radix);
        dedsec_status s = dedsec_bitstream_append_bits(output, (uint8_t)v, (unsigned)bits, 0);
        if (s != DEDSEC_OK) return s;
    }
    if (padded) {
        output->bit_length = whole_bits;
        output->bytes.len = (whole_bits + 7) / 8;
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static int radix_token_byte(uint8_t c, int radix, int padded) {
    return radix_value(c, radix) >= 0 || (padded && c == '=');
}

/* Do not decode an entire document by skipping arbitrary bytes. Instead, find
 * maximal alphabet-bounded spans, validate each span strictly, and report its
 * original byte range for the caller to decode independently. */
static dedsec_status detect_radix_tokens(dedsec_view input, dedsec_finding_fn emit,
                                         void *user, int radix, int bits, int padded,
                                         const char *rule, const char *variant) {
    size_t i = 0;
    while (i < input.len) {
        size_t start, length;
        dedsec_view token;
        dedsec_bitstream trial;
        dedsec_status s;
        if (!radix_token_byte(input.ptr[i], radix, padded)) { ++i; continue; }
        start = i;
        while (i < input.len && radix_token_byte(input.ptr[i], radix, padded)) ++i;
        length = i - start;
        if (length < 16) continue;
        token.ptr = input.ptr + start; token.len = length;
        dedsec_bitstream_init(&trial);
        s = decode_radix(token, &trial, radix, bits, padded);
        dedsec_bitstream_free(&trial);
        if (s == DEDSEC_OK) {
            size_t j;
            for (j = 0; j < length && token.ptr[j] != '='; ++j) {
                int value = radix_value(token.ptr[j], radix);
                s = dedsec_emit_symbol(emit, user, "surface", rule, variant,
                                       start + j, 1, (uint8_t)value,
                                       (uint8_t)bits);
                if (s != DEDSEC_OK) return s;
            }
            s = dedsec_emit_finding(emit, user, "surface", rule, variant,
                                    start, length, 15, length);
            if (s != DEDSEC_OK) return s;
        } else if (s == DEDSEC_ENOMEM) return s;
    }
    return DEDSEC_OK;
}

static dedsec_status surface_detect(void *context, dedsec_view input,
                                    dedsec_finding_fn emit, void *user) {
    size_t i;
    uint64_t json = 0, percent = 0, entity = 0, mime_q = 0, mime_b = 0;
    uint64_t trigraph = 0, ansi = 0;
    dedsec_status s;
    (void)context;
    for (i = 0; i < input.len; ++i) {
        if (i + 5 < input.len && input.ptr[i] == '\\' && input.ptr[i+1] == 'u' &&
            hex_digit(input.ptr[i+2]) && hex_digit(input.ptr[i+3]) &&
            hex_digit(input.ptr[i+4]) && hex_digit(input.ptr[i+5])) ++json;
        if (i + 2 < input.len && input.ptr[i] == '%' && hex_digit(input.ptr[i+1]) &&
            hex_digit(input.ptr[i+2])) ++percent;
        if (i + 2 < input.len && input.ptr[i] == '&' && input.ptr[i+1] == '#') ++entity;
        if (i + 10 < input.len && input.ptr[i] == '=' && input.ptr[i+1] == '?' ) {
            size_t j = i + 2;
            while (j + 2 < input.len && input.ptr[j] != '?') ++j;
            if (j + 2 < input.len && input.ptr[j] == '?') {
                if (input.ptr[j+1] == 'Q' || input.ptr[j+1] == 'q') ++mime_q;
                if (input.ptr[j+1] == 'B' || input.ptr[j+1] == 'b') ++mime_b;
            }
        }
        if (i + 2 < input.len && input.ptr[i] == '?' && input.ptr[i+1] == '?' &&
            input.ptr[i+2] == '=') ++trigraph;
        if (i + 2 < input.len && input.ptr[i] == 0x1b && input.ptr[i+1] == '[') ++ansi;
    }
#define REPORT_IF(count_, rule_, score_) do { \
    if ((count_) >= 2) { \
        s = dedsec_emit_finding(emit, user, "surface", (rule_), "token-map-msb", \
                                0, input.len, (score_), (count_)); \
        if (s != DEDSEC_OK) return s; \
    } \
} while (0)
    REPORT_IF(json, "json-unicode-escape-spellings", 25);
    REPORT_IF(percent, "percent-encoded-spellings", 20);
    REPORT_IF(entity, "numeric-character-reference-spellings", 25);
    if (mime_q && mime_b) REPORT_IF(mime_q + mime_b, "mixed-rfc2047-transfer-spellings", 40);
    REPORT_IF(trigraph, "c-trigraph-spellings", 50);
    REPORT_IF(ansi, "terminal-control-spellings", 35);
#undef REPORT_IF
    s = detect_radix_tokens(input, emit, user, 64, 6, 1,
                            "base64-rfc4648-token", "base64-rfc4648");
    if (s != DEDSEC_OK) return s;
    s = detect_radix_tokens(input, emit, user, 32, 5, 1,
                            "base32-rfc4648-token", "base32-rfc4648");
    if (s != DEDSEC_OK) return s;
    return detect_radix_tokens(input, emit, user, 0, 5, 0,
                               "base32-crockford-token", "base32-crockford");
}

static dedsec_status surface_decode(void *context, dedsec_view input,
                                    const dedsec_decode_request *request,
                                    dedsec_bitstream *output) {
    const dedsec_token_alphabet *a;
    size_t i = 0, j;
    (void)context;
    if (dedsec_streq(request->variant, "base64-rfc4648"))
        return decode_radix(input, output, 64, 6, 1);
    if (dedsec_streq(request->variant, "base32-rfc4648"))
        return decode_radix(input, output, 32, 5, 1);
    if (dedsec_streq(request->variant, "base32-crockford"))
        return decode_radix(input, output, 0, 5, 0);
    if (!dedsec_streq(request->variant, "token-map-msb") &&
        !dedsec_streq(request->variant, "token-map-lsb")) return DEDSEC_EUNSUPPORTED;
    if (!request->params || request->params_size != sizeof(*a)) return DEDSEC_EINVAL;
    a = (const dedsec_token_alphabet *)request->params;
    if (!a->symbols || !a->symbol_count || !a->bit_width || a->bit_width > 8)
        return DEDSEC_EINVAL;
    while (i < input.len) {
        size_t best = SIZE_MAX, best_len = 0;
        for (j = 0; j < a->symbol_count; ++j) {
            size_t n = a->symbols[j].spelling.len;
            if (!n || a->symbols[j].value >= (1u << a->bit_width)) return DEDSEC_EINVAL;
            if (n > best_len && n <= input.len - i &&
                memcmp(input.ptr + i, a->symbols[j].spelling.ptr, n) == 0) {
                best = j; best_len = n;
            }
        }
        if (best == SIZE_MAX) { ++i; continue; }
        {
            dedsec_status s = dedsec_bitstream_append_bits(output,
                                       a->symbols[best].value, a->bit_width,
                                       dedsec_streq(request->variant, "token-map-lsb") || a->lsb_first);
            if (s != DEDSEC_OK) return s;
        }
        i += best_len;
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "surface", NULL, surface_detect, NULL, surface_decode
};
const dedsec_module *dedsec_builtin_surface_module(void) { return &module; }
