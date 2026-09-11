#include "internal.h"

#include <string.h>

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

static dedsec_status surface_detect(void *context, dedsec_view input,
                                    dedsec_finding_fn emit, void *user) {
    (void)context;
    (void)input;
    (void)emit;
    (void)user;
    /* Surface spellings require a declared container grammar. A run accepted
     * by a radix alphabet can be ordinary prose or an identifier, while JSON
     * escapes and trigraphs routinely appear as source literals. Preserve the
     * explicit surface decoders below, but never turn unframed raw spelling
     * coincidences into parameter-free alerts. */
    return DEDSEC_OK;
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
