#include "internal.h"

typedef struct unicode_scan {
    dedsec_finding_fn emit;
    void *user;
    dedsec_status status;
    uint64_t ignorables, selectors, tags, bidi, interior_bom;
    uint64_t noncharacters, shorthand, iteration;
    size_t first_ignorable, first_selector, first_tag, first_bidi, first_bom;
    size_t first_noncharacter, first_shorthand, first_iteration;
} unicode_scan;

static int in_range(uint32_t v, uint32_t lo, uint32_t hi) {
    return v >= lo && v <= hi;
}
static int validate_only(void *opaque, const dedsec_scalar *s) {
    (void)opaque; (void)s; return 0;
}
static int known_ignorable(uint32_t cp) {
    return cp == 0x00ad || cp == 0x034f || cp == 0x061c ||
           in_range(cp, 0x200b, 0x200f) || in_range(cp, 0x202a, 0x202e) ||
           in_range(cp, 0x2060, 0x206f) || cp == 0xfeff ||
           in_range(cp, 0xe0001, 0xe007f);
}
static int scan_scalar(void *opaque, const dedsec_scalar *s) {
    unicode_scan *x = (unicode_scan *)opaque;
    uint32_t cp = s->value;
    if (known_ignorable(cp)) {
        if (!x->ignorables) x->first_ignorable = s->byte_offset;
        ++x->ignorables;
    }
    if (in_range(cp, 0xfe00, 0xfe0f) || in_range(cp, 0xe0100, 0xe01ef)) {
        if (!x->selectors) x->first_selector = s->byte_offset;
        ++x->selectors;
    }
    if (in_range(cp, 0xe0001, 0xe007f)) {
        if (!x->tags) x->first_tag = s->byte_offset;
        ++x->tags;
    }
    if (in_range(cp, 0x202a, 0x202e) || in_range(cp, 0x2066, 0x2069) ||
        cp == 0x061c || cp == 0x200e || cp == 0x200f) {
        if (!x->bidi) x->first_bidi = s->byte_offset;
        ++x->bidi;
    }
    if (cp == 0xfeff && s->byte_offset != 0) {
        if (!x->interior_bom) x->first_bom = s->byte_offset;
        ++x->interior_bom;
    }
    if (in_range(cp, 0xfdd0, 0xfdef) ||
        (cp <= 0x10ffff && (cp & 0xffffu) >= 0xfffeu)) {
        if (!x->noncharacters) x->first_noncharacter = s->byte_offset;
        ++x->noncharacters;
    }
    if (in_range(cp, 0x1bca0, 0x1bca3)) {
        if (!x->shorthand) x->first_shorthand = s->byte_offset;
        ++x->shorthand;
    }
    if (cp == 0x3005) {
        if (!x->iteration) x->first_iteration = s->byte_offset;
        ++x->iteration;
    }
    return 0;
}

static dedsec_status emit_count(unicode_scan *x, uint64_t count, size_t offset,
                                const char *rule, const char *decoder,
                                uint32_t base_score) {
    uint32_t score;
    if (!count) return DEDSEC_OK;
    score = base_score + (count > 10 ? 15u : (uint32_t)count);
    if (score > 100) score = 100;
    return dedsec_emit_finding(x->emit, x->user, "unicode", rule, decoder,
                               offset, 0, score, count);
}

static dedsec_status unicode_detect(void *context, dedsec_view input,
                                    dedsec_finding_fn emit, void *user) {
    unicode_scan x = {0};
    dedsec_status s;
    size_t error = 0;
    (void)context;
    x.emit = emit; x.user = user;
    s = dedsec_utf8_foreach(input, scan_scalar, &x, &error);
    if (s == DEDSEC_EUTF8) return DEDSEC_OK; /* encoding module owns this */
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.tags, x.first_tag, "unicode-tags", "tags-ascii", 85);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.selectors, x.first_selector, "variation-selectors",
                   "variation-nibbles", 45);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.bidi, x.first_bidi, "bidi-controls", NULL, 60);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.interior_bom, x.first_bom, "interior-bom",
                   "strip-known-ignorables", 80);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.noncharacters, x.first_noncharacter,
                   "unicode-noncharacters", "codepoint-map-msb", 90);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.shorthand, x.first_shorthand,
                   "shorthand-format-controls", "codepoint-map-msb", 75);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.iteration, x.first_iteration,
                   "ideographic-iteration-marks", "codepoint-map-msb", 10);
    if (s != DEDSEC_OK) return s;
    return emit_count(&x, x.ignorables, x.first_ignorable,
                      "default-ignorable-candidates", "strip-known-ignorables", 35);
}

typedef struct decode_state {
    const char *variant;
    dedsec_bitstream *out;
    int in_tags;
    const dedsec_codepoint_alphabet *alphabet;
    int lsb_first;
    uint32_t iteration_first;
    int iteration_have_first;
    dedsec_status status;
} decode_state;

static dedsec_status decode_bit(decode_state *x, unsigned bit) {
    return dedsec_bitstream_append_bits(x->out, (uint8_t)bit, 1, 0);
}

static dedsec_status decode_value(decode_state *x, uint8_t value, unsigned width) {
    unsigned j;
    for (j = 0; j < width; ++j) {
        unsigned shift = x->lsb_first ? j : width - 1u - j;
        dedsec_status s = decode_bit(x, (value >> shift) & 1u);
        if (s != DEDSEC_OK) return s;
    }
    return DEDSEC_OK;
}

static int decode_scalar(void *opaque, const dedsec_scalar *s) {
    decode_state *x = (decode_state *)opaque;
    uint32_t cp = s->value;
    if (dedsec_streq(x->variant, "tags-ascii")) {
        if (cp == 0xe0001) x->in_tags = 1;
        else if (cp == 0xe007f) x->in_tags = 0;
        else if (x->in_tags && in_range(cp, 0xe0020, 0xe007e))
            x->status = dedsec_bitstream_append_bits(x->out,
                                                      (uint8_t)(cp - 0xe0000), 8, 0);
    } else if (dedsec_streq(x->variant, "zwsp-zwnj-msb")) {
        if (cp == 0x200b || cp == 0x200c)
            x->status = decode_bit(x, cp == 0x200c);
    } else if (dedsec_streq(x->variant, "variation-nibbles")) {
        if (in_range(cp, 0xfe00, 0xfe0f)) {
            unsigned nibble = (unsigned)(cp - 0xfe00);
            x->status = decode_value(x, (uint8_t)nibble, 4);
        }
    } else if (dedsec_streq(x->variant, "codepoint-map-msb") ||
               dedsec_streq(x->variant, "codepoint-map-lsb")) {
        size_t i;
        for (i = 0; i < x->alphabet->symbol_count; ++i)
            if (x->alphabet->symbols[i].codepoint == cp) {
                x->status = decode_value(x, x->alphabet->symbols[i].value,
                                         x->alphabet->bit_width);
                break;
            }
    } else if (dedsec_streq(x->variant, "iteration-mark-bits")) {
        if (cp == 0x3001) {
            x->iteration_have_first = 0;
        } else if (!x->iteration_have_first) {
            x->iteration_first = cp;
            x->iteration_have_first = 1;
        } else {
            if (cp == x->iteration_first) x->status = decode_bit(x, 0);
            else if (cp == 0x3005) x->status = decode_bit(x, 1);
            x->iteration_have_first = 0;
        }
    }
    return x->status != DEDSEC_OK;
}

static dedsec_status strip_ignorables(dedsec_view input, dedsec_bitstream *output) {
    size_t i = 0, start;
    size_t error = 0;
    dedsec_status valid = dedsec_utf8_foreach(input, validate_only, NULL, &error);
    if (valid != DEDSEC_OK) return valid;
    while (i < input.len) {
        uint8_t b = input.ptr[i];
        size_t n = b < 0x80 ? 1 : ((b & 0xe0) == 0xc0 ? 2 : ((b & 0xf0) == 0xe0 ? 3 : 4));
        uint32_t cp;
        if (n > input.len - i) return DEDSEC_EUTF8;
        start = i;
        if (n == 1) cp = b;
        else if (n == 2) cp = ((uint32_t)(b & 0x1f) << 6) | (input.ptr[i+1]&0x3f);
        else if (n == 3) cp = ((uint32_t)(b & 0x0f) << 12) | ((uint32_t)(input.ptr[i+1]&0x3f)<<6) | (input.ptr[i+2]&0x3f);
        else cp = ((uint32_t)(b & 7)<<18) | ((uint32_t)(input.ptr[i+1]&0x3f)<<12) | ((uint32_t)(input.ptr[i+2]&0x3f)<<6) | (input.ptr[i+3]&0x3f);
        if (!known_ignorable(cp) && !in_range(cp, 0xfe00, 0xfe0f) && !in_range(cp, 0xe0100, 0xe01ef)) {
            size_t j;
            dedsec_status s = DEDSEC_OK;
            for (j = 0; j < n; ++j) {
                s = dedsec_bitstream_append_bits(output, input.ptr[start + j], 8, 0);
                if (s != DEDSEC_OK) break;
            }
            if (s != DEDSEC_OK) return s;
        }
        i += n;
    }
    return DEDSEC_OK;
}

static dedsec_status unicode_decode(void *context, dedsec_view input,
                                    const dedsec_decode_request *request,
                                    dedsec_bitstream *output) {
    decode_state x = {0};
    dedsec_status s;
    size_t error = 0;
    (void)context;
    if (dedsec_streq(request->variant, "strip-known-ignorables"))
        return strip_ignorables(input, output);
    if (!dedsec_streq(request->variant, "tags-ascii") &&
        !dedsec_streq(request->variant, "zwsp-zwnj-msb") &&
        !dedsec_streq(request->variant, "variation-nibbles") &&
        !dedsec_streq(request->variant, "iteration-mark-bits") &&
        !dedsec_streq(request->variant, "codepoint-map-msb") &&
        !dedsec_streq(request->variant, "codepoint-map-lsb"))
        return DEDSEC_EUNSUPPORTED;
    x.variant = request->variant; x.out = output; x.status = DEDSEC_OK;
    if (dedsec_streq(request->variant, "codepoint-map-msb") ||
        dedsec_streq(request->variant, "codepoint-map-lsb")) {
        if (!request->params || request->params_size != sizeof(dedsec_codepoint_alphabet))
            return DEDSEC_EINVAL;
        x.alphabet = (const dedsec_codepoint_alphabet *)request->params;
        if (!x.alphabet->symbols || !x.alphabet->symbol_count ||
            !x.alphabet->bit_width || x.alphabet->bit_width > 8) return DEDSEC_EINVAL;
        {
            size_t i;
            unsigned limit = 1u << x.alphabet->bit_width;
            for (i = 0; i < x.alphabet->symbol_count; ++i)
                if ((unsigned)x.alphabet->symbols[i].value >= limit) return DEDSEC_EINVAL;
        }
        x.lsb_first = dedsec_streq(request->variant, "codepoint-map-lsb") ||
                      x.alphabet->lsb_first;
    }
    s = dedsec_utf8_foreach(input, decode_scalar, &x, &error);
    if (s == DEDSEC_ESTOP && x.status != DEDSEC_OK) return x.status;
    if (s != DEDSEC_OK) return s;
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "unicode", NULL, unicode_detect, NULL, unicode_decode
};
const dedsec_module *dedsec_builtin_unicode_module(void) { return &module; }
