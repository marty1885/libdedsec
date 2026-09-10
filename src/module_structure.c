#include "internal.h"

#include <string.h>

/* Deliberately narrow script classes: ASCII Latin and common Han ranges.
 * They are useful trial features, not Unicode Script property coverage. */
static int ascii_latin(uint32_t cp) {
    return (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z');
}
static int common_han(uint32_t cp) {
    return (cp >= 0x3400 && cp <= 0x4dbf) ||
           (cp >= 0x4e00 && cp <= 0x9fff) ||
           (cp >= 0xf900 && cp <= 0xfaff);
}
static int sentence_end(uint32_t cp) {
    return cp == '.' || cp == '!' || cp == '?' || cp == 0x3002 ||
           cp == 0xff01 || cp == 0xff1f;
}
static int hspace_cp(uint32_t cp) { return cp == ' ' || cp == '\t' || cp == '\r'; }

static dedsec_status structure_detect(void *context, dedsec_view input,
                                      dedsec_finding_fn emit, void *user) {
    size_t i;
    uint64_t lf = 0, crlf = 0;
    (void)context;
    for (i = 0; i < input.len; ++i) {
        if (input.ptr[i] == '\r' && i + 1 < input.len && input.ptr[i + 1] == '\n') {
            ++crlf; ++i;
        } else if (input.ptr[i] == '\n') ++lf;
    }
    if (lf >= 2 && crlf >= 2 && lf + crlf >= 8)
        return dedsec_emit_finding(emit, user, "structure", "mixed-line-ending-forms",
                                   "line-ending-bits-lf-zero", 0, input.len,
                                   70, lf + crlf);
    return DEDSEC_OK;
}

typedef enum unit_mode { UNIT_SENTENCE, UNIT_PARAGRAPH } unit_mode;
typedef enum count_mode { COUNT_BYTES, COUNT_CODEPOINTS, COUNT_LATIN, COUNT_CJK } count_mode;
typedef struct unit_state {
    dedsec_bitstream *out;
    const dedsec_codepoint_alphabet *alphabet;
    const dedsec_binary_rule *rule;
    unit_mode unit;
    count_mode count;
    int lsb_first;
    int need_initial;
    int line_content;
    int have_content;
    size_t bytes;
    size_t codepoints;
    size_t latin;
    size_t cjk;
    dedsec_status status;
} unit_state;

static dedsec_status append_symbol(unit_state *x, uint32_t cp) {
    size_t i;
    for (i = 0; i < x->alphabet->symbol_count; ++i) {
        if (x->alphabet->symbols[i].codepoint == cp)
            return dedsec_bitstream_append_bits(x->out, x->alphabet->symbols[i].value,
                                                x->alphabet->bit_width, x->lsb_first);
    }
    return DEDSEC_OK;
}
static dedsec_status emit_count(unit_state *x) {
    size_t value;
    if (!x->have_content) return DEDSEC_OK;
    if (x->count == COUNT_BYTES) value = x->bytes;
    else if (x->count == COUNT_CODEPOINTS) value = x->codepoints;
    else if (x->count == COUNT_LATIN) value = x->latin;
    else value = x->cjk;
    if (x->rule) {
        uint64_t bits;
        unsigned width = x->rule->bit_width;
        if (x->rule->kind == DEDSEC_BINARY_EQUALS_PAIR) {
            if ((int64_t)value == x->rule->zero_value) bits = 0;
            else if ((int64_t)value == x->rule->one_value) bits = 1;
            else return DEDSEC_OK;
            width = 1;
        } else if (x->rule->kind == DEDSEC_BINARY_PARITY) { bits = value & 1u; width = 1; }
        else if (x->rule->kind == DEDSEC_BINARY_THRESHOLD) { bits = (int64_t)value >= x->rule->one_value; width = 1; }
        else bits = ((uint64_t)value >> x->rule->bit_offset) & ((1u << width) - 1u);
        return dedsec_bitstream_append_bits(x->out, (uint8_t)bits, width, x->rule->lsb_first);
    }
    return dedsec_bitstream_append_bits(x->out, (uint8_t)(value & 1u), 1, 0);
}
static void reset_count(unit_state *x) {
    x->have_content = 0; x->bytes = 0; x->codepoints = 0; x->latin = 0; x->cjk = 0;
}
static int scan_unit(void *opaque, const dedsec_scalar *s) {
    unit_state *x = (unit_state *)opaque;
    uint32_t cp = s->value;
    if (x->alphabet) {
        if (x->unit == UNIT_SENTENCE) {
            if (x->need_initial && !hspace_cp(cp) && cp != '\n') {
                x->status = append_symbol(x, cp); x->need_initial = 0;
            }
            if (sentence_end(cp)) x->need_initial = 1;
        } else {
            if (cp == '\n') {
                if (!x->line_content) x->need_initial = 1;
                x->line_content = 0;
            } else if (!hspace_cp(cp)) {
                if (x->need_initial) { x->status = append_symbol(x, cp); x->need_initial = 0; }
                x->line_content = 1;
            }
        }
    } else if (x->unit == UNIT_SENTENCE) {
        if (x->have_content || (!hspace_cp(cp) && cp != '\n')) {
            x->bytes += s->byte_length; ++x->codepoints;
            if (ascii_latin(cp)) ++x->latin;
            if (common_han(cp)) ++x->cjk;
            if (!hspace_cp(cp) && cp != '\n') x->have_content = 1;
        }
        if (sentence_end(cp)) { x->status = emit_count(x); reset_count(x); }
    } else {
        if (cp == '\n') {
            if (!x->line_content) { x->status = emit_count(x); reset_count(x); }
            x->line_content = 0;
        } else {
            if (x->have_content || !hspace_cp(cp)) {
                x->bytes += s->byte_length; ++x->codepoints;
                if (ascii_latin(cp)) ++x->latin;
                if (common_han(cp)) ++x->cjk;
                if (!hspace_cp(cp)) { x->have_content = 1; x->line_content = 1; }
            }
        }
    }
    return x->status != DEDSEC_OK;
}

static dedsec_status structure_decode(void *context, dedsec_view input,
                                      const dedsec_decode_request *request,
                                      dedsec_bitstream *output) {
    size_t i, error = 0;
    unit_state x = {0};
    dedsec_status s;
    int reverse;
    (void)context;
    if (dedsec_streq(request->variant, "line-ending-bits-lf-zero") ||
        dedsec_streq(request->variant, "line-ending-bits-crlf-zero")) {
        reverse = dedsec_streq(request->variant, "line-ending-bits-crlf-zero");
        for (i = 0; i < input.len; ++i) {
            unsigned bit;
            if (input.ptr[i] == '\r' && i + 1 < input.len && input.ptr[i + 1] == '\n') {
                bit = reverse ? 0u : 1u; ++i;
            } else if (input.ptr[i] == '\n') bit = reverse ? 1u : 0u;
            else continue;
            s = dedsec_bitstream_append_bits(output, (uint8_t)bit, 1, 0);
            if (s != DEDSEC_OK) return s;
        }
        return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
    }
    if (dedsec_streq(request->variant, "sentence-initial-map-msb") ||
        dedsec_streq(request->variant, "sentence-initial-map-lsb") ||
        dedsec_streq(request->variant, "paragraph-initial-map-msb") ||
        dedsec_streq(request->variant, "paragraph-initial-map-lsb")) {
        if (!request->params || request->params_size != sizeof(dedsec_codepoint_alphabet)) return DEDSEC_EINVAL;
        x.alphabet = (const dedsec_codepoint_alphabet *)request->params;
        if (!x.alphabet->symbols || !x.alphabet->symbol_count || !x.alphabet->bit_width ||
            x.alphabet->bit_width > 8) return DEDSEC_EINVAL;
        for (i = 0; i < x.alphabet->symbol_count; ++i)
            if (x.alphabet->symbols[i].value >= (1u << x.alphabet->bit_width))
                return DEDSEC_EINVAL;
        x.unit = strstr(request->variant, "paragraph") ? UNIT_PARAGRAPH : UNIT_SENTENCE;
        x.lsb_first = strstr(request->variant, "-lsb") != NULL || x.alphabet->lsb_first;
        x.need_initial = 1;
    } else {
        if (dedsec_streq(request->variant, "sentence-byte-parity")) {
            x.unit = UNIT_SENTENCE; x.count = COUNT_BYTES;
        } else if (dedsec_streq(request->variant, "sentence-codepoint-parity")) {
            x.unit = UNIT_SENTENCE; x.count = COUNT_CODEPOINTS;
        } else if (dedsec_streq(request->variant, "sentence-latin-count-parity")) {
            x.unit = UNIT_SENTENCE; x.count = COUNT_LATIN;
        } else if (dedsec_streq(request->variant, "sentence-cjk-count-parity")) {
            x.unit = UNIT_SENTENCE; x.count = COUNT_CJK;
        } else if (dedsec_streq(request->variant, "paragraph-byte-parity")) {
            x.unit = UNIT_PARAGRAPH; x.count = COUNT_BYTES;
        } else if (dedsec_streq(request->variant, "paragraph-codepoint-parity")) {
            x.unit = UNIT_PARAGRAPH; x.count = COUNT_CODEPOINTS;
        } else if (dedsec_streq(request->variant, "paragraph-latin-count-parity")) {
            x.unit = UNIT_PARAGRAPH; x.count = COUNT_LATIN;
        } else if (dedsec_streq(request->variant, "paragraph-cjk-count-parity")) {
            x.unit = UNIT_PARAGRAPH; x.count = COUNT_CJK;
        } else if (dedsec_streq(request->variant, "sentence-byte-rule") ||
                   dedsec_streq(request->variant, "sentence-codepoint-rule") ||
                   dedsec_streq(request->variant, "sentence-latin-count-rule") ||
                   dedsec_streq(request->variant, "sentence-cjk-count-rule") ||
                   dedsec_streq(request->variant, "paragraph-byte-rule") ||
                   dedsec_streq(request->variant, "paragraph-codepoint-rule") ||
                   dedsec_streq(request->variant, "paragraph-latin-count-rule") ||
                   dedsec_streq(request->variant, "paragraph-cjk-count-rule")) {
            if (!request->params || request->params_size != sizeof(dedsec_binary_rule)) return DEDSEC_EINVAL;
            x.rule = (const dedsec_binary_rule *)request->params;
            if ((unsigned)x.rule->kind > (unsigned)DEDSEC_BINARY_LOW_BIT ||
                !x.rule->bit_width || x.rule->bit_width > 8)
                return DEDSEC_EINVAL;
            x.unit = strstr(request->variant, "paragraph") ? UNIT_PARAGRAPH : UNIT_SENTENCE;
            if (strstr(request->variant, "byte-rule")) x.count = COUNT_BYTES;
            else if (strstr(request->variant, "codepoint-rule")) x.count = COUNT_CODEPOINTS;
            else if (strstr(request->variant, "latin-count-rule")) x.count = COUNT_LATIN;
            else x.count = COUNT_CJK;
        } else return DEDSEC_EUNSUPPORTED;
    }
    x.out = output;
    s = dedsec_utf8_foreach(input, scan_unit, &x, &error);
    if (s == DEDSEC_ESTOP && x.status != DEDSEC_OK) return x.status;
    if (s != DEDSEC_OK) return s;
    if (!x.alphabet) {
        s = emit_count(&x);
        if (s != DEDSEC_OK) return s;
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "structure", NULL, structure_detect, NULL, structure_decode
};
const dedsec_module *dedsec_builtin_structure_module(void) { return &module; }
