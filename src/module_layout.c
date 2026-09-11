#include "internal.h"

#include <stdlib.h>

typedef struct counts {
    uint64_t a, b, total;
    int64_t av, bv;
    dedsec_finding_fn emit;
    void *user;
    const char *rule;
    const char *decoder;
    dedsec_status status;
} counts;
static int count_pair(void *opaque, const dedsec_feature *f) {
    counts *c = (counts *)opaque;
    uint8_t value;
    ++c->total;
    if (f->value == c->av) { ++c->a; value = 0; }
    else if (f->value == c->bv) { ++c->b; value = 1; }
    else return 0;
    c->status = dedsec_emit_symbol(c->emit, c->user, "layout", c->rule,
                                   c->decoder, f->byte_offset, f->byte_length,
                                   value, 1);
    if (c->status != DEDSEC_OK) return 1;
    return 0;
}

typedef struct trailing_widths {
    int64_t first, second;
    uint64_t first_count, second_count;
    int have_first, have_second, other;
} trailing_widths;
static int collect_trailing_width(void *opaque, const dedsec_feature *f) {
    trailing_widths *x = (trailing_widths *)opaque;
    if (f->value <= 0) return 0;
    if (!x->have_first) {
        x->first = f->value;
        x->have_first = 1;
        ++x->first_count;
    } else if (f->value == x->first) {
        ++x->first_count;
    } else if (!x->have_second) {
        x->second = f->value;
        x->have_second = 1;
        ++x->second_count;
    } else if (f->value == x->second) {
        ++x->second_count;
    } else {
        x->other = 1;
    }
    return 0;
}

typedef struct trailing_emit {
    dedsec_finding_fn emit;
    void *user;
    dedsec_status status;
} trailing_emit;
static int emit_trailing_width(void *opaque, const dedsec_feature *f) {
    trailing_emit *x = (trailing_emit *)opaque;
    if (f->value <= 0) return 0;
    x->status = dedsec_emit_symbol(x->emit, x->user, "layout",
                                   "two-valued-trailing-hspace-widths",
                                   "trailing-hspace-width-low-bit",
                                   f->byte_offset, f->byte_length,
                                   (uint8_t)((uint64_t)f->value & 1u), 1);
    return x->status != DEDSEC_OK;
}

static dedsec_status check_trailing_widths(dedsec_view input,
                                           dedsec_finding_fn emit, void *user) {
    trailing_widths x = {0};
    trailing_emit symbols = {emit, user, DEDSEC_OK};
    dedsec_status s = dedsec_extract_features(DEDSEC_FEATURE_TRAILING_HSPACE,
                                               input, collect_trailing_width, &x);
    if (s != DEDSEC_OK) return s;
    s = dedsec_extract_features(DEDSEC_FEATURE_TRAILING_HSPACE, input,
                                emit_trailing_width, &symbols);
    if (s == DEDSEC_ESTOP && symbols.status != DEDSEC_OK) return symbols.status;
    if (s != DEDSEC_OK) return s;
    if (x.have_second && !x.other && x.first_count >= 8 && x.second_count >= 8 &&
        x.first_count + x.second_count >= 32 &&
        (x.first_count < x.second_count ? x.first_count : x.second_count) * 5u >=
            x.first_count + x.second_count)
        return dedsec_emit_finding(emit, user, "layout",
                                   "two-valued-trailing-hspace-widths",
                                   "trailing-hspace-width-low-bit", 0, input.len,
                                   68, x.first_count + x.second_count);
    return DEDSEC_OK;
}

static dedsec_status check_pair(dedsec_view input, dedsec_feature_kind kind,
                                int64_t a, int64_t b, const char *rule,
                                const char *decoder, dedsec_finding_fn emit,
                                void *user, uint32_t score) {
    counts c = {0};
    c.av = a;
    c.bv = b;
    c.emit = emit;
    c.user = user;
    c.rule = rule;
    c.decoder = decoder;
    c.status = DEDSEC_OK;
    dedsec_status s = dedsec_extract_features(kind, input, count_pair, &c);
    if (s == DEDSEC_ESTOP && c.status != DEDSEC_OK) return c.status;
    if (s != DEDSEC_OK) return s;
    /* Both values merely occurring is common natural formatting. A binary
     * carrier normally needs enough examples of both choices to transport a
     * non-trivial plaintext; reject heavily one-sided natural distributions.
     * This is a conservative detector gate, not a proof of steganography. */
    if (c.a >= 8 && c.b >= 8 && c.a + c.b >= 32 &&
        (c.a < c.b ? c.a : c.b) * 5u >= c.a + c.b)
        return dedsec_emit_finding(emit, user, "layout", rule, decoder, 0,
                                   input.len, score, c.a + c.b);
    return DEDSEC_OK;
}

static dedsec_status layout_detect(void *context, dedsec_view input,
                                   dedsec_finding_fn emit, void *user) {
    dedsec_status s;
    (void)context;
    s = check_trailing_widths(input, emit, user);
    if (s != DEDSEC_OK) return s;
    s = check_pair(input, DEDSEC_FEATURE_GAP_WIDTH, 1, 2,
                   "two-valued-word-gaps", "gap-width-bits", emit, user, 50);
    if (s != DEDSEC_OK) return s;
    s = check_pair(input, DEDSEC_FEATURE_WORD_INITIAL_CASE, 0, 1,
                   "binary-word-initial-case", "word-case-bits", emit, user, 30);
    if (s != DEDSEC_OK) return s;
    s = check_pair(input, DEDSEC_FEATURE_PUNCTUATION_CLASS, 0, 1,
                   "comma-semicolon-alphabet", "comma-semicolon-bits", emit, user, 25);
    if (s != DEDSEC_OK) return s;
    return check_pair(input, DEDSEC_FEATURE_PUNCTUATION_CLASS, 2, 3,
                      "period-question-alphabet", "period-question-bits", emit, user, 20);
}

typedef struct feature_vec { dedsec_feature *p; size_t n, cap; int oom; } feature_vec;
static int collect_feature(void *opaque, const dedsec_feature *f) {
    feature_vec *v = (feature_vec *)opaque;
    dedsec_feature *next;
    size_t cap;
    if (v->n == v->cap) {
        cap = v->cap ? v->cap * 2 : 64;
        next = (dedsec_feature *)realloc(v->p, cap * sizeof(*next));
        if (!next) { v->oom = 1; return 1; }
        v->p = next; v->cap = cap;
    }
    v->p[v->n++] = *f; return 0;
}

static dedsec_status layout_decode(void *context, dedsec_view input,
                                   const dedsec_decode_request *request,
                                   dedsec_bitstream *output) {
    dedsec_feature_kind kind;
    dedsec_binary_rule rule = { DEDSEC_BINARY_EQUALS_PAIR, 0, 1, 1, 0, 0 };
    feature_vec v = {0};
    dedsec_status s;
    (void)context;
    if (dedsec_streq(request->variant, "trailing-space-bits")) {
        kind = DEDSEC_FEATURE_TRAILING_HSPACE; rule.zero_value = 1; rule.one_value = 2;
    } else if (dedsec_streq(request->variant, "trailing-hspace-rule")) {
        if (!request->params || request->params_size != sizeof(dedsec_binary_rule))
            return DEDSEC_EINVAL;
        rule = *(const dedsec_binary_rule *)request->params;
        if ((unsigned)rule.kind > (unsigned)DEDSEC_BINARY_LOW_BIT ||
            !rule.bit_width || rule.bit_width > 8)
            return DEDSEC_EINVAL;
        kind = DEDSEC_FEATURE_TRAILING_HSPACE;
    } else if (dedsec_streq(request->variant, "trailing-hspace-width-low-bit")) {
        kind = DEDSEC_FEATURE_TRAILING_HSPACE;
        rule.kind = DEDSEC_BINARY_LOW_BIT;
        rule.bit_width = 1;
    } else if (dedsec_streq(request->variant, "gap-width-bits")) {
        kind = DEDSEC_FEATURE_GAP_WIDTH; rule.zero_value = 1; rule.one_value = 2;
    } else if (dedsec_streq(request->variant, "word-case-bits")) {
        kind = DEDSEC_FEATURE_WORD_INITIAL_CASE;
    } else if (dedsec_streq(request->variant, "comma-semicolon-bits")) {
        kind = DEDSEC_FEATURE_PUNCTUATION_CLASS;
    } else if (dedsec_streq(request->variant, "period-question-bits")) {
        kind = DEDSEC_FEATURE_PUNCTUATION_CLASS; rule.zero_value = 2; rule.one_value = 3;
    } else if (dedsec_streq(request->variant, "word-length-parity")) {
        kind = DEDSEC_FEATURE_WORD_CODEPOINTS; rule.kind = DEDSEC_BINARY_PARITY;
    } else if (dedsec_streq(request->variant, "line-length-parity")) {
        kind = DEDSEC_FEATURE_LINE_BYTES; rule.kind = DEDSEC_BINARY_PARITY;
    } else return DEDSEC_EUNSUPPORTED;
    s = dedsec_extract_features(kind, input, collect_feature, &v);
    if (s == DEDSEC_ESTOP && v.oom) s = DEDSEC_ENOMEM;
    if (s == DEDSEC_OK && dedsec_streq(request->variant,
                                       "trailing-hspace-width-low-bit")) {
        size_t read, write = 0;
        for (read = 0; read < v.n; ++read)
            if (v.p[read].value > 0) v.p[write++] = v.p[read];
        v.n = write;
    }
    if (s == DEDSEC_OK) s = dedsec_features_decode_bits(v.p, v.n, &rule, output);
    free(v.p); return s;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "layout", NULL, layout_detect, NULL, layout_decode
};
const dedsec_module *dedsec_builtin_layout_module(void) { return &module; }
