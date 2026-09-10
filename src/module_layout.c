#include "internal.h"

#include <stdlib.h>

typedef struct counts { uint64_t a, b, total; int64_t av, bv; } counts;
static int count_pair(void *opaque, const dedsec_feature *f) {
    counts *c = (counts *)opaque;
    ++c->total; if (f->value == c->av) ++c->a; if (f->value == c->bv) ++c->b;
    return 0;
}

static dedsec_status check_pair(dedsec_view input, dedsec_feature_kind kind,
                                int64_t a, int64_t b, const char *rule,
                                const char *decoder, dedsec_finding_fn emit,
                                void *user, uint32_t score) {
    counts c = {0,0,0,a,b};
    dedsec_status s = dedsec_extract_features(kind, input, count_pair, &c);
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
    s = check_pair(input, DEDSEC_FEATURE_TRAILING_HSPACE, 1, 2,
                   "two-valued-trailing-space", "trailing-space-bits", emit, user, 65);
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
    if (s == DEDSEC_OK) s = dedsec_features_decode_bits(v.p, v.n, &rule, output);
    free(v.p); return s;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "layout", NULL, layout_detect, NULL, layout_decode
};
const dedsec_module *dedsec_builtin_layout_module(void) { return &module; }
