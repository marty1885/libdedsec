#include "internal.h"

typedef int (*ul_entry_fn)(void *user, size_t marker_offset, uint8_t marker,
                           unsigned indent_columns);

static int hspace(uint8_t c) { return c == ' ' || c == '\t'; }
static int fence_line(const uint8_t *p, size_t n) {
    size_t i = 0, run = 0;
    while (i < n && i < 3 && p[i] == ' ') ++i;
    if (i == n || (p[i] != '`' && p[i] != '~')) return 0;
    while (i + run < n && p[i + run] == p[i]) ++run;
    return run >= 3;
}

/* This is intentionally a narrow block-list recognizer, not a CommonMark
 * parser. An entry is indentation + '-'/'*' + ASCII horizontal whitespace. */
static dedsec_status foreach_ul(dedsec_view input, ul_entry_fn emit, void *user) {
    size_t start = 0;
    int fenced = 0;
    while (start < input.len) {
        size_t end = start, i, columns = 0;
        while (end < input.len && input.ptr[end] != '\n') ++end;
        i = start;
        while (i < end && hspace(input.ptr[i])) {
            if (input.ptr[i] == '\t') columns = (columns + 4u) & ~3u;
            else ++columns;
            ++i;
        }
        if (fence_line(input.ptr + start, end - start)) {
            fenced = !fenced;
        } else if (!fenced && i + 1 < end &&
                   (input.ptr[i] == '-' || input.ptr[i] == '*') && hspace(input.ptr[i + 1])) {
            if (emit(user, i, input.ptr[i], (unsigned)columns)) return DEDSEC_ESTOP;
        }
        start = end < input.len ? end + 1 : end;
    }
    return DEDSEC_OK;
}

typedef struct count_state { uint64_t dash, star, total; } count_state;
static int count_ul(void *opaque, size_t offset, uint8_t marker, unsigned indent) {
    count_state *x = (count_state *)opaque;
    (void)offset; (void)indent;
    ++x->total; if (marker == '-') ++x->dash; else ++x->star;
    return 0;
}
static dedsec_status markdown_detect(void *context, dedsec_view input,
                                     dedsec_finding_fn emit, void *user) {
    count_state x = {0};
    dedsec_status s;
    (void)context;
    s = foreach_ul(input, count_ul, &x);
    if (s != DEDSEC_OK) return s;
    if (x.dash >= 2 && x.star >= 2 && x.total >= 8)
        return dedsec_emit_finding(emit, user, "markdown", "mixed-unordered-list-markers",
                                   "markdown-ul-marker-bits", 0, input.len, 45, x.total);
    return DEDSEC_OK;
}

typedef struct decode_state {
    dedsec_bitstream *out;
    const dedsec_binary_rule *rule;
    uint32_t flags;
    int levels_only;
    dedsec_status status;
} decode_state;
static int include_level(const decode_state *x, unsigned columns) {
    if ((x->flags & DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY) && columns != 0) return 0;
    if ((x->flags & DEDSEC_MARKDOWN_UL_NESTED_ONLY) && columns == 0) return 0;
    return 1;
}
static dedsec_status append_rule(dedsec_bitstream *out, const dedsec_binary_rule *rule,
                                 unsigned value) {
    uint64_t bits;
    unsigned width = rule->bit_width;
    if (rule->kind == DEDSEC_BINARY_EQUALS_PAIR) {
        if ((int64_t)value == rule->zero_value) bits = 0;
        else if ((int64_t)value == rule->one_value) bits = 1;
        else return DEDSEC_OK;
        width = 1;
    } else if (rule->kind == DEDSEC_BINARY_PARITY) { bits = value & 1u; width = 1; }
    else if (rule->kind == DEDSEC_BINARY_THRESHOLD) { bits = (int64_t)value >= rule->one_value; width = 1; }
    else bits = ((uint64_t)value >> rule->bit_offset) & ((1u << width) - 1u);
    return dedsec_bitstream_append_bits(out, (uint8_t)bits, width, rule->lsb_first);
}
static int decode_ul(void *opaque, size_t offset, uint8_t marker, unsigned columns) {
    decode_state *x = (decode_state *)opaque;
    (void)offset;
    if (!include_level(x, columns)) return 0;
    if (x->levels_only) x->status = append_rule(x->out, x->rule, columns);
    else x->status = dedsec_bitstream_append_bits(x->out, marker == '*' ? 1u : 0u, 1, 0);
    return x->status != DEDSEC_OK;
}
static dedsec_status markdown_decode(void *context, dedsec_view input,
                                    const dedsec_decode_request *request,
                                    dedsec_bitstream *output) {
    decode_state x = {0};
    dedsec_status s;
    (void)context;
    if (request->flags & ~(DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY | DEDSEC_MARKDOWN_UL_NESTED_ONLY))
        return DEDSEC_EINVAL;
    if ((request->flags & (DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY | DEDSEC_MARKDOWN_UL_NESTED_ONLY)) ==
        (DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY | DEDSEC_MARKDOWN_UL_NESTED_ONLY)) return DEDSEC_EINVAL;
    if (dedsec_streq(request->variant, "markdown-ul-marker-bits")) {
        x.levels_only = 0;
    } else if (dedsec_streq(request->variant, "markdown-ul-level-rule")) {
        x.levels_only = 1;
        if (!request->params || request->params_size != sizeof(dedsec_binary_rule)) return DEDSEC_EINVAL;
        x.rule = (const dedsec_binary_rule *)request->params;
        if ((unsigned)x.rule->kind > (unsigned)DEDSEC_BINARY_LOW_BIT ||
            !x.rule->bit_width || x.rule->bit_width > 8) return DEDSEC_EINVAL;
    } else return DEDSEC_EUNSUPPORTED;
    x.out = output; x.flags = request->flags;
    s = foreach_ul(input, decode_ul, &x);
    if (s == DEDSEC_ESTOP && x.status != DEDSEC_OK) return x.status;
    if (s != DEDSEC_OK) return s;
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "markdown", NULL, markdown_detect, NULL, markdown_decode
};
const dedsec_module *dedsec_builtin_markdown_module(void) { return &module; }
