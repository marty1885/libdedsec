#include "internal.h"

#include <string.h>

/* This is a deliberately narrow Gemini text (Gemtext) link recognizer.  It
 * only uses the line grammar needed for link separators; it is not a URL
 * normalizer or a general Gemtext parser. */
typedef struct gem_link {
    size_t line_start;
    size_t url_end;
    size_t prefix_start;
    size_t prefix_len;
    size_t label_sep_start;
    size_t label_sep_len;
    int has_label;
} gem_link;

typedef enum gem_lane {
    GEM_PREFIX_WIDTH,
    GEM_PREFIX_TYPE,
    GEM_LABEL_WIDTH,
    GEM_LABEL_TYPE
} gem_lane;

static int hspace(uint8_t c) { return c == ' ' || c == '\t'; }

static int validate_utf8(void *opaque, const dedsec_scalar *scalar) {
    (void)opaque;
    (void)scalar;
    return 0;
}

static int parse_link(dedsec_view input, size_t start, size_t end,
                      gem_link *link) {
    size_t i, url_start, sep_start;
    if (end - start < 3 || input.ptr[start] != '=' || input.ptr[start + 1] != '>')
        return 0;
    i = start + 2;
    link->prefix_start = i;
    while (i < end && hspace(input.ptr[i])) ++i;
    link->prefix_len = i - link->prefix_start;
    url_start = i;
    while (i < end && !hspace(input.ptr[i])) ++i;
    if (i == url_start) return 0;
    link->line_start = start;
    link->url_end = i;
    link->label_sep_start = i;
    link->label_sep_len = 0;
    link->has_label = 0;
    if (i == end) return 1;
    sep_start = i;
    while (i < end && hspace(input.ptr[i])) ++i;
    if (i == end) return 0; /* A separator without a nonempty label. */
    link->label_sep_start = sep_start;
    link->label_sep_len = i - sep_start;
    link->has_label = 1;
    return 1;
}

static int uniform_run(dedsec_view input, size_t offset, size_t length,
                       uint8_t *kind) {
    size_t i;
    if (!length) return 0;
    *kind = input.ptr[offset];
    for (i = 1; i < length; ++i)
        if (input.ptr[offset + i] != *kind) return 0;
    return *kind == ' ' || *kind == '\t';
}

static void next_line(dedsec_view input, size_t start, size_t *end,
                      size_t *next) {
    size_t i = start;
    while (i < input.len && input.ptr[i] != '\n') ++i;
    *end = i;
    if (*end > start && input.ptr[*end - 1] == '\r') --*end;
    *next = i < input.len ? i + 1 : i;
}

static int lane_observation(dedsec_view input, const gem_link *link,
                            gem_lane lane, size_t *offset, size_t *length,
                            uint8_t *value) {
    uint8_t kind;
    if (lane == GEM_PREFIX_WIDTH) {
        *value = (uint8_t)(link->prefix_len & 1u);
        if (link->prefix_len) {
            *offset = link->prefix_start;
            *length = link->prefix_len;
        } else {
            /* Zero width is an observation only because the complete link
             * grammar proves that this prefix slot exists. */
            *offset = link->line_start;
            *length = link->url_end - link->line_start;
        }
        return 1;
    }
    if (lane == GEM_PREFIX_TYPE) {
        if (!uniform_run(input, link->prefix_start, link->prefix_len, &kind)) return 0;
        *offset = link->prefix_start;
        *length = link->prefix_len;
        *value = kind == '\t';
        return 1;
    }
    if (!link->has_label) return 0;
    if (lane == GEM_LABEL_WIDTH) {
        *offset = link->label_sep_start;
        *length = link->label_sep_len;
        *value = (uint8_t)(link->label_sep_len & 1u);
        return 1;
    }
    if (!uniform_run(input, link->label_sep_start, link->label_sep_len, &kind)) return 0;
    *offset = link->label_sep_start;
    *length = link->label_sep_len;
    *value = kind == '\t';
    return 1;
}

static void lane_names(gem_lane lane, const char **rule, const char **decoder) {
    if (lane == GEM_PREFIX_WIDTH) {
        *rule = "gemtext-prefix-width-parity";
        *decoder = "gemtext-prefix-width-low-bit";
    } else if (lane == GEM_PREFIX_TYPE) {
        *rule = "gemtext-prefix-space-tab";
        *decoder = "gemtext-prefix-space-tab-bits-msb";
    } else if (lane == GEM_LABEL_WIDTH) {
        *rule = "gemtext-label-width-parity";
        *decoder = "gemtext-label-width-low-bit";
    } else {
        *rule = "gemtext-label-space-tab";
        *decoder = "gemtext-label-space-tab-bits-msb";
    }
}

static dedsec_status scan_lane(dedsec_view input, gem_lane lane,
                               dedsec_finding_fn emit, void *user,
                               uint64_t *zero, uint64_t *one,
                               size_t *first, size_t *last) {
    size_t start = 0;
    const char *rule, *decoder;
    lane_names(lane, &rule, &decoder);
    while (start < input.len) {
        size_t end, next, offset, length;
        gem_link link;
        uint8_t value;
        next_line(input, start, &end, &next);
        if (parse_link(input, start, end, &link) &&
            lane_observation(input, &link, lane, &offset, &length, &value)) {
            dedsec_status s;
            if (!*zero && !*one) *first = offset;
            if (value) {
                if (*one == UINT64_MAX) return DEDSEC_ENOMEM;
                ++*one;
            } else {
                if (*zero == UINT64_MAX) return DEDSEC_ENOMEM;
                ++*zero;
            }
            *last = offset > SIZE_MAX - length ? SIZE_MAX : offset + length;
            s = dedsec_emit_symbol(emit, user, "gemtext", rule, decoder,
                                   offset, length, value, 1);
            if (s != DEDSEC_OK) return s;
        }
        if (next == start) break;
        start = next;
    }
    return DEDSEC_OK;
}

static dedsec_status gemtext_detect(void *context, dedsec_view input,
                                    dedsec_finding_fn emit, void *user) {
    size_t error = 0;
    gem_lane lane;
    dedsec_status s;
    (void)context;
    if ((!input.ptr && input.len) || !emit) return DEDSEC_EINVAL;
    s = dedsec_utf8_foreach(input, validate_utf8, NULL, &error);
    if (s == DEDSEC_EUTF8) return DEDSEC_OK; /* Encoding owns malformed UTF-8. */
    if (s != DEDSEC_OK) return s;
    for (lane = GEM_PREFIX_WIDTH; lane <= GEM_LABEL_TYPE; ++lane) {
        uint64_t zero = 0, one = 0, total, minority;
        size_t first = 0, last = 0;
        const char *rule, *decoder;
        lane_names(lane, &rule, &decoder);
        s = scan_lane(input, lane, emit, user, &zero, &one, &first, &last);
        if (s != DEDSEC_OK) return s;
        total = zero + one;
        minority = zero < one ? zero : one;
        if (zero >= 8 && one >= 8 && total >= 32 &&
            minority * 5u >= total) {
            s = dedsec_emit_finding(emit, user, "gemtext", rule, decoder,
                                    first, last >= first ? last - first : 0,
                                    45, total);
            if (s != DEDSEC_OK) return s;
        }
    }
    return DEDSEC_OK;
}

static dedsec_status gemtext_decode(void *context, dedsec_view input,
                                    const dedsec_decode_request *request,
                                    dedsec_bitstream *output) {
    gem_lane lane;
    size_t error = 0, start = 0;
    dedsec_status s;
    (void)context;
    if ((!input.ptr && input.len) || !request || !request->variant || !output)
        return DEDSEC_EINVAL;
    if (dedsec_streq(request->variant, "gemtext-prefix-width-low-bit"))
        lane = GEM_PREFIX_WIDTH;
    else if (dedsec_streq(request->variant, "gemtext-prefix-space-tab-bits-msb"))
        lane = GEM_PREFIX_TYPE;
    else if (dedsec_streq(request->variant, "gemtext-label-width-low-bit"))
        lane = GEM_LABEL_WIDTH;
    else if (dedsec_streq(request->variant, "gemtext-label-space-tab-bits-msb"))
        lane = GEM_LABEL_TYPE;
    else return DEDSEC_EUNSUPPORTED;
    s = dedsec_utf8_foreach(input, validate_utf8, NULL, &error);
    if (s != DEDSEC_OK) return s;
    while (start < input.len) {
        size_t end, next, offset, length;
        gem_link link;
        uint8_t value;
        next_line(input, start, &end, &next);
        if (parse_link(input, start, end, &link) &&
            lane_observation(input, &link, lane, &offset, &length, &value)) {
            s = dedsec_bitstream_append_bits(output, value, 1, 0);
            if (s != DEDSEC_OK) return s;
        }
        if (next == start) break;
        start = next;
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "gemtext", NULL, gemtext_detect, NULL, gemtext_decode
};

const dedsec_module *dedsec_builtin_gemtext_module(void) { return &module; }
