#include "internal.h"

#include <stdlib.h>
#include <string.h>

static void text_init(dedsec_text *t) {
    dedsec_buffer_init(&t->bytes); t->origin = NULL; t->origin_count = 0;
    t->origin_capacity = 0;
}
static void text_free(dedsec_text *t) {
    dedsec_buffer_free(&t->bytes); free(t->origin); t->origin = NULL;
    t->origin_count = 0; t->origin_capacity = 0;
}
static dedsec_status text_from_view(dedsec_view v, dedsec_text *t) {
    size_t i;
    dedsec_status s;
    text_init(t);
    s = dedsec_buffer_append(&t->bytes, v.ptr, v.len);
    if (s != DEDSEC_OK) return s;
    if (!v.len) return DEDSEC_OK;
    t->origin = (size_t *)malloc(v.len * sizeof(*t->origin));
    if (!t->origin) { text_free(t); return DEDSEC_ENOMEM; }
    for (i = 0; i < v.len; ++i) t->origin[i] = i;
    t->origin_count = v.len; t->origin_capacity = v.len;
    return DEDSEC_OK;
}
static dedsec_status text_push(dedsec_text *out, uint8_t b, size_t origin) {
    size_t *next;
    size_t capacity;
    dedsec_status s = dedsec_buffer_push(&out->bytes, b);
    if (s != DEDSEC_OK) return s;
    if (out->origin_count == out->origin_capacity) {
        capacity = out->origin_capacity ? out->origin_capacity * 2 : 64;
        next = (size_t *)realloc(out->origin, capacity * sizeof(*next));
        if (!next) { --out->bytes.len; return DEDSEC_ENOMEM; }
        out->origin = next; out->origin_capacity = capacity;
    }
    out->origin[out->origin_count++] = origin;
    return DEDSEC_OK;
}
static dedsec_status copy_range(const dedsec_text *in, dedsec_text *out,
                                size_t offset, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i) {
        dedsec_status s = text_push(out, in->bytes.ptr[offset + i], in->origin[offset + i]);
        if (s != DEDSEC_OK) return s;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_transform_ascii_casefold(void *context,
                                              const dedsec_text *input,
                                              dedsec_text *output) {
    size_t i;
    (void)context; text_init(output);
    for (i = 0; i < input->bytes.len; ++i) {
        uint8_t b = input->bytes.ptr[i];
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + ('a' - 'A'));
        if (text_push(output, b, input->origin[i]) != DEDSEC_OK) { text_free(output); return DEDSEC_ENOMEM; }
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_transform_collapse_hspace(void *context,
                                               const dedsec_text *input,
                                               dedsec_text *output) {
    size_t i = 0;
    (void)context; text_init(output);
    while (i < input->bytes.len) {
        if (dedsec_is_hspace(input->bytes.ptr[i])) {
            size_t origin = input->origin[i];
            while (i < input->bytes.len && dedsec_is_hspace(input->bytes.ptr[i])) ++i;
            if (text_push(output, ' ', origin) != DEDSEC_OK) goto oom;
        } else {
            if (text_push(output, input->bytes.ptr[i], input->origin[i]) != DEDSEC_OK) goto oom;
            ++i;
        }
    }
    return DEDSEC_OK;
oom: text_free(output); return DEDSEC_ENOMEM;
}

dedsec_status dedsec_transform_delete_hspace(void *context,
                                             const dedsec_text *input,
                                             dedsec_text *output) {
    size_t i;
    (void)context; text_init(output);
    for (i = 0; i < input->bytes.len; ++i)
        if (!dedsec_is_hspace(input->bytes.ptr[i]) &&
            text_push(output, input->bytes.ptr[i], input->origin[i]) != DEDSEC_OK) {
            text_free(output); return DEDSEC_ENOMEM;
        }
    return DEDSEC_OK;
}

static uint32_t raw_cp(const uint8_t *p, size_t n) {
    if (n == 1) return p[0];
    if (n == 2) return ((uint32_t)(p[0]&0x1f)<<6) | (p[1]&0x3f);
    if (n == 3) return ((uint32_t)(p[0]&0x0f)<<12) | ((uint32_t)(p[1]&0x3f)<<6) | (p[2]&0x3f);
    return ((uint32_t)(p[0]&7)<<18) | ((uint32_t)(p[1]&0x3f)<<12) |
           ((uint32_t)(p[2]&0x3f)<<6) | (p[3]&0x3f);
}
static int strip_cp(uint32_t cp) {
    return cp == 0x00ad || cp == 0x034f || cp == 0x061c ||
           (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) ||
           (cp >= 0x2060 && cp <= 0x206f) || cp == 0xfeff ||
           (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0001 && cp <= 0xe007f) ||
           (cp >= 0xe0100 && cp <= 0xe01ef);
}
static int validate_sink(void *u, const dedsec_scalar *s) { (void)u; (void)s; return 0; }

dedsec_status dedsec_transform_strip_known_ignorables(void *context,
                                                      const dedsec_text *input,
                                                      dedsec_text *output) {
    size_t i = 0, error = 0;
    dedsec_view v = { input->bytes.ptr, input->bytes.len };
    dedsec_status s;
    (void)context; text_init(output);
    s = dedsec_utf8_foreach(v, validate_sink, NULL, &error);
    if (s != DEDSEC_OK) return s;
    while (i < input->bytes.len) {
        uint8_t b = input->bytes.ptr[i];
        size_t n = b < 0x80 ? 1 : ((b & 0xe0) == 0xc0 ? 2 : ((b & 0xf0) == 0xe0 ? 3 : 4));
        if (!strip_cp(raw_cp(input->bytes.ptr + i, n))) {
            s = copy_range(input, output, i, n);
            if (s != DEDSEC_OK) { text_free(output); return s; }
        }
        i += n;
    }
    return DEDSEC_OK;
}

static dedsec_status run_chain(dedsec_view v, const dedsec_chain *chain,
                               dedsec_text *result) {
    dedsec_text current, next;
    size_t i;
    dedsec_status s = text_from_view(v, &current);
    if (s != DEDSEC_OK) return s;
    for (i = 0; i < chain->count; ++i) {
        if (!chain->steps[i].apply) { text_free(&current); return DEDSEC_EINVAL; }
        text_init(&next);
        s = chain->steps[i].apply(chain->steps[i].context, &current, &next);
        text_free(&current);
        if (s != DEDSEC_OK) return s;
        current = next;
    }
    *result = current; return DEDSEC_OK;
}

dedsec_status dedsec_search(dedsec_view haystack,
                            const dedsec_view *needles, size_t needle_count,
                            const dedsec_chain *chains, size_t chain_count,
                            dedsec_match_fn emit, void *user) {
    size_t ci, ni, pos;
    if ((!haystack.ptr && haystack.len) || (!needles && needle_count) ||
        (!chains && chain_count) || !emit) return DEDSEC_EINVAL;
    for (ci = 0; ci < chain_count; ++ci) {
        dedsec_text h;
        dedsec_status s = run_chain(haystack, &chains[ci], &h);
        if (s != DEDSEC_OK) return s;
        for (ni = 0; ni < needle_count; ++ni) {
            dedsec_text n;
            s = run_chain(needles[ni], &chains[ci], &n);
            if (s != DEDSEC_OK) { text_free(&h); return s; }
            if (n.bytes.len) for (pos = 0; pos + n.bytes.len <= h.bytes.len; ++pos) {
                if (memcmp(h.bytes.ptr + pos, n.bytes.ptr, n.bytes.len) == 0) {
                    dedsec_match m = { ci, ni, pos, h.origin[pos] };
                    if (emit(user, &m)) { text_free(&n); text_free(&h); return DEDSEC_ESTOP; }
                }
            }
            text_free(&n);
        }
        text_free(&h);
    }
    return DEDSEC_OK;
}
