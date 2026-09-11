#include "internal.h"

#include <string.h>

/* This is a registry of reviewed Unicode representation identities, not a
 * general synonym matcher. Additions need an exact carrier, a narrowly stated
 * equivalence claim, negative controls, and independent validation. */
typedef struct identity_pair {
    const char *rule;
    const char *variant;
    dedsec_view zero;
    dedsec_view one;
} identity_pair;

static const uint8_t space_zero[] = {0x20};
static const uint8_t space_one[] = {0xc2, 0xa0};
static const uint8_t acute_zero[] = {0xc3, 0xa9};
static const uint8_t acute_one[] = {0x65, 0xcc, 0x81};
static const uint8_t hyphen_zero[] = {0x2d};
static const uint8_t hyphen_one[] = {0xe2, 0x80, 0x91};
static const uint8_t mark_order_zero[] = {0x61, 0xcc, 0xa3, 0xcc, 0x81};
static const uint8_t mark_order_one[] = {0x61, 0xcc, 0x81, 0xcc, 0xa3};

static const identity_pair pairs[] = {
    {"space-identity", "space-identity-bits",
     {space_zero, sizeof(space_zero)}, {space_one, sizeof(space_one)}},
    {"canonical-e-acute-identity", "canonical-e-acute-identity-bits",
     {acute_zero, sizeof(acute_zero)}, {acute_one, sizeof(acute_one)}},
    {"hyphen-identity", "hyphen-identity-bits",
     {hyphen_zero, sizeof(hyphen_zero)}, {hyphen_one, sizeof(hyphen_one)}},
    {"canonical-combining-order-identity", "canonical-combining-order-bits",
     {mark_order_zero, sizeof(mark_order_zero)},
     {mark_order_one, sizeof(mark_order_one)}}
};

static int validate_scalar(void *opaque, const dedsec_scalar *scalar) {
    (void)opaque;
    (void)scalar;
    return 0;
}

static int matches(dedsec_view input, size_t at, dedsec_view token) {
    return token.len <= input.len - at &&
           memcmp(input.ptr + at, token.ptr, token.len) == 0;
}

static dedsec_status scan_pair(const identity_pair *pair, dedsec_view input,
                               dedsec_bitstream *output, uint64_t *zeros,
                               uint64_t *ones, size_t *first, size_t *last) {
    size_t at = 0;
    while (at < input.len) {
        if (matches(input, at, pair->zero)) {
            if (*zeros == UINT64_MAX) return DEDSEC_ENOMEM;
            if (!*zeros && !*ones) *first = at;
            ++*zeros;
            *last = at + pair->zero.len;
            if (output) {
                dedsec_status s = dedsec_bitstream_append_bits(output, 0, 1, 0);
                if (s != DEDSEC_OK) return s;
            }
            at += pair->zero.len;
        } else if (matches(input, at, pair->one)) {
            if (*ones == UINT64_MAX) return DEDSEC_ENOMEM;
            if (!*zeros && !*ones) *first = at;
            ++*ones;
            *last = at + pair->one.len;
            if (output) {
                dedsec_status s = dedsec_bitstream_append_bits(output, 1, 1, 0);
                if (s != DEDSEC_OK) return s;
            }
            at += pair->one.len;
        } else {
            ++at;
        }
    }
    return DEDSEC_OK;
}

static dedsec_status emit_pair_symbols(const identity_pair *pair,
                                       dedsec_view input,
                                       dedsec_finding_fn emit, void *user) {
    size_t at = 0;
    while (at < input.len) {
        dedsec_view token;
        uint8_t value;
        dedsec_status s;
        if (matches(input, at, pair->zero)) {
            token = pair->zero;
            value = 0;
        } else if (matches(input, at, pair->one)) {
            token = pair->one;
            value = 1;
        } else {
            ++at;
            continue;
        }
        s = dedsec_emit_symbol(emit, user, "identity", pair->rule,
                               pair->variant, at, token.len, value, 1);
        if (s != DEDSEC_OK) return s;
        at += token.len;
    }
    return DEDSEC_OK;
}

static dedsec_status identity_detect(void *context, dedsec_view input,
                                     dedsec_finding_fn emit, void *user) {
    size_t error = 0;
    size_t i;
    dedsec_status s;
    (void)context;
    s = dedsec_utf8_foreach(input, validate_scalar, NULL, &error);
    if (s == DEDSEC_EUTF8) return DEDSEC_OK; /* Encoding owns malformed UTF-8. */
    if (s != DEDSEC_OK) return s;
    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); ++i) {
        uint64_t zeros = 0, ones = 0, total, minority;
        size_t first = 0, last = 0;
        s = scan_pair(&pairs[i], input, NULL, &zeros, &ones, &first, &last);
        if (s != DEDSEC_OK) return s;
        s = emit_pair_symbols(&pairs[i], input, emit, user);
        if (s != DEDSEC_OK) return s;
        total = zeros + ones;
        minority = zeros < ones ? zeros : ones;
        /* A known identity is ordinary typography by default. Promote only a
         * recurrent, reasonably balanced binary lane; framing remains the
         * caller's evidentiary responsibility. */
        if (zeros >= 8 && ones >= 8 && total >= 32 &&
            minority >= (total + 4u) / 5u) {
            uint32_t score = 55u + (total >= 45u ? 20u : (uint32_t)(total - 25u));
            s = dedsec_emit_finding(emit, user, "identity", pairs[i].rule,
                                    pairs[i].variant, first, last - first,
                                    score, total);
            if (s != DEDSEC_OK) return s;
        }
    }
    return DEDSEC_OK;
}

static dedsec_status identity_decode(void *context, dedsec_view input,
                                     const dedsec_decode_request *request,
                                     dedsec_bitstream *output) {
    size_t error = 0;
    size_t i;
    dedsec_status s;
    uint64_t zeros = 0, ones = 0;
    size_t first = 0, last = 0;
    (void)context;
    s = dedsec_utf8_foreach(input, validate_scalar, NULL, &error);
    if (s != DEDSEC_OK) return s;
    for (i = 0; i < sizeof(pairs) / sizeof(pairs[0]); ++i) {
        if (dedsec_streq(request->variant, pairs[i].variant)) {
            s = scan_pair(&pairs[i], input, output, &zeros, &ones, &first, &last);
            if (s != DEDSEC_OK) return s;
            return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
        }
    }
    return DEDSEC_EUNSUPPORTED;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "identity", NULL, identity_detect, NULL, identity_decode
};

const dedsec_module *dedsec_builtin_identity_module(void) { return &module; }
