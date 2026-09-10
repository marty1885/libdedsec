#include "internal.h"

typedef struct utf8_sink { int unused; } utf8_sink;
static int ignore_scalar(void *user, const dedsec_scalar *scalar) {
    (void)user; (void)scalar; return 0;
}

static int continuation(uint8_t b) { return (b & 0xc0u) == 0x80u; }

static int standard_astral(const uint8_t *p, size_t n) {
    if (n < 4 || p[0] < 0xf0 || p[0] > 0xf4 ||
        !continuation(p[1]) || !continuation(p[2]) || !continuation(p[3])) return 0;
    if (p[0] == 0xf0 && p[1] < 0x90) return 0;
    if (p[0] == 0xf4 && p[1] > 0x8f) return 0;
    return 1;
}

static int cesu_astral(const uint8_t *p, size_t n) {
    return n >= 6 && p[0] == 0xed && p[1] >= 0xa0 && p[1] <= 0xaf &&
           continuation(p[2]) && p[3] == 0xed &&
           p[4] >= 0xb0 && p[4] <= 0xbf && continuation(p[5]);
}

static dedsec_status encoding_detect(void *context, dedsec_view input,
                                     dedsec_finding_fn emit, void *user) {
    size_t i, bad = 0, nuls = 0, escapes = 0, cesu = 0;
    dedsec_status status;
    (void)context;
    status = dedsec_utf8_foreach(input, ignore_scalar, NULL, &bad);
    if (status == DEDSEC_EUTF8) {
        status = dedsec_emit_finding(emit, user, "encoding", "invalid-utf8",
                                     NULL, bad, 1, 95, 1);
        if (status != DEDSEC_OK) return status;
    }
    for (i = 0; i < input.len; ++i) {
        if (input.ptr[i] == 0) ++nuls;
        if (i + 2 < input.len && input.ptr[i] == 0x1b &&
            input.ptr[i + 1] == '(' &&
            (input.ptr[i + 2] == 'B' || input.ptr[i + 2] == 'J')) ++escapes;
        if (cesu_astral(input.ptr + i, input.len - i)) ++cesu;
    }
    if (nuls) {
        status = dedsec_emit_finding(emit, user, "encoding", "embedded-nul",
                                     "after-nul", 0, input.len, 90, nuls);
        if (status != DEDSEC_OK) return status;
    }
    if (escapes >= 2) {
        status = dedsec_emit_finding(emit, user, "encoding",
                                     "iso2022-redundant-designations",
                                     "iso2022-designation-bits-msb",
                                     0, input.len, 75, escapes);
        if (status != DEDSEC_OK) return status;
    }
    if (cesu) {
        status = dedsec_emit_finding(emit, user, "encoding", "cesu8-surrogate-pairs",
                                     "utf8-cesu8-form-bits-msb", 0, input.len,
                                     90, cesu);
        if (status != DEDSEC_OK) return status;
    }
    if (input.len >= 3 && input.ptr[0] == 0xef && input.ptr[1] == 0xbb &&
        input.ptr[2] == 0xbf) {
        status = dedsec_emit_finding(emit, user, "encoding", "leading-utf8-bom",
                                     "strip-leading-bom", 0, 3, 15, 1);
    }
    return status == DEDSEC_EUTF8 ? DEDSEC_OK : status;
}

static dedsec_status encoding_decode(void *context, dedsec_view input,
                                     const dedsec_decode_request *request,
                                     dedsec_bitstream *output) {
    size_t i;
    dedsec_status status;
    (void)context;
    if (dedsec_streq(request->variant, "after-nul")) {
        for (i = 0; i < input.len && input.ptr[i] != 0; ++i) {}
        if (i == input.len) return DEDSEC_ENOTFOUND;
        for (++i; i < input.len; ++i) {
            status = dedsec_bitstream_append_bits(output, input.ptr[i], 8, 0);
            if (status != DEDSEC_OK) return status;
        }
        return DEDSEC_OK;
    }
    if (dedsec_streq(request->variant, "strip-leading-bom")) {
        if (input.len >= 3 && input.ptr[0] == 0xef && input.ptr[1] == 0xbb &&
            input.ptr[2] == 0xbf) {
            for (i = 3; i < input.len; ++i) {
                status = dedsec_bitstream_append_bits(output, input.ptr[i], 8, 0);
                if (status != DEDSEC_OK) return status;
            }
            return DEDSEC_OK;
        }
        return DEDSEC_ENOTFOUND;
    }
    if (!dedsec_streq(request->variant, "iso2022-designation-bits-msb"))
        if (!dedsec_streq(request->variant, "utf8-cesu8-form-bits-msb"))
            return DEDSEC_EUNSUPPORTED;
    if (dedsec_streq(request->variant, "utf8-cesu8-form-bits-msb")) {
        for (i = 0; i < input.len;) {
            unsigned bit;
            size_t step;
            if (standard_astral(input.ptr + i, input.len - i)) { bit = 0; step = 4; }
            else if (cesu_astral(input.ptr + i, input.len - i)) { bit = 1; step = 6; }
            else { ++i; continue; }
            status = dedsec_bitstream_append_bits(output, (uint8_t)bit, 1, 0);
            if (status != DEDSEC_OK) return status;
            i += step;
        }
        return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
    }
    for (i = 0; i + 2 < input.len; ++i) {
        if (input.ptr[i] == 0x1b && input.ptr[i + 1] == '(' &&
            (input.ptr[i + 2] == 'B' || input.ptr[i + 2] == 'J')) {
            status = dedsec_bitstream_append_bits(output,
                                                   input.ptr[i + 2] == 'J', 1, 0);
            if (status != DEDSEC_OK) return status;
            i += 2;
        }
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "encoding", NULL, encoding_detect, NULL, encoding_decode
};
const dedsec_module *dedsec_builtin_encoding_module(void) { return &module; }
