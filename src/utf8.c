#include "internal.h"

dedsec_status dedsec_utf8_foreach(dedsec_view input,
                                  dedsec_scalar_fn emit, void *user,
                                  size_t *error_offset) {
    size_t i = 0;
    if ((!input.ptr && input.len) || !emit) return DEDSEC_EINVAL;
    while (i < input.len) {
        size_t start = i;
        uint8_t b0 = input.ptr[i++];
        uint32_t cp;
        unsigned need, j;
        dedsec_scalar scalar;
        if (b0 <= 0x7f) { cp = b0; need = 0; }
        else if (b0 >= 0xc2 && b0 <= 0xdf) { cp = b0 & 0x1f; need = 1; }
        else if (b0 >= 0xe0 && b0 <= 0xef) { cp = b0 & 0x0f; need = 2; }
        else if (b0 >= 0xf0 && b0 <= 0xf4) { cp = b0 & 0x07; need = 3; }
        else goto invalid;
        if (need > input.len - i) goto invalid;
        for (j = 0; j < need; ++j) {
            uint8_t bx = input.ptr[i++];
            if ((bx & 0xc0) != 0x80) goto invalid;
            if (j == 0 && b0 == 0xe0 && bx < 0xa0) goto invalid;
            if (j == 0 && b0 == 0xed && bx > 0x9f) goto invalid;
            if (j == 0 && b0 == 0xf0 && bx < 0x90) goto invalid;
            if (j == 0 && b0 == 0xf4 && bx > 0x8f) goto invalid;
            cp = (cp << 6) | (uint32_t)(bx & 0x3f);
        }
        scalar.value = cp; scalar.byte_offset = start;
        scalar.byte_length = (uint8_t)(i - start);
        if (emit(user, &scalar)) return DEDSEC_ESTOP;
        continue;
invalid:
        if (error_offset) *error_offset = start;
        return DEDSEC_EUTF8;
    }
    return DEDSEC_OK;
}
