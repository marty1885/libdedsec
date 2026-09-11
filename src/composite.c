#include "internal.h"

#include <stdlib.h>

static int compare_event_ptr(const void *left, const void *right) {
    const dedsec_finding *a = *(const dedsec_finding *const *)left;
    const dedsec_finding *b = *(const dedsec_finding *const *)right;
    if (a->byte_offset < b->byte_offset) return -1;
    if (a->byte_offset > b->byte_offset) return 1;
    if (a->byte_length < b->byte_length) return -1;
    if (a->byte_length > b->byte_length) return 1;
    return 0;
}

dedsec_status dedsec_symbols_glue_source_order(const dedsec_finding *events,
                                               size_t event_count,
                                               dedsec_bitstream *output) {
    const dedsec_finding **ordered;
    size_t i, previous_end = 0;
    dedsec_status status = DEDSEC_OK;
    if ((!events && event_count) || !output) return DEDSEC_EINVAL;
    output->bytes.len = 0;
    output->bit_length = 0;
    if (!event_count) return DEDSEC_ENOTFOUND;
    if (event_count > SIZE_MAX / sizeof(*ordered)) return DEDSEC_ENOMEM;
    ordered = (const dedsec_finding **)malloc(event_count * sizeof(*ordered));
    if (!ordered) return DEDSEC_ENOMEM;
    for (i = 0; i < event_count; ++i) {
        if (events[i].kind != DEDSEC_DETECTION_SYMBOL ||
            !events[i].symbol_width || events[i].symbol_width > 8 ||
            events[i].symbol_value >= (1u << events[i].symbol_width) ||
            !events[i].byte_length ||
            events[i].byte_offset > SIZE_MAX - events[i].byte_length) {
            status = DEDSEC_EINVAL;
            break;
        }
        ordered[i] = &events[i];
    }
    if (status == DEDSEC_OK) {
        qsort(ordered, event_count, sizeof(*ordered), compare_event_ptr);
        for (i = 0; i < event_count; ++i) {
            const dedsec_finding *event = ordered[i];
            if (i && event->byte_offset < previous_end) {
                status = DEDSEC_EINVAL;
                break;
            }
            previous_end = event->byte_offset + event->byte_length;
            status = dedsec_bitstream_append_bits(output, event->symbol_value,
                                                   event->symbol_width, 0);
            if (status != DEDSEC_OK) break;
        }
    }
    free(ordered);
    if (status != DEDSEC_OK) {
        output->bytes.len = 0;
        output->bit_length = 0;
    }
    return status;
}
