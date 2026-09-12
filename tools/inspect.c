#include <dedsec.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct event_list {
    dedsec_finding *items;
    size_t count, capacity;
    int oom;
} event_list;

typedef struct lane {
    const char *module;
    const char *rule;
    const char *decoder;
    size_t symbols;
    size_t bits;
    size_t zero_bits;
    size_t one_bits;
} lane;

static const char *status_name(dedsec_status status) {
    switch (status) {
    case DEDSEC_OK: return "ok";
    case DEDSEC_EINVAL: return "invalid argument";
    case DEDSEC_ENOMEM: return "out of memory";
    case DEDSEC_EUTF8: return "invalid UTF-8";
    case DEDSEC_ENOTFOUND: return "not found";
    case DEDSEC_EUNSUPPORTED: return "unsupported";
    case DEDSEC_ESTOP: return "stopped";
    }
    return "unknown error";
}

static const char *verdict_name(dedsec_plaintext_verdict verdict) {
    switch (verdict) {
    case DEDSEC_PLAINTEXT_REJECT: return "reject";
    case DEDSEC_PLAINTEXT_INSUFFICIENT: return "insufficient";
    case DEDSEC_PLAINTEXT_POSSIBLE: return "possible";
    case DEDSEC_PLAINTEXT_LIKELY: return "likely";
    }
    return "unknown";
}

static int collect_event(void *opaque, const dedsec_finding *event) {
    event_list *list = (event_list *)opaque;
    dedsec_finding *next;
    size_t capacity;
    if (list->count == list->capacity) {
        capacity = list->capacity ? list->capacity * 2 : 256;
        next = (dedsec_finding *)realloc(list->items, capacity * sizeof(*next));
        if (!next) { list->oom = 1; return 1; }
        list->items = next;
        list->capacity = capacity;
    }
    list->items[list->count++] = *event;
    return 0;
}

static int read_file(const char *path, dedsec_buffer *output) {
    uint8_t block[8192];
    FILE *file = fopen(path, "rb");
    size_t count;
    if (!file) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return 0;
    }
    while ((count = fread(block, 1, sizeof(block), file)) != 0) {
        if (dedsec_buffer_append(output, block, count) != DEDSEC_OK) {
            fprintf(stderr, "%s: out of memory\n", path);
            fclose(file);
            return 0;
        }
    }
    if (ferror(file)) {
        fprintf(stderr, "%s: read error\n", path);
        fclose(file);
        return 0;
    }
    fclose(file);
    return 1;
}

static void location(dedsec_view input, size_t offset, size_t *line, size_t *column) {
    size_t i;
    *line = 1;
    *column = 1;
    if (offset > input.len) offset = input.len;
    for (i = 0; i < offset; ++i) {
        if (input.ptr[i] == '\n') { ++*line; *column = 1; }
        else ++*column;
    }
}

static int same_lane(const lane *item, const dedsec_finding *event) {
    return strcmp(item->module, event->module_id) == 0 &&
           strcmp(item->rule, event->rule_id) == 0 &&
           strcmp(item->decoder, event->decoder_hint) == 0;
}

static unsigned bit_at(const dedsec_bitstream *stream, size_t bit) {
    return (stream->bytes.ptr[bit / 8] >> (7u - (unsigned)(bit % 8))) & 1u;
}

static void print_bits(const dedsec_bitstream *stream) {
    size_t i, limit = stream->bit_length < 96 ? stream->bit_length : 96;
    for (i = 0; i < limit; ++i) {
        if (i && i % 8 == 0) putchar(' ');
        putchar(bit_at(stream, i) ? '1' : '0');
    }
    if (limit < stream->bit_length) printf(" ...");
}

static void print_span(dedsec_view input, size_t offset, size_t length) {
    size_t i, limit = length < 32 ? length : 32;
    putchar('"');
    for (i = 0; i < limit && offset + i < input.len; ++i) {
        unsigned c = input.ptr[offset + i];
        if (c == '\\' || c == '"') printf("\\%c", c);
        else if (c == '\n') printf("\\n");
        else if (c == '\r') printf("\\r");
        else if (c == '\t') printf("\\t");
        else if (c >= 0x20 && c < 0x7f) putchar((int)c);
        else printf("\\x%02x", c);
    }
    if (limit < length) printf("...");
    putchar('"');
}

static int inspect_file(const dedsec_registry *registry, const char *path,
                        int show_symbols, const char *selected_lane,
                        dedsec_detection_mode mode) {
    dedsec_buffer bytes;
    dedsec_view input;
    event_list events = {0};
    lane *lanes = NULL;
    size_t lane_count = 0, lane_capacity = 0, findings = 0, observations = 0;
    size_t i, j;
    dedsec_status status;
    int ok = 0, matched_lane = selected_lane == NULL;
    dedsec_buffer_init(&bytes);
    if (!read_file(path, &bytes)) { dedsec_buffer_free(&bytes); return 0; }
    input.ptr = bytes.ptr;
    input.len = bytes.len;
    status = dedsec_detect_all_mode(registry, input, mode, collect_event, &events);
    if (status == DEDSEC_ESTOP && events.oom) status = DEDSEC_ENOMEM;
    if (status != DEDSEC_OK) {
        fprintf(stderr, "%s: detection failed: %s\n", path, status_name(status));
        free(events.items);
        dedsec_buffer_free(&bytes);
        return 0;
    }
    printf("FILE %s (%zu bytes)\n", path, input.len);
    for (i = 0; i < events.count; ++i) {
        dedsec_finding *event = &events.items[i];
        if (event->kind == DEDSEC_DETECTION_FINDING) {
            size_t line, column;
            location(input, event->byte_offset, &line, &column);
            printf("FINDING %s/%s decoder=%s score=%u evidence=%llu "
                   "span=%zu..%zu line=%zu:%zu\n",
                   event->module_id, event->rule_id,
                   event->decoder_hint ? event->decoder_hint : "-", event->score,
                   (unsigned long long)event->evidence, event->byte_offset,
                   event->byte_offset + event->byte_length, line, column);
            ++findings;
        } else if (event->kind == DEDSEC_DETECTION_OBSERVATION) ++observations;
        else if (event->decoder_hint) {
            for (j = 0; j < lane_count && !same_lane(&lanes[j], event); ++j) {}
            if (j == lane_count) {
                lane *next;
                size_t capacity;
                if (lane_count == lane_capacity) {
                    capacity = lane_capacity ? lane_capacity * 2 : 16;
                    next = (lane *)realloc(lanes, capacity * sizeof(*next));
                    if (!next) { fprintf(stderr, "%s: out of memory\n", path); goto done; }
                    lanes = next;
                    lane_capacity = capacity;
                }
                lanes[j] = (lane){event->module_id, event->rule_id,
                                  event->decoder_hint, 0, 0, 0, 0};
                ++lane_count;
            }
            ++lanes[j].symbols;
            lanes[j].bits += event->symbol_width;
            {
                unsigned k;
                for (k = 0; k < event->symbol_width; ++k) {
                    unsigned bit = (event->symbol_value >>
                        (event->symbol_width - 1u - k)) & 1u;
                    if (bit) ++lanes[j].one_bits; else ++lanes[j].zero_bits;
                }
            }
        }
    }
    if (!findings) printf("FINDINGS none\n");
    printf("SUMMARY findings=%zu symbol_lanes=%zu observations=%zu\n",
           findings, lane_count, observations);
    for (i = 0; i < lane_count; ++i) {
        dedsec_bitstream stream;
        dedsec_bitstream_filter_result filter;
        char lane_name[512];
        int wanted;
        snprintf(lane_name, sizeof(lane_name), "%s:%s", lanes[i].module,
                 lanes[i].decoder);
        wanted = !selected_lane || strcmp(selected_lane, lane_name) == 0;
        if (!wanted) continue;
        matched_lane = 1;
        dedsec_bitstream_init(&stream);
        for (j = 0; j < events.count; ++j) {
            dedsec_finding *event = &events.items[j];
            if (event->kind == DEDSEC_DETECTION_SYMBOL && same_lane(&lanes[i], event) &&
                dedsec_bitstream_append_bits(&stream, event->symbol_value,
                                             event->symbol_width, 0) != DEDSEC_OK) {
                fprintf(stderr, "%s: out of memory\n", path);
                dedsec_bitstream_free(&stream);
                goto done;
            }
        }
        printf("LANE %s rule=%s symbols=%zu bits=%zu zero=%zu one=%zu\n",
               lane_name, lanes[i].rule, lanes[i].symbols, lanes[i].bits,
               lanes[i].zero_bits, lanes[i].one_bits);
        printf("  bits: "); print_bits(&stream); putchar('\n');
        if (dedsec_bitstream_filter(&stream, &filter) == DEDSEC_OK)
            printf("  filter: %s score=%u flags=0x%08x offset=%u "
                   "consumed=%zu ignored-tail=%u assessed-tail=%u\n",
                   verdict_name(filter.verdict), filter.score, filter.flags,
                   filter.bit_offset, filter.source_bits_consumed,
                   filter.ignored_trailing_bits, filter.assessed_trailing_bits);
        if (show_symbols) {
            for (j = 0; j < events.count; ++j) {
                dedsec_finding *event = &events.items[j];
                size_t line, column;
                if (event->kind != DEDSEC_DETECTION_SYMBOL ||
                    !same_lane(&lanes[i], event)) continue;
                location(input, event->byte_offset, &line, &column);
                printf("  SYMBOL bit=%u/%u span=%zu..%zu line=%zu:%zu source=",
                       event->symbol_value, event->symbol_width, event->byte_offset,
                       event->byte_offset + event->byte_length, line, column);
                print_span(input, event->byte_offset, event->byte_length);
                putchar('\n');
            }
        }
        dedsec_bitstream_free(&stream);
    }
    if (!matched_lane) {
        fprintf(stderr, "%s: selected lane is not present: %s\n",
                path, selected_lane);
        goto done;
    }
    ok = 1;
done:
    free(lanes);
    free(events.items);
    dedsec_buffer_free(&bytes);
    return ok;
}

static void usage(const char *program) {
    fprintf(stderr, "usage: %s [--natural-text] [--symbols] "
            "[--lane MODULE:DECODER] FILE [FILE ...]\n",
            program);
}

int main(int argc, char **argv) {
    dedsec_registry registry;
    const char *selected_lane = NULL;
    dedsec_detection_mode mode = DEDSEC_DETECT_DEFAULT;
    int show_symbols = 0, first = 1, i, ok = 1;
    while (first < argc && argv[first][0] == '-') {
        if (strcmp(argv[first], "--symbols") == 0) show_symbols = 1;
        else if (strcmp(argv[first], "--natural-text") == 0)
            mode = DEDSEC_DETECT_NATURAL_TEXT;
        else if (strcmp(argv[first], "--lane") == 0 && first + 1 < argc)
            selected_lane = argv[++first];
        else { usage(argv[0]); return 2; }
        ++first;
    }
    if (first == argc) { usage(argv[0]); return 2; }
    dedsec_registry_init(&registry);
    if (dedsec_registry_add_builtins(&registry) != DEDSEC_OK) {
        fprintf(stderr, "could not initialize built-in modules\n");
        return 1;
    }
    for (i = first; i < argc; ++i)
        if (!inspect_file(&registry, argv[i], show_symbols, selected_lane, mode))
            ok = 0;
    dedsec_registry_free(&registry);
    return ok ? 0 : 1;
}
