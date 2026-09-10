/* Continuous carrier-anomaly features for paired ROC experiments. */
#include <dedsec.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct counts { size_t one, two; } counts;

static int count_gap(void *opaque, const dedsec_feature *feature) {
    counts *c = (counts *)opaque;
    if (feature->value == 1) ++c->one;
    else if (feature->value == 2) ++c->two;
    return 0;
}
static int count_unicode(void *opaque, const dedsec_scalar *scalar) {
    counts *c = (counts *)opaque;
    if (scalar->value == 0x200b || scalar->value == 0x200c) ++c->one;
    if (scalar->value >= 0xfe00 && scalar->value <= 0xfe0f) ++c->one;
    return 0;
}
static int read_file(const char *path, dedsec_buffer *out) {
    FILE *f = fopen(path, "rb");
    uint8_t block[8192];
    size_t n;
    if (!f) { fprintf(stderr, "%s: %s\n", path, strerror(errno)); return 0; }
    while ((n = fread(block, 1, sizeof(block), f)) != 0)
        if (dedsec_buffer_append(out, block, n) != DEDSEC_OK) { fclose(f); return 0; }
    if (ferror(f)) { fclose(f); return 0; }
    fclose(f); return 1;
}
int main(int argc, char **argv) {
    int i;
    if (argc < 3 || (strcmp(argv[1], "zero-width") && strcmp(argv[1], "variation") &&
                     strcmp(argv[1], "gap-width"))) {
        fprintf(stderr, "usage: %s {zero-width|variation|gap-width} FILE [FILE ...]\n", argv[0]);
        return 2;
    }
    puts("document\tscore\tprimary_count\teligible_count");
    for (i = 2; i < argc; ++i) {
        dedsec_buffer input;
        counts c = {0, 0};
        dedsec_status s;
        dedsec_buffer_init(&input);
        if (!read_file(argv[i], &input)) { dedsec_buffer_free(&input); return 1; }
        if (strcmp(argv[1], "gap-width") == 0) {
            s = dedsec_extract_features(DEDSEC_FEATURE_GAP_WIDTH,
                                        (dedsec_view){input.ptr, input.len}, count_gap, &c);
            if (s != DEDSEC_OK) { dedsec_buffer_free(&input); return 1; }
            /* Number of rare alternate-width choices: simple, monotonic and
             * deliberately independent of the bitstream's apparent entropy. */
            printf("%s\t%zu\t%zu\t%zu\n", argv[i], c.two, c.two, c.one + c.two);
        } else {
            s = dedsec_utf8_foreach((dedsec_view){input.ptr, input.len}, count_unicode, &c, NULL);
            if (s != DEDSEC_OK) { dedsec_buffer_free(&input); return 1; }
            printf("%s\t%zu\t%zu\t0\n", argv[i], c.one, c.one);
        }
        dedsec_buffer_free(&input);
    }
    return 0;
}
