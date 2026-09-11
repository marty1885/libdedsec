#include <dedsec.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, dedsec_buffer *out) {
    FILE *file = fopen(path, "rb");
    uint8_t block[8192];
    size_t count;
    if (!file) {
        fprintf(stderr, "%s: %s\n", path, strerror(errno));
        return 0;
    }
    while ((count = fread(block, 1, sizeof(block), file)) != 0) {
        if (dedsec_buffer_append(out, block, count) != DEDSEC_OK) {
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

static const char *verdict_name(dedsec_plaintext_verdict verdict) {
    if (verdict == DEDSEC_PLAINTEXT_LIKELY) return "likely";
    if (verdict == DEDSEC_PLAINTEXT_POSSIBLE) return "possible";
    if (verdict == DEDSEC_PLAINTEXT_INSUFFICIENT) return "insufficient";
    return "reject";
}

int main(int argc, char **argv) {
    int i, failed = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE ...]\n", argv[0]);
        return 2;
    }
    puts("file\tverdict\tscore\tflags\tbit_offset\ttransform_depth\tdecoded_bytes\tsource_bits\tconsumed_bits\tignored_tail_bits\tassessed_tail_bits\tequal_score_interpretations");
    for (i = 1; i < argc; ++i) {
        dedsec_bitstream stream;
        dedsec_bitstream_filter_result result;
        dedsec_buffer_init(&stream.bytes);
        stream.bit_length = 0;
        if (!read_file(argv[i], &stream.bytes)) {
            dedsec_bitstream_free(&stream);
            failed = 1;
            continue;
        }
        if (stream.bytes.len > SIZE_MAX / 8) {
            fprintf(stderr, "%s: file is too large\n", argv[i]);
            dedsec_bitstream_free(&stream);
            failed = 1;
            continue;
        }
        stream.bit_length = stream.bytes.len * 8;
        if (dedsec_bitstream_filter(&stream, &result) != DEDSEC_OK) {
            fprintf(stderr, "%s: filter error\n", argv[i]);
            dedsec_bitstream_free(&stream);
            failed = 1;
            continue;
        }
        printf("%s\t%s\t%u\t%u\t%u\t%u\t%zu\t%zu\t%zu\t%u\t%u\t%zu\n", argv[i],
               verdict_name(result.verdict), result.score, result.flags,
               result.bit_offset, result.transform_depth, result.decoded_length,
               result.source_bit_length, result.source_bits_consumed,
               result.ignored_trailing_bits, result.assessed_trailing_bits,
               result.equal_score_interpretations);
        dedsec_bitstream_free(&stream);
    }
    return failed;
}
