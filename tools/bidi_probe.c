#include <dedsec.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct probe_findings {
    size_t total;
    uint32_t max_score;
    uint32_t bidi_score;
    uint64_t bidi_evidence;
    uint32_t ignorable_score;
    uint64_t ignorable_evidence;
    uint32_t binary_score;
    uint64_t binary_evidence;
} probe_findings;

static int collect_finding(void *opaque, const dedsec_finding *finding) {
    probe_findings *result = (probe_findings *)opaque;
    ++result->total;
    if (finding->score > result->max_score) result->max_score = finding->score;
    if (strcmp(finding->rule_id, "bidi-controls") == 0) {
        result->bidi_score = finding->score;
        result->bidi_evidence = finding->evidence;
    } else if (strcmp(finding->rule_id, "default-ignorable-candidates") == 0) {
        result->ignorable_score = finding->score;
        result->ignorable_evidence = finding->evidence;
    } else if (strcmp(finding->rule_id, "binary-bidi-isolates") == 0) {
        result->binary_score = finding->score;
        result->binary_evidence = finding->evidence;
    }
    return 0;
}

static int read_file(const char *path, dedsec_buffer *output) {
    FILE *file = fopen(path, "rb");
    uint8_t block[8192];
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

static const char *verdict_name(dedsec_plaintext_verdict verdict) {
    if (verdict == DEDSEC_PLAINTEXT_LIKELY) return "likely";
    if (verdict == DEDSEC_PLAINTEXT_POSSIBLE) return "possible";
    if (verdict == DEDSEC_PLAINTEXT_INSUFFICIENT) return "insufficient";
    return "reject";
}

int main(int argc, char **argv) {
    dedsec_decode_request request = {"bidi-isolate-bits-msb", 0, NULL, 0};
    dedsec_registry registry;
    int i, failed = 0;
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE ...]\n", argv[0]);
        return 2;
    }
    dedsec_registry_init(&registry);
    if (dedsec_registry_add_builtins(&registry) != DEDSEC_OK) {
        fprintf(stderr, "could not initialize built-in modules\n");
        return 1;
    }
    puts("file\tfindings\tmax_score\tbidi_score\tbidi_evidence\tignorable_score\tignorable_evidence\tbinary_score\tbinary_evidence\textracted_bits\tplaintext_verdict\tplaintext_score\tplaintext_flags\ttransform_depth\tdecoded_bytes");
    for (i = 1; i < argc; ++i) {
        dedsec_buffer input;
        dedsec_bitstream bits;
        dedsec_bitstream_filter_result filter = {
            .verdict = DEDSEC_PLAINTEXT_INSUFFICIENT
        };
        probe_findings findings = {0};
        dedsec_status status;
        dedsec_buffer_init(&input);
        dedsec_bitstream_init(&bits);
        if (!read_file(argv[i], &input)) {
            failed = 1;
            goto next;
        }
        status = dedsec_detect_all(&registry, (dedsec_view){input.ptr, input.len},
                                   collect_finding, &findings);
        if (status != DEDSEC_OK) {
            fprintf(stderr, "%s: detector error\n", argv[i]);
            failed = 1;
            goto next;
        }
        status = dedsec_decode_bits(&registry, "unicode",
                                    (dedsec_view){input.ptr, input.len},
                                    &request, &bits);
        if (status == DEDSEC_OK) {
            status = dedsec_bitstream_filter(&bits, &filter);
            if (status != DEDSEC_OK) {
                fprintf(stderr, "%s: filter error\n", argv[i]);
                failed = 1;
                goto next;
            }
        } else if (status != DEDSEC_ENOTFOUND) {
            fprintf(stderr, "%s: bidi extraction error\n", argv[i]);
            failed = 1;
            goto next;
        }
        printf("%s\t%zu\t%u\t%u\t%llu\t%u\t%llu\t%u\t%llu\t%zu\t%s\t%u\t%u\t%u\t%zu\n",
               argv[i], findings.total, findings.max_score, findings.bidi_score,
               (unsigned long long)findings.bidi_evidence, findings.ignorable_score,
               (unsigned long long)findings.ignorable_evidence, findings.binary_score,
               (unsigned long long)findings.binary_evidence, bits.bit_length,
               verdict_name(filter.verdict), filter.score, filter.flags,
               filter.transform_depth, filter.decoded_length);
next:
        dedsec_bitstream_free(&bits);
        dedsec_buffer_free(&input);
    }
    dedsec_registry_free(&registry);
    return failed;
}
