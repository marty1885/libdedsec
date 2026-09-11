/* Reproducible exploratory benchmark; it does not classify documents. */
#include <dedsec.h>

#include <errno.h>
#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct lane { const char *module; const char *variant; } lane;
static const lane lanes[] = {
    {"unicode", "tags-ascii"},
    {"unicode", "zwsp-zwnj-msb"},
    {"unicode", "variation-nibbles"},
    {"unicode", "bidi-isolate-bits-msb"},
    {"encoding", "iso2022-designation-bits-msb"},
    {"encoding", "utf8-cesu8-form-bits-msb"},
    {"layout", "trailing-space-bits"},
    {"layout", "gap-width-bits"},
    {"layout", "word-case-bits"},
    {"layout", "comma-semicolon-bits"},
    {"layout", "period-question-bits"},
    {"layout", "word-length-parity"},
    {"layout", "line-length-parity"},
    {"structure", "line-ending-bits-lf-zero"},
    {"structure", "line-ending-bits-crlf-zero"},
    {"structure", "sentence-byte-parity"},
    {"structure", "sentence-codepoint-parity"},
    {"structure", "sentence-latin-count-parity"},
    {"structure", "paragraph-byte-parity"},
    {"structure", "paragraph-codepoint-parity"},
    {"markdown", "markdown-ul-marker-bits"},
    {"surface", "base64-rfc4648"},
    {"surface", "base32-rfc4648"},
    {"surface", "base32-crockford"}
};

typedef struct finding_stats {
    size_t count[sizeof(lanes) / sizeof(lanes[0])];
    uint32_t max_score[sizeof(lanes) / sizeof(lanes[0])];
} finding_stats;

static int collect_finding(void *opaque, const dedsec_finding *finding) {
    finding_stats *stats = (finding_stats *)opaque;
    size_t i;
    if (!finding->decoder_hint) return 0;
    for (i = 0; i < sizeof(lanes) / sizeof(lanes[0]); ++i) {
        if (strcmp(lanes[i].module, finding->module_id) == 0 &&
            strcmp(lanes[i].variant, finding->decoder_hint) == 0) {
            ++stats->count[i];
            if (finding->score > stats->max_score[i])
                stats->max_score[i] = finding->score;
        }
    }
    return 0;
}

static int read_file(const char *path, dedsec_buffer *out) {
    FILE *f = fopen(path, "rb");
    unsigned char block[8192];
    size_t n;
    if (!f) { fprintf(stderr, "%s: %s\n", path, strerror(errno)); return 0; }
    while ((n = fread(block, 1, sizeof(block), f)) != 0) {
        if (dedsec_buffer_append(out, block, n) != DEDSEC_OK) {
            fprintf(stderr, "%s: out of memory\n", path); fclose(f); return 0;
        }
    }
    if (ferror(f)) { fprintf(stderr, "%s: read error\n", path); fclose(f); return 0; }
    fclose(f); return 1;
}

static unsigned bit_at(const dedsec_bitstream *s, size_t bit) {
    return (s->bytes.ptr[bit / 8] >> (7u - (unsigned)(bit % 8))) & 1u;
}

static double entropy_from_counts(const size_t *counts, size_t count, size_t total) {
    double h = 0.0;
    size_t i;
    if (!total) return 0.0;
    for (i = 0; i < count; ++i) if (counts[i]) {
        double p = (double)counts[i] / (double)total;
        h -= p * log2(p);
    }
    return h;
}

static void metrics(const dedsec_bitstream *s, size_t *ones, double *bit_h,
                    double *bit_min_h, double *byte_h, double *serial_h,
                    size_t *fft_bits, double *peak_share, double *flatness,
                    double *dominant_period) {
    size_t bit_counts[2] = {0, 0}, byte_counts[256] = {0}, pairs[2][2] = {{0,0},{0,0}};
    size_t i, bytes = s->bit_length / 8;
    for (i = 0; i < s->bit_length; ++i) ++bit_counts[bit_at(s, i)];
    for (i = 1; i < s->bit_length; ++i)
        ++pairs[bit_at(s, i - 1)][bit_at(s, i)];
    for (i = 0; i < bytes; ++i) ++byte_counts[s->bytes.ptr[i]];
    *ones = bit_counts[1];
    *bit_h = entropy_from_counts(bit_counts, 2, s->bit_length);
    if (s->bit_length) {
        double max_p = (double)(bit_counts[0] > bit_counts[1] ? bit_counts[0] : bit_counts[1]) /
                       (double)s->bit_length;
        *bit_min_h = -log2(max_p);
    } else *bit_min_h = 0.0;
    *byte_h = entropy_from_counts(byte_counts, 256, bytes);
    *serial_h = 0.0;
    if (s->bit_length > 1) {
        size_t total = s->bit_length - 1;
        unsigned prev;
        for (prev = 0; prev < 2; ++prev) {
            size_t n = pairs[prev][0] + pairs[prev][1];
            if (n) *serial_h += ((double)n / (double)total) *
                                 entropy_from_counts(pairs[prev], 2, n);
        }
    }
    *fft_bits = 0; *peak_share = 0.0; *flatness = 0.0; *dominant_period = 0.0;
    if (s->bit_length >= 16) {
        size_t n = 1;
        double complex *a;
        while (n <= s->bit_length / 2 && n < (1u << 20)) n <<= 1;
        a = (double complex *)calloc(n, sizeof(*a));
        if (a) {
            size_t j, length, peak_k = 0;
            double sum_power = 0.0, max_power = 0.0, log_power = 0.0;
            for (j = 0; j < n; ++j) a[j] = bit_at(s, j) ? 1.0 : -1.0;
            {
                size_t reverse = 0;
                for (i = 1; i < n; ++i) {
                size_t bit = n >> 1;
                    for (; reverse & bit; bit >>= 1) reverse ^= bit;
                    reverse ^= bit;
                    if (i < reverse) {
                        double complex t = a[i]; a[i] = a[reverse]; a[reverse] = t;
                    }
                }
            }
            for (length = 2; length <= n; length <<= 1) {
                double complex wlen = cexp(-6.28318530717958647692 * I / (double)length);
                for (i = 0; i < n; i += length) {
                    double complex w = 1.0;
                    for (j = 0; j < length / 2; ++j) {
                        double complex u = a[i + j], v = a[i + j + length / 2] * w;
                        a[i + j] = u + v; a[i + j + length / 2] = u - v; w *= wlen;
                    }
                }
            }
            for (i = 1; i <= n / 2; ++i) {
                double power = creal(a[i]) * creal(a[i]) + cimag(a[i]) * cimag(a[i]);
                sum_power += power;
                if (power > max_power) { max_power = power; peak_k = i; }
                if (power > 0.0) log_power += log(power);
                else { log_power = -INFINITY; }
            }
            if (sum_power > 0.0) {
                *peak_share = max_power / sum_power;
                *flatness = isfinite(log_power) ?
                    exp(log_power / (double)(n / 2)) / (sum_power / (double)(n / 2)) : 0.0;
                *dominant_period = peak_k ? (double)n / (double)peak_k : 0.0;
            }
            *fft_bits = n;
            free(a);
        }
    }
}

static const char *status_name(dedsec_status s) {
    if (s == DEDSEC_ENOTFOUND) return "empty";
    if (s == DEDSEC_OK) return "ok";
    if (s == DEDSEC_EUTF8) return "invalid-utf8";
    return "error";
}

static const char *verdict_name(dedsec_plaintext_verdict verdict) {
    if (verdict == DEDSEC_PLAINTEXT_LIKELY) return "likely";
    if (verdict == DEDSEC_PLAINTEXT_POSSIBLE) return "possible";
    if (verdict == DEDSEC_PLAINTEXT_INSUFFICIENT) return "insufficient";
    return "reject";
}

static uint32_t crc32_ieee(const uint8_t *data, size_t length) {
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int)(crc & 1u));
    }
    return ~crc;
}

/* DSC1: magic (4), payload length (uint16 big-endian), payload, CRC-32.
 * It is a benchmark validation frame, not a cryptographic authentication tag. */
static const char *validate_dsc1(const dedsec_bitstream *stream, size_t *payload_bytes) {
    const uint8_t *p = stream->bytes.ptr;
    size_t bytes = stream->bit_length / 8, length;
    uint32_t expected, actual;
    *payload_bytes = 0;
    if (bytes < 10 || memcmp(p, "DSC1", 4) != 0) return "none";
    length = ((size_t)p[4] << 8) | p[5];
    if (length != bytes - 10) return "bad-frame";
    expected = ((uint32_t)p[bytes - 4] << 24) | ((uint32_t)p[bytes - 3] << 16) |
               ((uint32_t)p[bytes - 2] << 8) | p[bytes - 1];
    actual = crc32_ieee(p, bytes - 4);
    if (actual != expected) return "bad-crc";
    *payload_bytes = length;
    return "valid-dsc1-crc32";
}

static void benchmark_file(const dedsec_registry *registry, const char *path,
                           int detected_only, int valid_frame_only) {
    dedsec_buffer input;
    finding_stats findings = {{0}, {0}};
    size_t i;
    dedsec_buffer_init(&input);
    if (!read_file(path, &input)) { dedsec_buffer_free(&input); return; }
    if (dedsec_detect_all(registry, (dedsec_view){input.ptr, input.len},
                          collect_finding, &findings) != DEDSEC_OK) {
        fprintf(stderr, "%s: detector error\n", path);
        dedsec_buffer_free(&input); return;
    }
    for (i = 0; i < sizeof(lanes) / sizeof(lanes[0]); ++i) {
        dedsec_decode_request request = {lanes[i].variant, 0, NULL, 0};
        dedsec_bitstream stream;
        dedsec_status s;
        size_t ones = 0;
        size_t frame_payload = 0;
        const char *frame_status = "none";
        size_t fft_bits = 0;
        double bit_h = 0.0, bit_min_h = 0.0, byte_h = 0.0, serial_h = 0.0;
        double peak_share = 0.0, flatness = 0.0, dominant_period = 0.0;
        dedsec_bitstream_filter_result filter = {
            .verdict = DEDSEC_PLAINTEXT_INSUFFICIENT
        };
        dedsec_bitstream_init(&stream);
        if (detected_only && findings.count[i] == 0) continue;
        s = dedsec_decode_bits(registry, lanes[i].module,
                               (dedsec_view){input.ptr, input.len}, &request, &stream);
        if (s == DEDSEC_OK) metrics(&stream, &ones, &bit_h, &bit_min_h, &byte_h,
                                    &serial_h, &fft_bits, &peak_share, &flatness,
                                    &dominant_period);
        if (s == DEDSEC_OK) frame_status = validate_dsc1(&stream, &frame_payload);
        if (s == DEDSEC_OK && dedsec_bitstream_filter(&stream, &filter) != DEDSEC_OK) {
            fprintf(stderr, "%s: plaintext filter error\n", path);
            dedsec_bitstream_free(&stream);
            continue;
        }
        if (valid_frame_only && strcmp(frame_status, "valid-dsc1-crc32") != 0) {
            dedsec_bitstream_free(&stream);
            continue;
        }
        printf("%s\t%s\t%s\t%zu\t%u\t%s\t%s\t%zu\t%zu\t%zu\t%.6f\t%.6f\t%.6f\t%.6f\t%zu\t%.6f\t%.6f\t%.3f\t%s\t%u\t%u\t%u\t%u\t%zu\n",
               path, lanes[i].module, lanes[i].variant, findings.count[i],
               findings.max_score[i], status_name(s), frame_status, frame_payload,
               stream.bit_length, ones, bit_h, bit_min_h, byte_h, serial_h,
               fft_bits, peak_share, flatness, dominant_period,
               verdict_name(filter.verdict), filter.score, filter.flags,
               filter.bit_offset, filter.transform_depth, filter.decoded_length);
        dedsec_bitstream_free(&stream);
    }
    dedsec_buffer_free(&input);
}

int main(int argc, char **argv) {
    dedsec_registry registry;
    int i, first_file = 1, detected_only = 0, valid_frame_only = 0;
    while (first_file < argc && argv[first_file][0] == '-') {
        if (strcmp(argv[first_file], "--detected-only") == 0) detected_only = 1;
        else if (strcmp(argv[first_file], "--valid-dsc1-only") == 0) {
            detected_only = 1; valid_frame_only = 1;
        } else break;
        ++first_file;
    }
    if (argc <= first_file) {
        fprintf(stderr, "usage: %s [--detected-only] [--valid-dsc1-only] FILE [FILE ...] > benchmark.tsv\n", argv[0]);
        return 2;
    }
    dedsec_registry_init(&registry);
    if (dedsec_registry_add_builtins(&registry) != DEDSEC_OK) {
        fprintf(stderr, "could not initialize built-in modules\n"); return 1;
    }
    puts("document\tmodule\tvariant\tfinding_count\tmax_score\tstatus\tframe_status\tframe_payload_bytes\tbits\tones\tbit_shannon\tbit_min_entropy\tbyte_shannon\tserial_cond_entropy\tfft_bits\tfft_peak_share\tfft_flatness\tdominant_period_bits\tplaintext_verdict\tplaintext_score\tplaintext_flags\tplaintext_bit_offset\tplaintext_transform_depth\tplaintext_decoded_bytes");
    for (i = first_file; i < argc; ++i)
        benchmark_file(&registry, argv[i], detected_only, valid_frame_only);
    dedsec_registry_free(&registry);
    return 0;
}
