#include "dedsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static int count_finding(void *u, const dedsec_finding *f) {
    size_t *n = (size_t *)u; (void)f; ++*n; return 0;
}
static int count_match(void *u, const dedsec_match *m) {
    size_t *n = (size_t *)u; CHECK(m->source_offset == 0); ++*n; return 0;
}
typedef struct finding_capture { size_t count, offset, length; } finding_capture;
static int capture_base64(void *u, const dedsec_finding *f) {
    finding_capture *capture = (finding_capture *)u;
    if (strcmp(f->rule_id, "base64-rfc4648-token") == 0) {
        ++capture->count; capture->offset = f->byte_offset; capture->length = f->byte_length;
    }
    return 0;
}
static int capture_zwsp_zwnj(void *u, const dedsec_finding *f) {
    size_t *count = (size_t *)u;
    if (f->decoder_hint && strcmp(f->decoder_hint, "zwsp-zwnj-msb") == 0) ++*count;
    return 0;
}
static int capture_bidi_binary(void *u, const dedsec_finding *f) {
    size_t *count = (size_t *)u;
    if (f->decoder_hint && strcmp(f->decoder_hint, "bidi-isolate-bits-msb") == 0)
        ++*count;
    return 0;
}
static dedsec_view view(const void *p, size_t n) {
    dedsec_view v = {(const uint8_t *)p, n}; return v;
}
static void filter_bytes_expect(const uint8_t *p, size_t n,
                                dedsec_plaintext_verdict minimum,
                                uint32_t required_flags) {
    dedsec_bitstream stream;
    dedsec_bitstream_filter_result result;
    size_t i;
    dedsec_bitstream_init(&stream);
    for (i = 0; i < n; ++i)
        CHECK(dedsec_bitstream_append_bits(&stream, p[i], 8, 0) == DEDSEC_OK);
    CHECK(dedsec_bitstream_filter(&stream, &result) == DEDSEC_OK);
    CHECK(result.verdict >= minimum);
    CHECK((result.flags & required_flags) == required_flags);
    dedsec_bitstream_free(&stream);
}
static void decode_expect(dedsec_registry *r, const char *module,
                          const char *variant, const uint8_t *p, size_t n,
                          const char *expected) {
    dedsec_decode_request req = {variant, 0, NULL, 0};
    dedsec_buffer out;
    dedsec_buffer_init(&out);
    CHECK(dedsec_decode(r, module, view(p, n), &req, &out) == DEDSEC_OK);
    CHECK(out.len == strlen(expected));
    CHECK(memcmp(out.ptr, expected, out.len) == 0);
    dedsec_buffer_free(&out);
}
static void decode_params_expect(dedsec_registry *r, const char *module,
                                 const char *variant, const uint8_t *p, size_t n,
                                 const void *params, size_t params_size,
                                 const char *expected) {
    dedsec_decode_request req = {variant, 0, params, params_size};
    dedsec_buffer out;
    dedsec_buffer_init(&out);
    CHECK(dedsec_decode(r, module, view(p, n), &req, &out) == DEDSEC_OK);
    CHECK(out.len == strlen(expected));
    CHECK(memcmp(out.ptr, expected, out.len) == 0);
    dedsec_buffer_free(&out);
}
static void decode_bits_expect(dedsec_registry *r, const char *module,
                               const char *variant, const uint8_t *p, size_t n,
                               const void *params, size_t params_size,
                               size_t expected_bits, const uint8_t *expected,
                               size_t expected_bytes) {
    dedsec_decode_request req = {variant, 0, params, params_size};
    dedsec_bitstream out;
    dedsec_bitstream_init(&out);
    CHECK(dedsec_decode_bits(r, module, view(p, n), &req, &out) == DEDSEC_OK);
    CHECK(out.bit_length == expected_bits);
    CHECK(out.bytes.len == expected_bytes);
    CHECK(memcmp(out.bytes.ptr, expected, expected_bytes) == 0);
    dedsec_bitstream_free(&out);
}

int main(void) {
    dedsec_registry registry;
    size_t findings = 0, matches = 0;
    static const uint8_t zw[] = {
        0xe2,0x80,0x8b, 0xe2,0x80,0x8c, 0xe2,0x80,0x8b, 0xe2,0x80,0x8b,
        0xe2,0x80,0x8c, 0xe2,0x80,0x8c, 0xe2,0x80,0x8c, 0xe2,0x80,0x8c,
        0xe2,0x80,0x8b, 0xe2,0x80,0x8c, 0xe2,0x80,0x8b, 0xe2,0x80,0x8b,
        0xe2,0x80,0x8c, 0xe2,0x80,0x8b, 0xe2,0x80,0x8c, 0xe2,0x80,0x8c
    };
    uint8_t zw_with_tail[sizeof(zw) + 3];
    static const uint8_t tags[] = {
        'S', 0xf3,0xa0,0x80,0x81, 0xf3,0xa0,0x81,0x8f,
        0xf3,0xa0,0x81,0x8b, 0xf3,0xa0,0x81,0xbf, 'Z'
    };
    static const uint8_t vs[] = {
        'a',0xef,0xb8,0x84,'b',0xef,0xb8,0x8f,
        'c',0xef,0xb8,0x84,'d',0xef,0xb8,0x8b
    };
    static const uint8_t iso[] = {
        0x1b,'(','B','A','|', 0x1b,'(','J','A','|',
        0x1b,'(','B','A','|', 0x1b,'(','B','A','|',
        0x1b,'(','J','A','|', 0x1b,'(','J','A','|',
        0x1b,'(','J','A','|', 0x1b,'(','J','A','|',
        0x1b,'(','B','A','|', 0x1b,'(','J','A','|',
        0x1b,'(','B','A','|', 0x1b,'(','B','A','|',
        0x1b,'(','J','A','|', 0x1b,'(','B','A','|',
        0x1b,'(','J','A','|', 0x1b,'(','J','A'
    };
    static const char trailing[] =
        "1 \n2  \n3 \n4 \n5  \n6  \n7  \n8  \n"
        "9 \n10  \n11 \n12 \n13  \n14 \n15  \n16  \n";
    static const uint8_t bad[] = {0xc0,0xaf};
    static const uint8_t nonchars[] = {
        'A', 0xef,0xb7,0x99, 0xef,0xb7,0xad, 0xef,0xb7,0x95,
        0xef,0xb7,0xa0, 'B'
    };
    static const dedsec_codepoint_symbol nonchar_symbols[] = {
        {0xfdd9,9}, {0xfded,29}, {0xfdd5,5}, {0xfde0,16}
    };
    static const dedsec_codepoint_alphabet nonchar_alpha = {
        nonchar_symbols, 4, 5, 0
    };
    static const uint8_t homoglyphs[] = {
        0xd0,0xb0,'a',0xd0,0xb0,0xd0,0xb0,'a','a','a','a',
        0xd0,0xb0,'a',0xd0,0xb0,0xd0,0xb0,'a',0xd0,0xb0,'a','a'
    };
    static const dedsec_codepoint_symbol homoglyph_symbols[] = {
        {0x0430,0}, {0x0061,1}
    };
    static const dedsec_codepoint_alphabet homoglyph_alpha = {
        homoglyph_symbols, 2, 1, 0
    };
    static const uint8_t cesu[] = {
        0xf0,0x9f,0x98,0x80, 0xed,0xa0,0xbd,0xed,0xb8,0x80,
        0xf0,0x9f,0x98,0x80, 0xf0,0x9f,0x98,0x80,
        0xed,0xa0,0xbd,0xed,0xb8,0x80, 0xed,0xa0,0xbd,0xed,0xb8,0x80,
        0xed,0xa0,0xbd,0xed,0xb8,0x80, 0xed,0xa0,0xbd,0xed,0xb8,0x80,
        0xf0,0x9f,0x98,0x80, 0xed,0xa0,0xbd,0xed,0xb8,0x80,
        0xf0,0x9f,0x98,0x80, 0xf0,0x9f,0x98,0x80,
        0xed,0xa0,0xbd,0xed,0xb8,0x80, 0xf0,0x9f,0x98,0x80,
        0xed,0xa0,0xbd,0xed,0xb8,0x80, 0xed,0xa0,0xbd,0xed,0xb8,0x80
    };
    static const uint8_t water[] = {0xe6,0xb0,0xb4};
    static const uint8_t json_escape[] = {'\\','u','6','C','3','4'};
    static const uint8_t json_carrier[] = {
        0xe6,0xb0,0xb4,'\\','u','6','C','3','4',0xe6,0xb0,0xb4,0xe6,0xb0,0xb4,
        '\\','u','6','C','3','4','\\','u','6','C','3','4','\\','u','6','C','3','4',
        '\\','u','6','C','3','4',0xe6,0xb0,0xb4,'\\','u','6','C','3','4',
        0xe6,0xb0,0xb4,0xe6,0xb0,0xb4,'\\','u','6','C','3','4',0xe6,0xb0,0xb4,
        '\\','u','6','C','3','4','\\','u','6','C','3','4'
    };
    static const dedsec_token_symbol json_symbols[] = {
        {{json_escape, sizeof(json_escape)},1}, {{water, sizeof(water)},0}
    };
    static const dedsec_token_alphabet json_alpha = {json_symbols, 2, 1, 0};
    static const char json_numbers[] = "1.0,1,1.00,1.00,1.0,1,1e0,1.00";
    static const char iteration[] = u8"\u4eba\u4eba\u3001\u65e5\u3005\u3001"
        u8"\u6642\u6642\u3001\u56fd\u56fd\u3001\u6240\u3005\u3001"
        u8"\u69d8\u3005\u3001\u8272\u3005\u3001\u5404\u3005\u3001"
        u8"\u591a\u591a\u3001\u5ea6\u3005\u3001\u5e74\u5e74\u3001"
        u8"\u6708\u6708\u3001\u65b9\u3005\u3001\u4ee3\u4ee3\u3001"
        u8"\u5bb6\u3005\u3001\u591c\u3005";
    static const uint8_t nt0[] = "1", nt1[] = "1.0", nt2[] = "1e0", nt3[] = "1.00";
    static const dedsec_token_symbol number_symbols[] = {
        {{nt0,1},0}, {{nt1,3},1}, {{nt2,3},2}, {{nt3,4},3}
    };
    static const dedsec_token_alphabet number_alpha = {number_symbols, 4, 2, 0};
    static const char hay[] = "Se cret";
    static const char needle[] = "secret";
    static const char normal[] = "ordinary prose has one question? nothing unusual follows.\n";
    static const char hidden[] = "Meet at the loading dock at midnight.";
    static const char hidden_hex[] =
        "4d65657420617420746865206c6f6164696e6720646f636b206174206d69646e696768742e";
    static const char hidden_b32[] =
        "JVSWK5BAMF2CA5DIMUQGY33BMRUW4ZZAMRXWG2ZAMF2CA3LJMRXGSZ3IOQXA====";
    static const char hidden_b32hex[] =
        "9LIMAT10C5Q20T38CKG6ORR1CHKMSPP0CHNM6QP0C5Q20RB9CHN6IPR8EGN0====";
    static const char hidden_b64[] =
        "TWVldCBhdCB0aGUgbG9hZGluZyBkb2NrIGF0IG1pZG5pZ2h0Lg==";
    static const char hidden_nested[] =
        "SlZTV0s1QkFNRjJDQTVESU1VUUdZMzNCTVJVVzRaWkFNUlhXRzJaQU1GMkNBM0xKTVJYR1NaM0lPUVhBPT09PQ==";
    static const uint8_t ciphertext_like[] = {
        0xa4,0x72,0x19,0xef,0x03,0x88,0xd1,0x5c,0xb7,0x26,0x90,0x4a,0xfd,0x61,0x0e,0xc3,
        0x58,0x9b,0x2d,0xe0,0x74,0x11,0xca,0x3f,0x86,0xd5,0x49,0xb2,0x07,0xec,0x68,0x95
    };
    static const char ciphertext_b32[] =
        "URZBT3YDRDIVZNZGSBFP2YIOYNMJWLPAOQI4UP4G2VE3EB7MNCKQ====";
    static const char line_forms[] = "\n\r\n\n\r\n\n\r\n\n\r\n";
    static const char b64[] = "T0s=";
    static const char b32[] = "J5FQ====";
    static const char crockford[] = "9X5G";
    static const char b64_long[] = "T0tPS09LT0tPS09L";
    static const char markdown_b64[] = "## Note\n\n`T0tPS09LT0tPS09L`\n";
    static const char html_b64[] = "<code>T0tPS09LT0tPS09L</code>";
    static const char markdown_list[] =
        "- a\n* b\n- c\n- d\n* e\n* f\n* g\n* h\n```\n* ignored\n- ignored\n```\n";
    static const char markdown_levels[] = "- a\n  - b\n- c\n  - d\n";
    static const char sentences[] = "Alpha. Beta?";
    static const char paragraphs[] = "Alpha\n\nBeta";
    static const dedsec_codepoint_symbol initials[] = {{'A', 0}, {'B', 1}};
    static const dedsec_codepoint_alphabet initial_alpha = {initials, 2, 1, 0};
    static const dedsec_binary_rule parity_rule = {DEDSEC_BINARY_PARITY, 0, 0, 1, 0, 0};
    dedsec_transform ops[] = {
        {"casefold", dedsec_transform_ascii_casefold, NULL},
        {"delete-hspace", dedsec_transform_delete_hspace, NULL}
    };
    dedsec_chain chain = {ops, 2};
    dedsec_view nv = view(needle, sizeof(needle)-1);

    dedsec_registry_init(&registry);
    CHECK(dedsec_registry_add_builtins(&registry) == DEDSEC_OK);
    CHECK(registry.count == 6);
    memcpy(zw_with_tail, zw, sizeof(zw));
    zw_with_tail[sizeof(zw)] = 0xe2;
    zw_with_tail[sizeof(zw) + 1] = 0x80;
    zw_with_tail[sizeof(zw) + 2] = 0x8c; /* one appended 1 bit */
    decode_expect(&registry, "unicode", "zwsp-zwnj-msb", zw, sizeof(zw), "OK");
    {
        static const uint8_t expected[] = {'O', 'K', 0x80};
        decode_bits_expect(&registry, "unicode", "zwsp-zwnj-msb",
                           zw_with_tail, sizeof(zw_with_tail), NULL, 0,
                           17, expected, sizeof(expected));
    }
    decode_expect(&registry, "unicode", "tags-ascii", tags, sizeof(tags), "OK");
    decode_expect(&registry, "unicode", "variation-nibbles", vs, sizeof(vs), "OK");
    decode_expect(&registry, "encoding", "iso2022-designation-bits-msb", iso, sizeof(iso), "OK");
    decode_expect(&registry, "layout", "trailing-space-bits",
                  (const uint8_t *)trailing, sizeof(trailing)-1, "OK");
    decode_params_expect(&registry, "unicode", "codepoint-map-msb",
                         nonchars, sizeof(nonchars), &nonchar_alpha,
                         sizeof(nonchar_alpha), "OK");
    {
        static const uint8_t expected[] = {'O', 'K', 0x00};
        decode_bits_expect(&registry, "unicode", "codepoint-map-msb",
                           nonchars, sizeof(nonchars), &nonchar_alpha,
                           sizeof(nonchar_alpha), 20, expected, sizeof(expected));
    }
    decode_params_expect(&registry, "unicode", "codepoint-map-msb",
                         homoglyphs, sizeof(homoglyphs), &homoglyph_alpha,
                         sizeof(homoglyph_alpha), "OK");
    decode_expect(&registry, "encoding", "utf8-cesu8-form-bits-msb",
                  cesu, sizeof(cesu), "OK");
    decode_params_expect(&registry, "surface", "token-map-msb",
                         json_carrier, sizeof(json_carrier), &json_alpha,
                         sizeof(json_alpha), "OK");
    decode_params_expect(&registry, "surface", "token-map-msb",
                         (const uint8_t *)json_numbers, sizeof(json_numbers)-1,
                         &number_alpha, sizeof(number_alpha), "OK");
    decode_expect(&registry, "unicode", "iteration-mark-bits",
                  (const uint8_t *)iteration, sizeof(iteration)-1, "OK");
    decode_expect(&registry, "surface", "base64-rfc4648",
                  (const uint8_t *)b64, sizeof(b64)-1, "OK");
    decode_expect(&registry, "surface", "base32-rfc4648",
                  (const uint8_t *)b32, sizeof(b32)-1, "OK");
    decode_expect(&registry, "structure", "line-ending-bits-lf-zero",
                  (const uint8_t *)line_forms, sizeof(line_forms)-1, "U");
    decode_expect(&registry, "markdown", "markdown-ul-marker-bits",
                  (const uint8_t *)markdown_list, sizeof(markdown_list)-1, "O");
    {
        static const uint8_t expected[] = {0x22};
        static const dedsec_binary_rule lane_rule = {DEDSEC_BINARY_LOW_BIT, 0, 0, 2, 0, 0};
        decode_bits_expect(&registry, "markdown", "markdown-ul-level-rule",
                           (const uint8_t *)markdown_levels, sizeof(markdown_levels)-1,
                           &lane_rule, sizeof(lane_rule), 8, expected, sizeof(expected));
    }
    {
        dedsec_decode_request req = {"markdown-ul-marker-bits",
                                     DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY, NULL, 0};
        dedsec_bitstream out;
        dedsec_bitstream_init(&out);
        CHECK(dedsec_decode_bits(&registry, "markdown",
                                 view(markdown_levels, sizeof(markdown_levels)-1),
                                 &req, &out) == DEDSEC_OK);
        CHECK(out.bit_length == 2 && out.bytes.len == 1 && out.bytes.ptr[0] == 0);
        dedsec_bitstream_free(&out);
    }
    {
        static const uint8_t expected[] = {'O', 'K', 0x00};
        decode_bits_expect(&registry, "surface", "base32-crockford",
                           (const uint8_t *)crockford, sizeof(crockford)-1,
                           NULL, 0, 20, expected, sizeof(expected));
    }
    {
        static const uint8_t expected[] = {0x40};
        decode_bits_expect(&registry, "structure", "sentence-initial-map-msb",
                           (const uint8_t *)sentences, sizeof(sentences)-1,
                           &initial_alpha, sizeof(initial_alpha), 2, expected, sizeof(expected));
        decode_bits_expect(&registry, "structure", "paragraph-initial-map-msb",
                           (const uint8_t *)paragraphs, sizeof(paragraphs)-1,
                           &initial_alpha, sizeof(initial_alpha), 2, expected, sizeof(expected));
        decode_bits_expect(&registry, "structure", "sentence-byte-rule",
                           (const uint8_t *)sentences, sizeof(sentences)-1,
                           &parity_rule, sizeof(parity_rule), 2, expected, sizeof(expected));
    }
    CHECK(dedsec_detect_all(&registry, view(tags, sizeof(tags)), count_finding, &findings) == DEDSEC_OK);
    CHECK(findings >= 2);
    findings = 0;
    CHECK(dedsec_detect_all(&registry, view(zw, sizeof(zw)), capture_zwsp_zwnj, &findings) == DEDSEC_OK);
    CHECK(findings == 1);
    findings = 0;
    CHECK(dedsec_detect_all(&registry, view(bad, sizeof(bad)), count_finding, &findings) == DEDSEC_OK);
    CHECK(findings == 1);
    findings = 0;
    CHECK(dedsec_detect_all(&registry, view(json_carrier, sizeof(json_carrier)),
                            count_finding, &findings) == DEDSEC_OK);
    CHECK(findings >= 1);
    findings = 0;
    CHECK(dedsec_detect_all(&registry, view(line_forms, sizeof(line_forms)-1),
                            count_finding, &findings) == DEDSEC_OK);
    CHECK(findings >= 1);
    {
        finding_capture capture = {0};
        dedsec_view token;
        CHECK(dedsec_detect_all(&registry, view(markdown_b64, sizeof(markdown_b64)-1),
                                capture_base64, &capture) == DEDSEC_OK);
        CHECK(capture.count == 1);
        CHECK(capture.length == sizeof(b64_long)-1);
        CHECK(capture.offset == (size_t)(strstr(markdown_b64, b64_long) - markdown_b64));
        token.ptr = (const uint8_t *)markdown_b64 + capture.offset;
        token.len = capture.length;
        decode_expect(&registry, "surface", "base64-rfc4648", token.ptr, token.len,
                      "OKOKOKOKOKOK");
        capture.count = 0;
        CHECK(dedsec_detect_all(&registry, view(html_b64, sizeof(html_b64)-1),
                                capture_base64, &capture) == DEDSEC_OK);
        CHECK(capture.count == 1);
    }
    CHECK(dedsec_search(view(hay, sizeof(hay)-1), &nv, 1, &chain, 1,
                        count_match, &matches) == DEDSEC_OK);
    CHECK(matches == 1);
    findings = 0;
    CHECK(dedsec_detect_all(&registry, view(normal, sizeof(normal)-1),
                            count_finding, &findings) == DEDSEC_OK);
    CHECK(findings == 0);
    filter_bytes_expect((const uint8_t *)hidden, sizeof(hidden)-1,
                        DEDSEC_PLAINTEXT_LIKELY,
                        DEDSEC_PLAINTEXT_ASCII | DEDSEC_PLAINTEXT_UTF8);
    filter_bytes_expect((const uint8_t *)hidden_hex, sizeof(hidden_hex)-1,
                        DEDSEC_PLAINTEXT_LIKELY, DEDSEC_PLAINTEXT_BASE16);
    filter_bytes_expect((const uint8_t *)hidden_b32, sizeof(hidden_b32)-1,
                        DEDSEC_PLAINTEXT_LIKELY, DEDSEC_PLAINTEXT_BASE32);
    filter_bytes_expect((const uint8_t *)hidden_b32hex, sizeof(hidden_b32hex)-1,
                        DEDSEC_PLAINTEXT_LIKELY, DEDSEC_PLAINTEXT_BASE32HEX);
    filter_bytes_expect((const uint8_t *)hidden_b64, sizeof(hidden_b64)-1,
                        DEDSEC_PLAINTEXT_LIKELY, DEDSEC_PLAINTEXT_BASE64);
    filter_bytes_expect((const uint8_t *)hidden_nested, sizeof(hidden_nested)-1,
                        DEDSEC_PLAINTEXT_LIKELY,
                        DEDSEC_PLAINTEXT_BASE64 | DEDSEC_PLAINTEXT_BASE32);
    {
        dedsec_bitstream stream;
        dedsec_bitstream_filter_result result;
        size_t i;
        dedsec_bitstream_init(&stream);
        CHECK(dedsec_bitstream_append_bits(&stream, 5, 3, 0) == DEDSEC_OK);
        for (i = 0; i < sizeof(hidden)-1; ++i)
            CHECK(dedsec_bitstream_append_bits(&stream, (uint8_t)hidden[i], 8, 0) == DEDSEC_OK);
        CHECK(dedsec_bitstream_filter(&stream, &result) == DEDSEC_OK);
        CHECK(result.verdict == DEDSEC_PLAINTEXT_LIKELY);
        CHECK(result.bit_offset == 3);
        dedsec_bitstream_free(&stream);
    }
    {
        dedsec_bitstream stream;
        dedsec_bitstream_filter_result result;
        size_t i;
        dedsec_bitstream_init(&stream);
        for (i = 0; i < sizeof(ciphertext_like); ++i)
            CHECK(dedsec_bitstream_append_bits(&stream, ciphertext_like[i], 8, 0) == DEDSEC_OK);
        CHECK(dedsec_bitstream_filter(&stream, &result) == DEDSEC_OK);
        CHECK(result.verdict == DEDSEC_PLAINTEXT_REJECT);
        dedsec_bitstream_free(&stream);
    }
    {
        dedsec_bitstream stream;
        dedsec_bitstream_filter_result result;
        size_t i;
        dedsec_bitstream_init(&stream);
        for (i = 0; i < sizeof(ciphertext_b32)-1; ++i)
            CHECK(dedsec_bitstream_append_bits(&stream, (uint8_t)ciphertext_b32[i], 8, 0) == DEDSEC_OK);
        CHECK(dedsec_bitstream_filter(&stream, &result) == DEDSEC_OK);
        CHECK(result.verdict == DEDSEC_PLAINTEXT_REJECT);
        dedsec_bitstream_free(&stream);
    }
    {
        dedsec_bitstream empty, malformed;
        dedsec_bitstream_filter_result result;
        dedsec_bitstream_init(&empty);
        CHECK(dedsec_bitstream_filter(&empty, &result) == DEDSEC_OK);
        CHECK(result.verdict == DEDSEC_PLAINTEXT_INSUFFICIENT);
        dedsec_bitstream_init(&malformed);
        malformed.bit_length = 8;
        CHECK(dedsec_bitstream_filter(&malformed, &result) == DEDSEC_EINVAL);
        dedsec_bitstream_free(&empty);
        dedsec_bitstream_free(&malformed);
    }
    {
        static const uint8_t arabic_alef[] = {0xd8, 0xa7};
        static const uint8_t lri[] = {0xe2, 0x81, 0xa6};
        static const uint8_t rli[] = {0xe2, 0x81, 0xa7};
        static const uint8_t pdi[] = {0xe2, 0x81, 0xa9};
        dedsec_buffer carrier;
        dedsec_decode_request request = {"bidi-isolate-bits-msb", 0, NULL, 0};
        dedsec_bitstream extracted;
        dedsec_bitstream_filter_result result;
        size_t i, bit, bidi_findings = 0;
        dedsec_buffer_init(&carrier);
        for (i = 0; i < sizeof(hidden)-1; ++i) {
            for (bit = 0; bit < 8; ++bit) {
                const uint8_t *opener = ((uint8_t)hidden[i] >> (7u - bit)) & 1u ? rli : lri;
                CHECK(dedsec_buffer_append(&carrier, arabic_alef, sizeof(arabic_alef)) == DEDSEC_OK);
                CHECK(dedsec_buffer_append(&carrier, opener, sizeof(lri)) == DEDSEC_OK);
                CHECK(dedsec_buffer_append(&carrier, pdi, sizeof(pdi)) == DEDSEC_OK);
            }
        }
        CHECK(dedsec_detect_all(&registry, view(carrier.ptr, carrier.len),
                                capture_bidi_binary, &bidi_findings) == DEDSEC_OK);
        CHECK(bidi_findings == 1);
        dedsec_bitstream_init(&extracted);
        CHECK(dedsec_decode_bits(&registry, "unicode", view(carrier.ptr, carrier.len),
                                 &request, &extracted) == DEDSEC_OK);
        CHECK(extracted.bit_length == (sizeof(hidden)-1) * 8);
        CHECK(memcmp(extracted.bytes.ptr, hidden, sizeof(hidden)-1) == 0);
        CHECK(dedsec_bitstream_filter(&extracted, &result) == DEDSEC_OK);
        CHECK(result.verdict == DEDSEC_PLAINTEXT_LIKELY);
        dedsec_bitstream_free(&extracted);
        dedsec_buffer_free(&carrier);
    }
    {
        static const uint8_t lri[] = {0xe2, 0x81, 0xa6};
        static const uint8_t rli[] = {0xe2, 0x81, 0xa7};
        static const uint8_t pdi[] = {0xe2, 0x81, 0xa9};
        dedsec_buffer legitimate;
        size_t i, bidi_findings = 0;
        dedsec_buffer_init(&legitimate);
        for (i = 0; i < 80; ++i) {
            const uint8_t *opener = i & 1u ? rli : lri;
            CHECK(dedsec_buffer_append(&legitimate, opener, sizeof(lri)) == DEDSEC_OK);
            CHECK(dedsec_buffer_append(&legitimate, "W3C", 3) == DEDSEC_OK);
            CHECK(dedsec_buffer_append(&legitimate, pdi, sizeof(pdi)) == DEDSEC_OK);
        }
        CHECK(dedsec_detect_all(&registry, view(legitimate.ptr, legitimate.len),
                                capture_bidi_binary, &bidi_findings) == DEDSEC_OK);
        CHECK(bidi_findings == 0);
        dedsec_buffer_free(&legitimate);
    }
    dedsec_registry_free(&registry);
    puts("ok");
    return 0;
}
