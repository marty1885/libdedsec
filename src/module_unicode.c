#include "internal.h"

#include <string.h>

typedef struct bidi_frame {
    int visible;
    int after_arabic_letter;
    int binary;
} bidi_frame;

typedef struct unicode_scan {
    dedsec_finding_fn emit;
    void *user;
    dedsec_status status;
    uint64_t ignorables, selectors, tags, bidi, interior_bom, zwsp, zwnj;
    uint64_t mongolian_fvs1, mongolian_fvs2;
    uint64_t noncharacters, shorthand, iteration;
    uint64_t scalars, lri, rli, fsi, pdi, matched_binary_isolates;
    uint64_t empty_binary_isolates, empty_after_arabic, unmatched_pdi, stack_overflow;
    size_t first_ignorable, first_selector, first_tag, first_bidi, first_bom;
    size_t first_mongolian_fvs;
    size_t first_noncharacter, first_shorthand, first_iteration;
    uint32_t previous_cp;
    size_t previous_offset, previous_length;
    int have_previous;
    int in_tag_payload;
    bidi_frame bidi_stack[128];
    size_t bidi_depth;
} unicode_scan;

static int in_range(uint32_t v, uint32_t lo, uint32_t hi) {
    return v >= lo && v <= hi;
}
static int validate_only(void *opaque, const dedsec_scalar *s) {
    (void)opaque; (void)s; return 0;
}
static int arabic_letter(uint32_t cp) {
    return in_range(cp, 0x0620, 0x063f) || in_range(cp, 0x0641, 0x064a) ||
           in_range(cp, 0x066e, 0x066f) || in_range(cp, 0x0671, 0x06d3) ||
           in_range(cp, 0x06e5, 0x06e6) || in_range(cp, 0x06ee, 0x06ef) ||
           in_range(cp, 0x06fa, 0x06fc) || cp == 0x06ff;
}
static int specialized_ignorable_slot(const unicode_scan *x, uint32_t cp) {
    /* The reviewed U+1820 + FVS1/FVS2 lane already has raw symbol ownership.
     * Do not add that same selector to the generic aggregate observation. */
    return x->have_previous && x->previous_cp == 0x1820 &&
           (cp == 0x180b || cp == 0x180c);
}
static int scan_scalar(void *opaque, const dedsec_scalar *s) {
    unicode_scan *x = (unicode_scan *)opaque;
    uint32_t cp = s->value;
    dedsec_status emitted = DEDSEC_OK;
    ++x->scalars;
    if (cp == 0x2066 || cp == 0x2067 || cp == 0x2068) {
        if (cp == 0x2066) ++x->lri;
        else if (cp == 0x2067) ++x->rli;
        else ++x->fsi;
        if (x->bidi_depth < sizeof(x->bidi_stack) / sizeof(x->bidi_stack[0])) {
            bidi_frame *frame = &x->bidi_stack[x->bidi_depth++];
            frame->visible = 0;
            frame->after_arabic_letter = x->have_previous && arabic_letter(x->previous_cp);
            frame->binary = cp == 0x2066 || cp == 0x2067;
        } else ++x->stack_overflow;
    } else if (cp == 0x2069) {
        ++x->pdi;
        if (x->bidi_depth) {
            bidi_frame frame = x->bidi_stack[--x->bidi_depth];
            if (frame.binary) {
                ++x->matched_binary_isolates;
                if (!frame.visible) {
                    ++x->empty_binary_isolates;
                    if (frame.after_arabic_letter) ++x->empty_after_arabic;
                }
            }
            if (frame.visible && x->bidi_depth) {
                x->bidi_stack[x->bidi_depth - 1].visible = 1;
            }
        } else ++x->unmatched_pdi;
    } else if (x->bidi_depth && !dedsec_unicode_is_default_ignorable(cp)) {
        x->bidi_stack[x->bidi_depth - 1].visible = 1;
    }
    if (dedsec_unicode_is_default_ignorable(cp) &&
        !specialized_ignorable_slot(x, cp)) {
        if (!x->ignorables) x->first_ignorable = s->byte_offset;
        ++x->ignorables;
    }
    if (dedsec_unicode_is_default_ignorable(cp)) {
        emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                          "default-ignorable-scalar",
                                          s->byte_offset, s->byte_length, cp);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
        if (x->have_previous) {
            emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                              "default-ignorable-adjacent-context",
                                              x->previous_offset,
                                              x->previous_length + s->byte_length,
                                              cp);
            if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
        }
    }
    /* Non-ASCII White_Space is a raw property observation, not an ASCII
     * layout feature, identity assertion, or bit symbol. */
    if (cp > 0x7fu && dedsec_unicode_is_white_space(cp)) {
        emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                          "unicode-white-space-scalar",
                                          s->byte_offset, s->byte_length, cp);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    /* C1 controls are retained as zero-score forensic observations. C0 and
     * DEL remain byte-oriented/input-specific concerns and are not streamed
     * here to avoid changing existing ASCII layout semantics. */
    if (cp >= 0x0080u && dedsec_unicode_is_control(cp)) {
        emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                          "unicode-c1-control-scalar",
                                          s->byte_offset, s->byte_length, cp);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    /* Cf does not imply invisibility. The residual after Default_Ignorable
     * includes prepended concatenation marks, interlinear annotation controls,
     * and Egyptian shaping controls. Preserve each raw value and conservative
     * preceding-scalar dependency context for forensic review; never assign a
     * bit or decoder without a caller-supplied grammar/rendering contract. */
    if (dedsec_unicode_is_format_control(cp) &&
        !dedsec_unicode_is_default_ignorable(cp)) {
        emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                          "unicode-non-ignorable-format-control-scalar",
                                          s->byte_offset, s->byte_length, cp);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
        if (x->have_previous) {
            emitted = dedsec_emit_observation(x->emit, x->user, "unicode",
                                              "unicode-non-ignorable-format-control-adjacent-context",
                                              x->previous_offset,
                                              x->previous_length + s->byte_length,
                                              cp);
            if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
        }
    }
    if (cp == 0x200b) ++x->zwsp;
    if (cp == 0x200c) ++x->zwnj;
    if (cp == 0x200b || cp == 0x200c) {
        emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                     "zero-width-binary-symbols",
                                     "zwsp-zwnj-msb", s->byte_offset,
                                     s->byte_length, cp == 0x200c, 1);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    if (in_range(cp, 0xfe00, 0xfe0f) || in_range(cp, 0xe0100, 0xe01ef)) {
        if (!x->selectors) x->first_selector = s->byte_offset;
        ++x->selectors;
    }
    if (in_range(cp, 0xfe00, 0xfe0f)) {
        emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                     "variation-selectors", "variation-nibbles",
                                     s->byte_offset, s->byte_length,
                                     (uint8_t)(cp - 0xfe00), 4);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    /* U+180B..U+180D are Mongolian Free Variation Selectors, not the
     * standardized variation-selector ranges used by variation-nibbles.
     * Keep their binary observation narrowly bound to the reviewed U+1820
     * base and FVS1/FVS2 pair; FVS3 remains outside this binary lane. */
    if (x->have_previous && x->previous_cp == 0x1820) {
        if (cp == 0x180b) {
            if (!x->mongolian_fvs1 && !x->mongolian_fvs2)
                x->first_mongolian_fvs = s->byte_offset;
            ++x->mongolian_fvs1;
            emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                         "mongolian-fvs-binary-symbols",
                                         "mongolian-fvs1-fvs2-bits-msb",
                                         s->byte_offset, s->byte_length, 0, 1);
        } else if (cp == 0x180c) {
            if (!x->mongolian_fvs1 && !x->mongolian_fvs2)
                x->first_mongolian_fvs = s->byte_offset;
            ++x->mongolian_fvs2;
            emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                         "mongolian-fvs-binary-symbols",
                                         "mongolian-fvs1-fvs2-bits-msb",
                                         s->byte_offset, s->byte_length, 1, 1);
        }
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    if (in_range(cp, 0xe0001, 0xe007f)) {
        if (!x->tags) x->first_tag = s->byte_offset;
        ++x->tags;
    }
    if (cp == 0xe0001) {
        x->in_tag_payload = 1;
    } else if (cp == 0xe007f) {
        x->in_tag_payload = 0;
    } else if (x->in_tag_payload && in_range(cp, 0xe0020, 0xe007e)) {
        emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                     "unicode-tags", "tags-ascii",
                                     s->byte_offset, s->byte_length,
                                     (uint8_t)(cp - 0xe0000), 8);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    if (in_range(cp, 0x202a, 0x202e) || in_range(cp, 0x2066, 0x2069) ||
        cp == 0x061c || cp == 0x200e || cp == 0x200f) {
        if (!x->bidi) x->first_bidi = s->byte_offset;
        ++x->bidi;
    }
    if (cp == 0xfeff && s->byte_offset != 0) {
        if (!x->interior_bom) x->first_bom = s->byte_offset;
        ++x->interior_bom;
    }
    if (in_range(cp, 0xfdd0, 0xfdef) ||
        (cp <= 0x10ffff && (cp & 0xffffu) >= 0xfffeu)) {
        if (!x->noncharacters) x->first_noncharacter = s->byte_offset;
        ++x->noncharacters;
    }
    if (in_range(cp, 0x1bca0, 0x1bca3)) {
        if (!x->shorthand) x->first_shorthand = s->byte_offset;
        ++x->shorthand;
    }
    if (cp == 0x3005) {
        if (!x->iteration) x->first_iteration = s->byte_offset;
        ++x->iteration;
    }
    if (cp == 0x2066 || cp == 0x2067) {
        emitted = dedsec_emit_symbol(x->emit, x->user, "unicode",
                                     "binary-bidi-isolates",
                                     "bidi-isolate-bits-msb", s->byte_offset,
                                     s->byte_length, cp == 0x2067, 1);
        if (emitted != DEDSEC_OK) { x->status = emitted; return 1; }
    }
    x->previous_cp = cp;
    x->previous_offset = s->byte_offset;
    x->previous_length = s->byte_length;
    x->have_previous = 1;
    return 0;
}

static dedsec_status emit_count(unicode_scan *x, uint64_t count, size_t offset,
                                const char *rule, const char *decoder,
                                uint32_t base_score) {
    uint32_t score;
    if (!count) return DEDSEC_OK;
    score = base_score + (count > 10 ? 15u : (uint32_t)count);
    if (score > 100) score = 100;
    return dedsec_emit_finding(x->emit, x->user, "unicode", rule, decoder,
                               offset, 0, score, count);
}

/* This is deliberately a source-order observation, not a general UAX #9
 * implementation.  Under the reviewed contract each complete LF-terminated
 * five-byte record starts with ASCII 'a' and is exactly one of these two
 * spellings.  The leading L scalar establishes the standalone LTR paragraph
 * context used by the independent validation; no inferred context is used. */
static int implicit_bidi_record(dedsec_view input, size_t start, size_t end,
                                uint8_t *value) {
    static const uint8_t zero[] = {0x61, 0xd7, 0x90, 0x31, 0x0a};
    static const uint8_t one[] = {0x61, 0x31, 0xd7, 0x90, 0x0a};
    if (end < start || end - start != sizeof(zero)) return 0;
    if (memcmp(input.ptr + start, zero, sizeof(zero)) == 0) {
        *value = 0;
        return 1;
    }
    if (memcmp(input.ptr + start, one, sizeof(one)) == 0) {
        *value = 1;
        return 1;
    }
    return 0;
}

static dedsec_status scan_implicit_bidi(dedsec_view input,
                                        dedsec_finding_fn emit, void *user,
                                        uint64_t *zero, uint64_t *one,
                                        size_t *first, size_t *last) {
    size_t start = 0;
    int have_record = 0;
    while (start < input.len) {
        size_t end = start;
        uint8_t value;
        while (end < input.len && input.ptr[end] != 0x0a) ++end;
        if (end < input.len) {
            size_t record_end = end + 1;
            if (implicit_bidi_record(input, start, record_end, &value)) {
                dedsec_status s;
                if (value) {
                    if (*one == UINT64_MAX) return DEDSEC_ENOMEM;
                    ++*one;
                } else {
                    if (*zero == UINT64_MAX) return DEDSEC_ENOMEM;
                    ++*zero;
                }
                if (!have_record) {
                    *first = start;
                    have_record = 1;
                }
                *last = record_end;
                s = dedsec_emit_symbol(emit, user, "unicode",
                                       "implicit-bidi-source-order-collision",
                                       "implicit-bidi-ltr-source-order-bits-msb",
                                       start, record_end - start, value, 1);
                if (s != DEDSEC_OK) return s;
            }
            start = record_end;
        } else {
            /* An unterminated final line is never a complete slot. */
            break;
        }
    }
    return DEDSEC_OK;
}

static dedsec_status detect_implicit_bidi(dedsec_view input,
                                          dedsec_finding_fn emit, void *user) {
    uint64_t zero = 0, one = 0, total, minority;
    size_t first = 0, last = 0;
    dedsec_status s;
    s = scan_implicit_bidi(input, emit, user, &zero, &one, &first, &last);
    if (s != DEDSEC_OK) return s;
    total = zero + one;
    minority = zero < one ? zero : one;
    if (total >= 32 && zero >= 8 && one >= 8 && minority * 5 >= total)
        return dedsec_emit_finding(emit, user, "unicode",
                                   "implicit-bidi-source-order-collision",
                                   "implicit-bidi-ltr-source-order-bits-msb",
                                   first, last >= first ? last - first : 0,
                                   55, total);
    return DEDSEC_OK;
}

static dedsec_status unicode_detect(void *context, dedsec_view input,
                                    dedsec_finding_fn emit, void *user) {
    unicode_scan x = {0};
    dedsec_status s;
    size_t error = 0;
    (void)context;
    x.emit = emit; x.user = user;
    s = dedsec_utf8_foreach(input, validate_only, NULL, &error);
    if (s == DEDSEC_EUTF8) return DEDSEC_OK; /* encoding module owns this */
    if (s != DEDSEC_OK) return s;
    s = dedsec_utf8_foreach(input, scan_scalar, &x, &error);
    if (s != DEDSEC_OK) return s;
    s = detect_implicit_bidi(input, emit, user);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.tags, x.first_tag, "unicode-tags", "tags-ascii", 85);
    if (s != DEDSEC_OK) return s;
    if (x.zwsp && x.zwnj) {
        uint64_t symbols = x.zwsp + x.zwnj;
        uint32_t score = 45u + (symbols > 10 ? 15u : (uint32_t)symbols);
        if (score > 100u) score = 100u;
        s = dedsec_emit_finding(x.emit, x.user, "unicode",
                                "zero-width-binary-symbols", "zwsp-zwnj-msb",
                                x.first_ignorable, 0, score, symbols);
        if (s != DEDSEC_OK) return s;
    }
    s = emit_count(&x, x.selectors, x.first_selector, "variation-selectors",
                   "variation-nibbles", 45);
    if (s != DEDSEC_OK) return s;
    {
        uint64_t symbols = x.mongolian_fvs1 + x.mongolian_fvs2;
        uint64_t minority = x.mongolian_fvs1 < x.mongolian_fvs2 ?
            x.mongolian_fvs1 : x.mongolian_fvs2;
        if (symbols >= 32 && x.mongolian_fvs1 >= 8 && x.mongolian_fvs2 >= 8 &&
            minority * 5 >= symbols) {
            s = dedsec_emit_finding(x.emit, x.user, "unicode",
                                    "mongolian-fvs-binary-symbols",
                                    "mongolian-fvs1-fvs2-bits-msb",
                                    x.first_mongolian_fvs, 0, 55, symbols);
            if (s != DEDSEC_OK) return s;
        }
    }
    s = emit_count(&x, x.bidi, x.first_bidi, "bidi-controls", NULL, 60);
    if (s != DEDSEC_OK) return s;
    {
        uint64_t openers = x.lri + x.rli;
        uint64_t minority = x.lri < x.rli ? x.lri : x.rli;
        uint64_t base_scalars = x.scalars > x.bidi ? x.scalars - x.bidi : 0;
        double minority_ratio = openers ? (double)minority / (double)openers : 0.0;
        double matched_ratio = openers ?
            (double)x.matched_binary_isolates / (double)openers : 0.0;
        double empty_ratio = openers ?
            (double)x.empty_binary_isolates / (double)openers : 0.0;
        double after_arabic_ratio = x.empty_binary_isolates ?
            (double)x.empty_after_arabic / (double)x.empty_binary_isolates : 0.0;
        double density = base_scalars ? (double)openers / (double)base_scalars : 0.0;
        if (openers >= 64 && x.lri >= 8 && x.rli >= 8 &&
            minority_ratio >= 0.10 && matched_ratio >= 0.90 &&
            empty_ratio >= 0.50 && density >= 0.05 && !x.stack_overflow &&
            !x.unmatched_pdi && !x.bidi_depth) {
            uint32_t score = 65;
            if (empty_ratio >= 0.90) score += 10;
            if (minority_ratio >= 0.25) score += 10;
            if (density >= 0.10) score += 10;
            if (after_arabic_ratio >= 0.50) score += 5;
            s = dedsec_emit_finding(x.emit, x.user, "unicode",
                                    "binary-bidi-isolates",
                                    "bidi-isolate-bits-msb",
                                    x.first_bidi, 0, score, openers);
            if (s != DEDSEC_OK) return s;
        }
    }
    s = emit_count(&x, x.interior_bom, x.first_bom, "interior-bom",
                   "strip-known-ignorables", 80);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.noncharacters, x.first_noncharacter,
                   "unicode-noncharacters", "codepoint-map-msb", 90);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.shorthand, x.first_shorthand,
                   "shorthand-format-controls", "codepoint-map-msb", 75);
    if (s != DEDSEC_OK) return s;
    s = emit_count(&x, x.iteration, x.first_iteration,
                   "ideographic-iteration-marks", "codepoint-map-msb", 10);
    if (s != DEDSEC_OK) return s;
    return emit_count(&x, x.ignorables, x.first_ignorable,
                      "default-ignorable-candidates", "strip-known-ignorables", 35);
}

typedef struct decode_state {
    const char *variant;
    dedsec_bitstream *out;
    int in_tags;
    const dedsec_codepoint_alphabet *alphabet;
    int lsb_first;
    uint32_t iteration_first;
    int iteration_have_first;
    uint32_t previous_cp;
    int have_previous;
    dedsec_status status;
} decode_state;

static dedsec_status decode_bit(decode_state *x, unsigned bit) {
    return dedsec_bitstream_append_bits(x->out, (uint8_t)bit, 1, 0);
}

static dedsec_status decode_value(decode_state *x, uint8_t value, unsigned width) {
    unsigned j;
    for (j = 0; j < width; ++j) {
        unsigned shift = x->lsb_first ? j : width - 1u - j;
        dedsec_status s = decode_bit(x, (value >> shift) & 1u);
        if (s != DEDSEC_OK) return s;
    }
    return DEDSEC_OK;
}

static int decode_scalar(void *opaque, const dedsec_scalar *s) {
    decode_state *x = (decode_state *)opaque;
    uint32_t cp = s->value;
    if (dedsec_streq(x->variant, "tags-ascii")) {
        if (cp == 0xe0001) x->in_tags = 1;
        else if (cp == 0xe007f) x->in_tags = 0;
        else if (x->in_tags && in_range(cp, 0xe0020, 0xe007e))
            x->status = dedsec_bitstream_append_bits(x->out,
                                                      (uint8_t)(cp - 0xe0000), 8, 0);
    } else if (dedsec_streq(x->variant, "zwsp-zwnj-msb")) {
        if (cp == 0x200b || cp == 0x200c)
            x->status = decode_bit(x, cp == 0x200c);
    } else if (dedsec_streq(x->variant, "variation-nibbles")) {
        if (in_range(cp, 0xfe00, 0xfe0f)) {
            unsigned nibble = (unsigned)(cp - 0xfe00);
            x->status = decode_value(x, (uint8_t)nibble, 4);
        }
    } else if (dedsec_streq(x->variant, "mongolian-fvs1-fvs2-bits-msb")) {
        if (x->have_previous && x->previous_cp == 0x1820) {
            if (cp == 0x180b) x->status = decode_bit(x, 0);
            else if (cp == 0x180c) x->status = decode_bit(x, 1);
        }
    } else if (dedsec_streq(x->variant, "bidi-isolate-bits-msb")) {
        if (cp == 0x2066 || cp == 0x2067)
            x->status = decode_bit(x, cp == 0x2067);
    } else if (dedsec_streq(x->variant, "codepoint-map-msb") ||
               dedsec_streq(x->variant, "codepoint-map-lsb")) {
        size_t i;
        for (i = 0; i < x->alphabet->symbol_count; ++i)
            if (x->alphabet->symbols[i].codepoint == cp) {
                x->status = decode_value(x, x->alphabet->symbols[i].value,
                                         x->alphabet->bit_width);
                break;
            }
    } else if (dedsec_streq(x->variant, "iteration-mark-bits")) {
        if (cp == 0x3001) {
            x->iteration_have_first = 0;
        } else if (!x->iteration_have_first) {
            x->iteration_first = cp;
            x->iteration_have_first = 1;
        } else {
            if (cp == x->iteration_first) x->status = decode_bit(x, 0);
            else if (cp == 0x3005) x->status = decode_bit(x, 1);
            x->iteration_have_first = 0;
        }
    }
    x->previous_cp = cp;
    x->have_previous = 1;
    return x->status != DEDSEC_OK;
}

static dedsec_status decode_implicit_bidi(dedsec_view input,
                                          dedsec_bitstream *output) {
    size_t start = 0;
    while (start < input.len) {
        size_t end = start;
        uint8_t value;
        while (end < input.len && input.ptr[end] != 0x0a) ++end;
        if (end < input.len) {
            size_t record_end = end + 1;
            if (implicit_bidi_record(input, start, record_end, &value)) {
                dedsec_status s = dedsec_bitstream_append_bits(output, value, 1, 0);
                if (s != DEDSEC_OK) return s;
            }
            start = record_end;
        } else {
            break;
        }
    }
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static dedsec_status strip_ignorables(dedsec_view input, dedsec_bitstream *output) {
    size_t i = 0, start;
    size_t error = 0;
    dedsec_status valid = dedsec_utf8_foreach(input, validate_only, NULL, &error);
    if (valid != DEDSEC_OK) return valid;
    while (i < input.len) {
        uint8_t b = input.ptr[i];
        size_t n = b < 0x80 ? 1 : ((b & 0xe0) == 0xc0 ? 2 : ((b & 0xf0) == 0xe0 ? 3 : 4));
        uint32_t cp;
        if (n > input.len - i) return DEDSEC_EUTF8;
        start = i;
        if (n == 1) cp = b;
        else if (n == 2) cp = ((uint32_t)(b & 0x1f) << 6) | (input.ptr[i+1]&0x3f);
        else if (n == 3) cp = ((uint32_t)(b & 0x0f) << 12) | ((uint32_t)(input.ptr[i+1]&0x3f)<<6) | (input.ptr[i+2]&0x3f);
        else cp = ((uint32_t)(b & 7)<<18) | ((uint32_t)(input.ptr[i+1]&0x3f)<<12) | ((uint32_t)(input.ptr[i+2]&0x3f)<<6) | (input.ptr[i+3]&0x3f);
        if (!dedsec_unicode_is_default_ignorable(cp)) {
            size_t j;
            dedsec_status s = DEDSEC_OK;
            for (j = 0; j < n; ++j) {
                s = dedsec_bitstream_append_bits(output, input.ptr[start + j], 8, 0);
                if (s != DEDSEC_OK) break;
            }
            if (s != DEDSEC_OK) return s;
        }
        i += n;
    }
    return DEDSEC_OK;
}

static dedsec_status unicode_decode(void *context, dedsec_view input,
                                    const dedsec_decode_request *request,
                                    dedsec_bitstream *output) {
    decode_state x = {0};
    dedsec_status s;
    size_t error = 0;
    (void)context;
    if (dedsec_streq(request->variant, "strip-known-ignorables"))
        return strip_ignorables(input, output);
    if (!dedsec_streq(request->variant, "tags-ascii") &&
        !dedsec_streq(request->variant, "zwsp-zwnj-msb") &&
        !dedsec_streq(request->variant, "variation-nibbles") &&
        !dedsec_streq(request->variant, "mongolian-fvs1-fvs2-bits-msb") &&
        !dedsec_streq(request->variant, "bidi-isolate-bits-msb") &&
        !dedsec_streq(request->variant,
                      "implicit-bidi-ltr-source-order-bits-msb") &&
        !dedsec_streq(request->variant, "iteration-mark-bits") &&
        !dedsec_streq(request->variant, "codepoint-map-msb") &&
        !dedsec_streq(request->variant, "codepoint-map-lsb"))
        return DEDSEC_EUNSUPPORTED;
    if (dedsec_streq(request->variant,
                     "implicit-bidi-ltr-source-order-bits-msb")) {
        s = dedsec_utf8_foreach(input, validate_only, NULL, &error);
        if (s != DEDSEC_OK) return s;
        return decode_implicit_bidi(input, output);
    }
    x.variant = request->variant; x.out = output; x.status = DEDSEC_OK;
    if (dedsec_streq(request->variant, "codepoint-map-msb") ||
        dedsec_streq(request->variant, "codepoint-map-lsb")) {
        if (!request->params || request->params_size != sizeof(dedsec_codepoint_alphabet))
            return DEDSEC_EINVAL;
        x.alphabet = (const dedsec_codepoint_alphabet *)request->params;
        if (!x.alphabet->symbols || !x.alphabet->symbol_count ||
            !x.alphabet->bit_width || x.alphabet->bit_width > 8) return DEDSEC_EINVAL;
        {
            size_t i;
            unsigned limit = 1u << x.alphabet->bit_width;
            for (i = 0; i < x.alphabet->symbol_count; ++i)
                if ((unsigned)x.alphabet->symbols[i].value >= limit) return DEDSEC_EINVAL;
        }
        x.lsb_first = dedsec_streq(request->variant, "codepoint-map-lsb") ||
                      x.alphabet->lsb_first;
    }
    s = dedsec_utf8_foreach(input, decode_scalar, &x, &error);
    if (s == DEDSEC_ESTOP && x.status != DEDSEC_OK) return x.status;
    if (s != DEDSEC_OK) return s;
    return output->bit_length ? DEDSEC_OK : DEDSEC_ENOTFOUND;
}

static const dedsec_module module = {
    DEDSEC_ABI_VERSION, "unicode", NULL, unicode_detect, NULL, unicode_decode
};
const dedsec_module *dedsec_builtin_unicode_module(void) { return &module; }
