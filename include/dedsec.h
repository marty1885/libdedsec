#ifndef DEDSEC_H
#define DEDSEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DEDSEC_ABI_VERSION 2u

/* Filters for Markdown unordered-list trial decoders. */
#define DEDSEC_MARKDOWN_UL_TOP_LEVEL_ONLY 0x00000001u
#define DEDSEC_MARKDOWN_UL_NESTED_ONLY    0x00000002u

typedef enum dedsec_status {
    DEDSEC_OK = 0,
    DEDSEC_EINVAL = -1,
    DEDSEC_ENOMEM = -2,
    DEDSEC_EUTF8 = -3,
    DEDSEC_ENOTFOUND = -4,
    DEDSEC_EUNSUPPORTED = -5,
    DEDSEC_ESTOP = -6
} dedsec_status;

typedef struct dedsec_view {
    const uint8_t *ptr;
    size_t len;
} dedsec_view;

typedef struct dedsec_buffer {
    uint8_t *ptr;
    size_t len;
    size_t capacity;
} dedsec_buffer;

/* Bits are packed MSB-first. bytes.len is ceil(bit_length / 8); unused low
 * bits in the final byte are always zero. */
typedef struct dedsec_bitstream {
    dedsec_buffer bytes;
    size_t bit_length;
} dedsec_bitstream;

typedef struct dedsec_finding {
    const char *module_id;
    const char *rule_id;
    const char *decoder_hint;
    size_t byte_offset;
    size_t byte_length;
    uint32_t score;       /* heuristic, 0..100; never a probability */
    uint64_t evidence;
} dedsec_finding;

typedef int (*dedsec_finding_fn)(void *user, const dedsec_finding *finding);

typedef struct dedsec_decode_request {
    const char *variant;
    uint32_t flags;
    const void *params;
    size_t params_size;
} dedsec_decode_request;

typedef struct dedsec_codepoint_symbol {
    uint32_t codepoint;
    uint8_t value;
} dedsec_codepoint_symbol;

typedef struct dedsec_codepoint_alphabet {
    const dedsec_codepoint_symbol *symbols;
    size_t symbol_count;
    unsigned bit_width;
    int lsb_first;
} dedsec_codepoint_alphabet;

typedef struct dedsec_token_symbol {
    dedsec_view spelling;
    uint8_t value;
} dedsec_token_symbol;

typedef struct dedsec_token_alphabet {
    const dedsec_token_symbol *symbols;
    size_t symbol_count;
    unsigned bit_width;
    int lsb_first;
} dedsec_token_alphabet;

typedef struct dedsec_module {
    uint32_t abi_version;
    const char *id;
    void *context;
    dedsec_status (*detect)(void *context, dedsec_view input,
                            dedsec_finding_fn emit, void *user);
    dedsec_status (*decode)(void *context, dedsec_view input,
                            const dedsec_decode_request *request,
                            dedsec_buffer *output);
    /* Optional for legacy modules. New modules should preserve partial bytes
     * here; dedsec_decode() remains the whole-byte compatibility wrapper. */
    dedsec_status (*decode_bits)(void *context, dedsec_view input,
                                 const dedsec_decode_request *request,
                                 dedsec_bitstream *output);
} dedsec_module;

typedef struct dedsec_registry {
    const dedsec_module **modules;
    size_t count;
    size_t capacity;
} dedsec_registry;

void dedsec_buffer_init(dedsec_buffer *buffer);
void dedsec_buffer_free(dedsec_buffer *buffer);
dedsec_status dedsec_buffer_append(dedsec_buffer *buffer,
                                   const void *data, size_t length);
void dedsec_bitstream_init(dedsec_bitstream *stream);
void dedsec_bitstream_free(dedsec_bitstream *stream);
dedsec_status dedsec_bitstream_append_bits(dedsec_bitstream *stream,
                                           uint8_t value, unsigned bit_count,
                                           int lsb_first);

void dedsec_registry_init(dedsec_registry *registry);
void dedsec_registry_free(dedsec_registry *registry);
dedsec_status dedsec_registry_add(dedsec_registry *registry,
                                  const dedsec_module *module);
dedsec_status dedsec_registry_add_builtins(dedsec_registry *registry);
const dedsec_module *dedsec_registry_find(const dedsec_registry *registry,
                                          const char *id);
dedsec_status dedsec_detect_all(const dedsec_registry *registry,
                                dedsec_view input,
                                dedsec_finding_fn emit, void *user);
dedsec_status dedsec_decode(const dedsec_registry *registry,
                            const char *module_id, dedsec_view input,
                            const dedsec_decode_request *request,
                            dedsec_buffer *output);
dedsec_status dedsec_decode_bits(const dedsec_registry *registry,
                                 const char *module_id, dedsec_view input,
                                 const dedsec_decode_request *request,
                                 dedsec_bitstream *output);

typedef struct dedsec_scalar {
    uint32_t value;
    size_t byte_offset;
    uint8_t byte_length;
} dedsec_scalar;

typedef int (*dedsec_scalar_fn)(void *user, const dedsec_scalar *scalar);
dedsec_status dedsec_utf8_foreach(dedsec_view input,
                                  dedsec_scalar_fn emit, void *user,
                                  size_t *error_offset);

typedef enum dedsec_feature_kind {
    DEDSEC_FEATURE_LINE_BYTES,
    DEDSEC_FEATURE_WORD_BYTES,
    DEDSEC_FEATURE_WORD_CODEPOINTS,
    DEDSEC_FEATURE_GAP_WIDTH,
    DEDSEC_FEATURE_TRAILING_HSPACE,
    DEDSEC_FEATURE_WORD_INITIAL_CASE,
    DEDSEC_FEATURE_PUNCTUATION_CLASS,
    DEDSEC_FEATURE_CODEPOINT
} dedsec_feature_kind;

typedef struct dedsec_feature {
    int64_t value;
    size_t byte_offset;
    size_t byte_length;
} dedsec_feature;

typedef int (*dedsec_feature_fn)(void *user, const dedsec_feature *feature);
dedsec_status dedsec_extract_features(dedsec_feature_kind kind,
                                      dedsec_view input,
                                      dedsec_feature_fn emit, void *user);

typedef enum dedsec_binary_rule_kind {
    DEDSEC_BINARY_PARITY,
    DEDSEC_BINARY_EQUALS_PAIR,
    DEDSEC_BINARY_THRESHOLD,
    DEDSEC_BINARY_LOW_BIT
} dedsec_binary_rule_kind;

typedef struct dedsec_binary_rule {
    dedsec_binary_rule_kind kind;
    int64_t zero_value;
    int64_t one_value;
    unsigned bit_width;   /* 1..8; LOW_BIT may extract several bits */
    unsigned bit_offset;
    int lsb_first;
} dedsec_binary_rule;

dedsec_status dedsec_features_decode(const dedsec_feature *features,
                                     size_t feature_count,
                                     const dedsec_binary_rule *rule,
                                     dedsec_buffer *output);
dedsec_status dedsec_features_decode_bits(const dedsec_feature *features,
                                          size_t feature_count,
                                          const dedsec_binary_rule *rule,
                                          dedsec_bitstream *output);

typedef struct dedsec_text {
    dedsec_buffer bytes;
    size_t *origin;       /* one source byte offset per output byte */
    size_t origin_count;
    size_t origin_capacity;
} dedsec_text;

typedef dedsec_status (*dedsec_transform_fn)(void *context,
                                             const dedsec_text *input,
                                             dedsec_text *output);

typedef struct dedsec_transform {
    const char *id;
    dedsec_transform_fn apply;
    void *context;
} dedsec_transform;

typedef struct dedsec_chain {
    const dedsec_transform *steps;
    size_t count;
} dedsec_chain;

typedef struct dedsec_match {
    size_t chain_index;
    size_t needle_index;
    size_t transformed_offset;
    size_t source_offset;
} dedsec_match;

typedef int (*dedsec_match_fn)(void *user, const dedsec_match *match);
dedsec_status dedsec_search(dedsec_view haystack,
                            const dedsec_view *needles, size_t needle_count,
                            const dedsec_chain *chains, size_t chain_count,
                            dedsec_match_fn emit, void *user);

dedsec_status dedsec_transform_ascii_casefold(void *context,
                                              const dedsec_text *input,
                                              dedsec_text *output);
dedsec_status dedsec_transform_collapse_hspace(void *context,
                                               const dedsec_text *input,
                                               dedsec_text *output);
dedsec_status dedsec_transform_delete_hspace(void *context,
                                             const dedsec_text *input,
                                             dedsec_text *output);
dedsec_status dedsec_transform_strip_known_ignorables(void *context,
                                                      const dedsec_text *input,
                                                      dedsec_text *output);

const dedsec_module *dedsec_builtin_unicode_module(void);
const dedsec_module *dedsec_builtin_layout_module(void);
const dedsec_module *dedsec_builtin_encoding_module(void);
const dedsec_module *dedsec_builtin_surface_module(void);
const dedsec_module *dedsec_builtin_structure_module(void);
const dedsec_module *dedsec_builtin_markdown_module(void);

#ifdef __cplusplus
}
#endif
#endif
