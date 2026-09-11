#include "internal.h"

#include <stdlib.h>
#include <string.h>

int dedsec_streq(const char *a, const char *b) {
    return a != NULL && b != NULL && strcmp(a, b) == 0;
}

void dedsec_buffer_init(dedsec_buffer *buffer) {
    if (buffer) { buffer->ptr = NULL; buffer->len = 0; buffer->capacity = 0; }
}

void dedsec_buffer_free(dedsec_buffer *buffer) {
    if (buffer) { free(buffer->ptr); dedsec_buffer_init(buffer); }
}

void dedsec_bitstream_init(dedsec_bitstream *stream) {
    if (stream) { dedsec_buffer_init(&stream->bytes); stream->bit_length = 0; }
}

void dedsec_bitstream_free(dedsec_bitstream *stream) {
    if (stream) { dedsec_buffer_free(&stream->bytes); stream->bit_length = 0; }
}

dedsec_status dedsec_bitstream_append_bits(dedsec_bitstream *stream,
                                           uint8_t value, unsigned bit_count,
                                           int lsb_first) {
    unsigned j;
    if (!stream || !bit_count || bit_count > 8 ||
        stream->bit_length > SIZE_MAX - bit_count) return DEDSEC_EINVAL;
    for (j = 0; j < bit_count; ++j) {
        size_t byte_index = stream->bit_length / 8;
        unsigned bit_index = (unsigned)(stream->bit_length % 8);
        unsigned shift = lsb_first ? j : bit_count - 1u - j;
        dedsec_status s;
        if (bit_index == 0) {
            s = dedsec_buffer_push(&stream->bytes, 0);
            if (s != DEDSEC_OK) return s;
        }
        if ((value >> shift) & 1u)
            stream->bytes.ptr[byte_index] |= (uint8_t)(0x80u >> bit_index);
        ++stream->bit_length;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_buffer_append(dedsec_buffer *buffer,
                                   const void *data, size_t length) {
    size_t needed, capacity;
    uint8_t *next;
    if (!buffer || (!data && length)) return DEDSEC_EINVAL;
    if (length > SIZE_MAX - buffer->len) return DEDSEC_ENOMEM;
    needed = buffer->len + length;
    if (needed > buffer->capacity) {
        capacity = buffer->capacity ? buffer->capacity : 64;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) { capacity = needed; break; }
            capacity *= 2;
        }
        next = (uint8_t *)realloc(buffer->ptr, capacity);
        if (!next) return DEDSEC_ENOMEM;
        buffer->ptr = next;
        buffer->capacity = capacity;
    }
    if (length) memcpy(buffer->ptr + buffer->len, data, length);
    buffer->len = needed;
    return DEDSEC_OK;
}

dedsec_status dedsec_buffer_push(dedsec_buffer *buffer, uint8_t byte) {
    return dedsec_buffer_append(buffer, &byte, 1);
}

void dedsec_registry_init(dedsec_registry *registry) {
    if (registry) { registry->modules = NULL; registry->count = 0; registry->capacity = 0; }
}

void dedsec_registry_free(dedsec_registry *registry) {
    if (registry) { free(registry->modules); dedsec_registry_init(registry); }
}

dedsec_status dedsec_registry_add(dedsec_registry *registry,
                                  const dedsec_module *module) {
    const dedsec_module **next;
    size_t capacity;
    if (!registry || !module || module->abi_version != DEDSEC_ABI_VERSION ||
        !module->id || !module->detect || (!module->decode && !module->decode_bits))
        return DEDSEC_EINVAL;
    if (dedsec_registry_find(registry, module->id)) return DEDSEC_EINVAL;
    if (registry->count == registry->capacity) {
        capacity = registry->capacity ? registry->capacity * 2 : 8;
        next = (const dedsec_module **)realloc(registry->modules,
                                               capacity * sizeof(*next));
        if (!next) return DEDSEC_ENOMEM;
        registry->modules = next;
        registry->capacity = capacity;
    }
    registry->modules[registry->count++] = module;
    return DEDSEC_OK;
}

const dedsec_module *dedsec_registry_find(const dedsec_registry *registry,
                                          const char *id) {
    size_t i;
    if (!registry || !id) return NULL;
    for (i = 0; i < registry->count; ++i)
        if (dedsec_streq(registry->modules[i]->id, id)) return registry->modules[i];
    return NULL;
}

dedsec_status dedsec_registry_add_builtins(dedsec_registry *registry) {
    const dedsec_module *mods[7];
    size_t i;
    dedsec_status status;
    mods[0] = dedsec_builtin_encoding_module();
    mods[1] = dedsec_builtin_unicode_module();
    mods[2] = dedsec_builtin_identity_module();
    mods[3] = dedsec_builtin_layout_module();
    mods[4] = dedsec_builtin_surface_module();
    mods[5] = dedsec_builtin_structure_module();
    mods[6] = dedsec_builtin_markdown_module();
    for (i = 0; i < 7; ++i) {
        status = dedsec_registry_add(registry, mods[i]);
        if (status != DEDSEC_OK) return status;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_emit_finding(dedsec_finding_fn emit, void *user,
                                  const char *module, const char *rule,
                                  const char *decoder, size_t offset,
                                  size_t length, uint32_t score,
                                  uint64_t evidence) {
    dedsec_finding finding;
    if (!emit) return DEDSEC_EINVAL;
    finding.module_id = module; finding.rule_id = rule;
    finding.decoder_hint = decoder; finding.byte_offset = offset;
    finding.byte_length = length; finding.score = score;
    finding.evidence = evidence;
    finding.kind = DEDSEC_DETECTION_FINDING;
    finding.symbol_value = 0;
    finding.symbol_width = 0;
    return emit(user, &finding) ? DEDSEC_ESTOP : DEDSEC_OK;
}

dedsec_status dedsec_emit_symbol(dedsec_finding_fn emit, void *user,
                                 const char *module, const char *rule,
                                 const char *decoder, size_t offset,
                                 size_t length, uint8_t value,
                                 uint8_t width) {
    dedsec_finding finding;
    if (!emit || !width || width > 8 || value >= (1u << width))
        return DEDSEC_EINVAL;
    finding.module_id = module;
    finding.rule_id = rule;
    finding.decoder_hint = decoder;
    finding.byte_offset = offset;
    finding.byte_length = length;
    finding.score = 0;
    finding.evidence = 1;
    finding.kind = DEDSEC_DETECTION_SYMBOL;
    finding.symbol_value = value;
    finding.symbol_width = width;
    return emit(user, &finding) ? DEDSEC_ESTOP : DEDSEC_OK;
}

dedsec_status dedsec_detect_all(const dedsec_registry *registry,
                                dedsec_view input,
                                dedsec_finding_fn emit, void *user) {
    size_t i;
    dedsec_status status;
    if (!registry || (!input.ptr && input.len) || !emit) return DEDSEC_EINVAL;
    for (i = 0; i < registry->count; ++i) {
        status = registry->modules[i]->detect(registry->modules[i]->context,
                                              input, emit, user);
        if (status != DEDSEC_OK) return status;
    }
    return DEDSEC_OK;
}

dedsec_status dedsec_decode(const dedsec_registry *registry,
                            const char *module_id, dedsec_view input,
                            const dedsec_decode_request *request,
                            dedsec_buffer *output) {
    dedsec_bitstream bits;
    dedsec_status s;
    size_t whole_bytes;
    if (!request || !request->variant || !output) return DEDSEC_EINVAL;
    output->len = 0;
    dedsec_bitstream_init(&bits);
    s = dedsec_decode_bits(registry, module_id, input, request, &bits);
    if (s == DEDSEC_OK) {
        whole_bytes = bits.bit_length / 8;
        s = dedsec_buffer_append(output, bits.bytes.ptr, whole_bytes);
    }
    dedsec_bitstream_free(&bits);
    return s;
}

dedsec_status dedsec_decode_bits(const dedsec_registry *registry,
                                 const char *module_id, dedsec_view input,
                                 const dedsec_decode_request *request,
                                 dedsec_bitstream *output) {
    const dedsec_module *module = dedsec_registry_find(registry, module_id);
    dedsec_status s;
    if (!module) return DEDSEC_ENOTFOUND;
    if (!request || !request->variant || !output) return DEDSEC_EINVAL;
    output->bytes.len = 0;
    output->bit_length = 0;
    if (module->decode_bits)
        return module->decode_bits(module->context, input, request, output);
    /* Version-1-style modules can only report complete bytes. */
    s = module->decode(module->context, input, request, &output->bytes);
    if (s == DEDSEC_OK) {
        if (output->bytes.len > SIZE_MAX / 8) return DEDSEC_ENOMEM;
        output->bit_length = output->bytes.len * 8;
    }
    return s;
}

int dedsec_is_hspace(uint8_t byte) { return byte == ' ' || byte == '\t'; }
