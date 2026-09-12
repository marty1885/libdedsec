#ifndef DEDSEC_INTERNAL_H
#define DEDSEC_INTERNAL_H

#include "dedsec.h"

int dedsec_streq(const char *a, const char *b);
dedsec_status dedsec_buffer_push(dedsec_buffer *buffer, uint8_t byte);
dedsec_status dedsec_emit_finding(dedsec_finding_fn emit, void *user,
                                  const char *module, const char *rule,
                                  const char *decoder, size_t offset,
                                  size_t length, uint32_t score,
                                  uint64_t evidence);
dedsec_status dedsec_emit_symbol(dedsec_finding_fn emit, void *user,
                                 const char *module, const char *rule,
                                 const char *decoder, size_t offset,
                                 size_t length, uint8_t value,
                                 uint8_t width);
dedsec_status dedsec_emit_observation(dedsec_finding_fn emit, void *user,
                                      const char *module, const char *rule,
                                      size_t offset, size_t length,
                                      uint64_t evidence);
int dedsec_is_hspace(uint8_t byte);
dedsec_status dedsec_builtin_layout_detect_default(dedsec_view input,
                                                    dedsec_finding_fn emit,
                                                    void *user);
int dedsec_unicode_is_default_ignorable(uint32_t cp);
int dedsec_unicode_is_white_space(uint32_t cp);
int dedsec_unicode_is_control(uint32_t cp);
int dedsec_unicode_is_format_control(uint32_t cp);

#endif
