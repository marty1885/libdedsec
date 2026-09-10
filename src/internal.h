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
int dedsec_is_hspace(uint8_t byte);

#endif
