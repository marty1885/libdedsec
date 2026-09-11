#include "internal.h"

/* Generated from Unicode 17.0.0 DerivedCoreProperties.txt,
 * Default_Ignorable_Code_Point.  The compact range form is committed so the
 * library has no runtime UCD dependency.  Keep this table and its version
 * declaration synchronized when deliberately updating Unicode properties. */
typedef struct dedsec_unicode_range {
    uint32_t first;
    uint32_t last;
} dedsec_unicode_range;

static const dedsec_unicode_range default_ignorable_ranges[] = {
    {0x00adu, 0x00adu}, {0x034fu, 0x034fu}, {0x061cu, 0x061cu},
    {0x115fu, 0x1160u}, {0x17b4u, 0x17b5u}, {0x180bu, 0x180fu},
    {0x200bu, 0x200fu}, {0x202au, 0x202eu}, {0x2060u, 0x206fu},
    {0x3164u, 0x3164u}, {0xfe00u, 0xfe0fu}, {0xfeffu, 0xfeffu},
    {0xffa0u, 0xffa0u}, {0xfff0u, 0xfff8u}, {0x1bca0u, 0x1bca3u},
    {0x1d173u, 0x1d17au}, {0xe0000u, 0xe0fffu}
};

/* Generated from Unicode 17.0.0 PropList.txt, White_Space. This is separate
 * from byte-oriented ASCII hspace handling and must not change its semantics. */
static const dedsec_unicode_range white_space_ranges[] = {
    {0x0009u, 0x000du}, {0x0020u, 0x0020u}, {0x0085u, 0x0085u},
    {0x00a0u, 0x00a0u}, {0x1680u, 0x1680u}, {0x2000u, 0x200au},
    {0x2028u, 0x2029u}, {0x202fu, 0x202fu}, {0x205fu, 0x205fu},
    {0x3000u, 0x3000u}
};

/* Generated from Unicode 17.0.0 UnicodeData.txt, General_Category=Cc. */
static const dedsec_unicode_range control_ranges[] = {
    {0x0000u, 0x001fu}, {0x007fu, 0x009fu}
};

/* Generated from Unicode 17.0.0 UnicodeData.txt, General_Category=Cf.
 * Callers that need the residual non-default-ignorable inventory must combine
 * this with dedsec_unicode_is_default_ignorable(); do not infer invisibility
 * from General_Category alone. */
static const dedsec_unicode_range format_control_ranges[] = {
    {0x00adu, 0x00adu}, {0x0600u, 0x0605u}, {0x061cu, 0x061cu},
    {0x06ddu, 0x06ddu}, {0x070fu, 0x070fu}, {0x0890u, 0x0891u},
    {0x08e2u, 0x08e2u}, {0x180eu, 0x180eu}, {0x200bu, 0x200fu},
    {0x202au, 0x202eu}, {0x2060u, 0x206fu}, {0xfeffu, 0xfeffu},
    {0xfff9u, 0xfffbu}, {0x110bdu, 0x110cdu}, {0x13430u, 0x1343fu},
    {0x1bca0u, 0x1bca3u}, {0x1d173u, 0x1d17au}, {0xe0001u, 0xe0001u},
    {0xe0020u, 0xe007fu}
};

static int in_ranges(const dedsec_unicode_range *ranges, size_t count,
                     uint32_t cp) {
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (cp < ranges[mid].first) {
            hi = mid;
        } else if (cp > ranges[mid].last) {
            lo = mid + 1u;
        } else {
            return 1;
        }
    }
    return 0;
}

int dedsec_unicode_is_default_ignorable(uint32_t cp) {
    return in_ranges(default_ignorable_ranges,
                     sizeof(default_ignorable_ranges) /
                     sizeof(default_ignorable_ranges[0]), cp);
}

int dedsec_unicode_is_white_space(uint32_t cp) {
    return in_ranges(white_space_ranges,
                     sizeof(white_space_ranges) / sizeof(white_space_ranges[0]),
                     cp);
}

int dedsec_unicode_is_control(uint32_t cp) {
    return in_ranges(control_ranges,
                     sizeof(control_ranges) / sizeof(control_ranges[0]), cp);
}

int dedsec_unicode_is_format_control(uint32_t cp) {
    return in_ranges(format_control_ranges,
                     sizeof(format_control_ranges) /
                     sizeof(format_control_ranges[0]), cp);
}
