#include "internal.h"

#include <stdlib.h>

#define SCORE_Q16_ONE 65536u
#define SCORE_SHORT_BITS 24u
#define SCORE_DEFAULT_LZ_LIMIT 65536u
#define SCORE_LINEAR_MAX_BITS 1024u

typedef struct lz_node {
    size_t child[2];
} lz_node;

static unsigned score_bit(const dedsec_bitstream *stream, size_t index) {
    return (stream->bytes.ptr[index / 8u] >>
            (7u - (unsigned)(index % 8u))) & 1u;
}

static int valid_stream(const dedsec_bitstream *stream) {
    size_t required;
    if (!stream || (!stream->bytes.ptr && stream->bit_length)) return 0;
    if (stream->bit_length > SIZE_MAX - 7u) return 0;
    required = (stream->bit_length + 7u) / 8u;
    if (stream->bytes.len != required ||
        stream->bytes.len > stream->bytes.capacity) return 0;
    if (stream->bit_length % 8u) {
        unsigned unused = 8u - (unsigned)(stream->bit_length % 8u);
        uint8_t mask = (uint8_t)((1u << unused) - 1u);
        if (stream->bytes.ptr[required - 1u] & mask) return 0;
    }
    return 1;
}

static unsigned ceil_log2_size(size_t value) {
    unsigned bits = 0;
    size_t power = 1;
    while (power < value && power <= SIZE_MAX / 2u) {
        power <<= 1;
        ++bits;
    }
    if (power < value) ++bits;
    return bits;
}

/* Piecewise-linear log2 over sixteen mantissa intervals. Maximum table
 * interpolation error is small relative to the heuristic/model uncertainty. */
static uint64_t log2_q16_u64(uint64_t value) {
    static const uint32_t table[17] = {
        0u, 5732u, 11136u, 16248u, 21098u, 25711u, 30109u, 34312u,
        38336u, 42196u, 45904u, 49472u, 52911u, 56229u, 59434u,
        62534u, 65536u
    };
    unsigned integer = 0, slot;
    uint64_t normalized, fraction, delta;
    if (!value) return 0;
    normalized = value;
    while (normalized > 1u) {
        normalized >>= 1;
        ++integer;
    }
    if (integer >= 16u)
        normalized = value >> (integer - 16u);
    else
        normalized = value << (16u - integer);
    fraction = normalized - 65536u;
    slot = (unsigned)(fraction >> 12);
    if (slot > 15u) slot = 15u;
    delta = table[slot + 1u] - table[slot];
    return (uint64_t)integer * SCORE_Q16_ONE + table[slot] +
           ((delta * (fraction & 4095u)) >> 12);
}

static uint64_t add_cost(uint64_t total, uint64_t value, uint32_t *flags) {
    if (UINT64_MAX - total < value) {
        *flags |= DEDSEC_BITSTREAM_SCORE_ARITHMETIC_CLAMPED;
        return UINT64_MAX;
    }
    return total + value;
}

static uint64_t kt_binary_cost_q16(size_t zero, size_t one,
                                   uint32_t *flags) {
    size_t z = 0, o = 0, i;
    uint64_t cost = 0;
    /* Prequential KT: -log2((count + 1/2)/(total + 1)). Counts alone
     * determine the product, so order within this binary subsequence does not. */
    for (i = 0; i < zero + one; ++i) {
        int take_one = i >= zero;
        uint64_t numerator = 2u * (uint64_t)(z + o + 1u);
        uint64_t denominator = 2u * (uint64_t)(take_one ? o : z) + 1u;
        uint64_t term = log2_q16_u64(numerator) - log2_q16_u64(denominator);
        cost = add_cost(cost, term, flags);
        if (take_one) ++o; else ++z;
    }
    return cost;
}

static void finish_result(dedsec_bitstream_scorer_result *result) {
    if (!result->assessed_bits || result->description_bits_q16 == UINT64_MAX) {
        result->bits_per_source_bit_q16 = UINT32_MAX;
    } else {
        uint64_t ratio = result->description_bits_q16 / result->assessed_bits;
        result->bits_per_source_bit_q16 = ratio > UINT32_MAX ?
            UINT32_MAX : (uint32_t)ratio;
    }
    if (result->source_bits < SCORE_SHORT_BITS)
        result->flags |= DEDSEC_BITSTREAM_SCORE_SHORT_SAMPLE;
}

dedsec_status dedsec_bitstream_scorer_runs(
    const dedsec_bitstream *stream, dedsec_bitstream_scorer_result *result) {
    size_t i, transitions = 0;
    uint32_t flags = 0;
    if (!valid_stream(stream) || !result) return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_scorer_result){0};
    result->scorer = DEDSEC_BITSTREAM_SCORER_RUNS;
    result->source_bits = result->assessed_bits = stream->bit_length;
    for (i = 1; i < stream->bit_length; ++i)
        if (score_bit(stream, i) != score_bit(stream, i - 1u)) ++transitions;
    result->statistic = transitions;
    if (stream->bit_length) {
        result->description_bits_q16 = SCORE_Q16_ONE;
        if (stream->bit_length > 1u)
            result->description_bits_q16 = add_cost(
                result->description_bits_q16,
                kt_binary_cost_q16(stream->bit_length - 1u - transitions,
                                   transitions, &flags), &flags);
    }
    result->flags = flags;
    finish_result(result);
    return DEDSEC_OK;
}

static uint64_t kt_order_cost(const dedsec_bitstream *stream, unsigned order,
                              uint32_t *flags, size_t *used_contexts) {
    size_t counts[31][2] = {{0}};
    size_t i;
    uint64_t total = 0;
    *used_contexts = 0;
    for (i = 0; i < stream->bit_length; ++i) {
        unsigned context = 0, available = i < order ? (unsigned)i : order, j;
        size_t zero, one;
        for (j = available; j > 0; --j)
            context = (context << 1) | score_bit(stream, i - j);
        /* Distinguish short prefixes from full contexts. */
        context += (1u << available) - 1u;
        zero = counts[context][0];
        one = counts[context][1];
        total = add_cost(total,
            log2_q16_u64(2u * (uint64_t)(zero + one + 1u)) -
            log2_q16_u64(2u * (uint64_t)(score_bit(stream, i) ? one : zero) + 1u),
            flags);
        ++counts[context][score_bit(stream, i)];
    }
    for (i = 0; i < 31u; ++i)
        if (counts[i][0] || counts[i][1]) ++*used_contexts;
    return total;
}

dedsec_status dedsec_bitstream_scorer_kt(
    const dedsec_bitstream *stream, unsigned maximum_order,
    dedsec_bitstream_scorer_result *result) {
    unsigned order;
    uint64_t best = UINT64_MAX, model_cost;
    size_t best_contexts = 0;
    uint32_t flags = 0;
    if (!valid_stream(stream) || !result || maximum_order > 4u)
        return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_scorer_result){0};
    result->scorer = DEDSEC_BITSTREAM_SCORER_KT;
    result->source_bits = result->assessed_bits = stream->bit_length;
    model_cost = (uint64_t)ceil_log2_size((size_t)maximum_order + 1u) *
                 SCORE_Q16_ONE;
    for (order = 0; order <= maximum_order; ++order) {
        size_t contexts = 0;
        uint64_t cost = kt_order_cost(stream, order, &flags, &contexts);
        cost = add_cost(cost, model_cost, &flags);
        if (cost < best) {
            best = cost;
            result->model_parameter = order;
            best_contexts = contexts;
        }
    }
    result->description_bits_q16 = stream->bit_length ? best : 0;
    result->statistic = best_contexts;
    result->flags = flags;
    finish_result(result);
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_scorer_periodic(
    const dedsec_bitstream *stream, unsigned maximum_period,
    dedsec_bitstream_scorer_result *result) {
    unsigned period;
    uint64_t best = UINT64_MAX;
    uint32_t flags = 0;
    size_t best_errors = 0;
    if (!valid_stream(stream) || !result || maximum_period > 64u)
        return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_scorer_result){0};
    result->scorer = DEDSEC_BITSTREAM_SCORER_PERIODIC;
    result->source_bits = result->assessed_bits = stream->bit_length;
    if (!stream->bit_length || !maximum_period) {
        result->description_bits_q16 = 0;
        result->flags = DEDSEC_BITSTREAM_SCORE_SHORT_SAMPLE;
        finish_result(result);
        return DEDSEC_OK;
    }
    if (maximum_period >= stream->bit_length)
        maximum_period = (unsigned)(stream->bit_length - 1u);
    for (period = 1; period <= maximum_period; ++period) {
        size_t i, errors = 0, trials = stream->bit_length - period;
        uint64_t cost;
        for (i = period; i < stream->bit_length; ++i)
            if (score_bit(stream, i) != score_bit(stream, i - period)) ++errors;
        cost = ((uint64_t)period + ceil_log2_size(maximum_period + 1u)) *
               SCORE_Q16_ONE;
        cost = add_cost(cost,
                        kt_binary_cost_q16(trials - errors, errors, &flags),
                        &flags);
        if (cost < best) {
            best = cost;
            result->model_parameter = period;
            best_errors = errors;
        }
    }
    result->description_bits_q16 = best;
    result->statistic = best_errors;
    result->flags = flags;
    finish_result(result);
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_scorer_lz78(
    const dedsec_bitstream *stream, size_t dictionary_limit,
    dedsec_bitstream_scorer_result *result) {
    lz_node *nodes;
    size_t position = 0, entries = 0, phrases = 0;
    uint64_t cost = 0;
    uint32_t flags = 0;
    if (!valid_stream(stream) || !result || !dictionary_limit ||
        dictionary_limit > (SIZE_MAX / sizeof(*nodes)) - 1u)
        return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_scorer_result){0};
    result->scorer = DEDSEC_BITSTREAM_SCORER_LZ78;
    result->source_bits = stream->bit_length;
    nodes = (lz_node *)calloc(dictionary_limit + 1u, sizeof(*nodes));
    if (!nodes) return DEDSEC_ENOMEM;
    while (position < stream->bit_length) {
        size_t start = position, node = 0;
        int added = 0;
        while (position < stream->bit_length) {
            unsigned bit = score_bit(stream, position);
            size_t next = nodes[node].child[bit];
            if (!next) {
                if (entries == dictionary_limit) {
                    flags |= DEDSEC_BITSTREAM_SCORE_LIMIT_REACHED;
                    position = start;
                    goto done;
                }
                ++entries;
                nodes[node].child[bit] = entries;
                ++position;
                ++phrases;
                added = 1;
                cost = add_cost(cost,
                    ((uint64_t)ceil_log2_size(entries) + 1u) * SCORE_Q16_ONE,
                    &flags);
                break;
            }
            node = next;
            ++position;
        }
        if (position == stream->bit_length && !added && node != 0) {
            ++phrases;
            cost = add_cost(cost,
                (uint64_t)ceil_log2_size(entries + 1u) * SCORE_Q16_ONE,
                &flags);
        }
    }
done:
    free(nodes);
    result->assessed_bits = position;
    result->description_bits_q16 = cost;
    result->statistic = phrases;
    result->model_parameter = entries > UINT32_MAX ? UINT32_MAX : (unsigned)entries;
    result->flags = flags;
    finish_result(result);
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_scorer_linear(
    const dedsec_bitstream *stream, dedsec_bitstream_scorer_result *result) {
    uint8_t *connection, *previous, *saved;
    size_t n, index, length = 0, shift = 1;
    uint32_t flags = 0;
    if (!valid_stream(stream) || !result) return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_scorer_result){0};
    result->scorer = DEDSEC_BITSTREAM_SCORER_LINEAR;
    result->source_bits = result->assessed_bits = stream->bit_length;
    n = stream->bit_length;
    if (!n) {
        result->flags = DEDSEC_BITSTREAM_SCORE_SHORT_SAMPLE;
        finish_result(result);
        return DEDSEC_OK;
    }
    if (n > SCORE_LINEAR_MAX_BITS) {
        n = SCORE_LINEAR_MAX_BITS;
        result->assessed_bits = n;
        flags |= DEDSEC_BITSTREAM_SCORE_LIMIT_REACHED;
    }
    connection = (uint8_t *)calloc(n, 1);
    previous = (uint8_t *)calloc(n, 1);
    saved = (uint8_t *)calloc(n, 1);
    if (!connection || !previous || !saved) {
        free(connection); free(previous); free(saved);
        return DEDSEC_ENOMEM;
    }
    connection[0] = previous[0] = 1;
    for (index = 0; index < n; ++index) {
        unsigned discrepancy = score_bit(stream, index);
        size_t j;
        for (j = 1; j <= length; ++j)
            discrepancy ^= connection[j] & score_bit(stream, index - j);
        if (!discrepancy) { ++shift; continue; }
        for (j = 0; j < n; ++j) saved[j] = connection[j];
        for (j = shift; j < n; ++j)
            connection[j] ^= previous[j - shift];
        if (2u * length <= index) {
            length = index + 1u - length;
            for (j = 0; j < n; ++j) previous[j] = saved[j];
            shift = 1;
        } else ++shift;
    }
    free(connection); free(previous); free(saved);
    result->statistic = length;
    result->model_parameter = length > UINT32_MAX ? UINT32_MAX : (unsigned)length;
    if (length > (UINT64_MAX / SCORE_Q16_ONE -
                  ceil_log2_size(n + 1u)) / 2u) {
        result->description_bits_q16 = UINT64_MAX;
        flags |= DEDSEC_BITSTREAM_SCORE_ARITHMETIC_CLAMPED;
    } else {
        result->description_bits_q16 =
            (2u * (uint64_t)length + ceil_log2_size(n + 1u)) * SCORE_Q16_ONE;
    }
    result->flags = flags;
    finish_result(result);
    return DEDSEC_OK;
}

dedsec_status dedsec_bitstream_score(
    const dedsec_bitstream *stream, dedsec_bitstream_score_result *result) {
    dedsec_status status;
    uint32_t threshold, basic_min, periodic, lz78;
    size_t lz_limit;
    if (!valid_stream(stream) || !result) return DEDSEC_EINVAL;
    *result = (dedsec_bitstream_score_result){0};
    result->source_bits = stream->bit_length;
    result->scorer_count = DEDSEC_BITSTREAM_SCORER_COUNT;
    status = dedsec_bitstream_scorer_runs(stream, &result->scorers[0]);
    if (status != DEDSEC_OK) return status;
    /* Order one is the default natural-regime model. Higher orders remain
     * available through the public scorer, but selecting among them here can
     * cheaply memorize short byte-shaped streams and hide useful structure. */
    status = dedsec_bitstream_scorer_kt(stream, 1u, &result->scorers[1]);
    if (status != DEDSEC_OK) return status;
    status = dedsec_bitstream_scorer_periodic(stream, 8u, &result->scorers[2]);
    if (status != DEDSEC_OK) return status;
    lz_limit = stream->bit_length < SCORE_DEFAULT_LZ_LIMIT ?
        stream->bit_length : SCORE_DEFAULT_LZ_LIMIT;
    if (!lz_limit) lz_limit = 1;
    status = dedsec_bitstream_scorer_lz78(stream, lz_limit,
                                          &result->scorers[3]);
    if (status != DEDSEC_OK) return status;
    if (stream->bit_length < SCORE_SHORT_BITS) {
        result->flags |= DEDSEC_BITSTREAM_SCORE_SHORT_SAMPLE;
        return DEDSEC_OK;
    }
    threshold = (uint32_t)(49152u +
        (stream->bit_length < 65536u ?
         (524288u / (uint32_t)stream->bit_length) : 8u));
    if (threshold > 72090u) threshold = 72090u;
    basic_min = result->scorers[0].bits_per_source_bit_q16;
    if (result->scorers[1].bits_per_source_bit_q16 < basic_min)
        basic_min = result->scorers[1].bits_per_source_bit_q16;
    periodic = result->scorers[2].bits_per_source_bit_q16;
    lz78 = result->scorers[3].bits_per_source_bit_q16;
    if (basic_min < threshold) {
        result->flags |= DEDSEC_BITSTREAM_SCORE_SIMPLE;
        result->score = 20u;
    } else if (periodic < threshold) {
        result->flags |= DEDSEC_BITSTREAM_SCORE_PERIODIC_STRUCTURE;
        result->score = 72u;
    } else if (!(result->scorers[3].flags &
                 DEDSEC_BITSTREAM_SCORE_LIMIT_REACHED) && lz78 < threshold) {
        result->flags |= DEDSEC_BITSTREAM_SCORE_DICTIONARY_STRUCTURE;
        result->score = 72u;
    } else {
        result->flags |= DEDSEC_BITSTREAM_SCORE_HIGH_UNEXPLAINED;
        result->score = 70u;
    }
    return DEDSEC_OK;
}
