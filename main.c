#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <getopt.h>
#include <sys/time.h>

static int control(const uint8_t *src, int size, uint8_t *dst)
{
    (void) src;
    (void) size;
    (void) dst;
    return 0;
}

#define VERSION 1

#if VERSION == 1

static int vc1_unescape_buffer(const uint8_t *src, int size, uint8_t *dst)
{
    int dsize = 0, i;

    if (size < 4) {
        for (dsize = 0; dsize < size; dsize++)
            *dst++ = *src++;
        return size;
    }
    for (i = 0; i < size; i++, src++) {
        if (src[0] == 3 && i >= 2 && !src[-1] && !src[-2] && i < size-1 && src[1] < 4) {
            dst[dsize++] = src[1];
            src++;
            i++;
        } else
            dst[dsize++] = *src;
    }
    return dsize;
}

#elif VERSION == 2

static int vc1_unescape_buffer(const uint8_t *src, int size, uint8_t *dst)
{
#define VC1_UNESCAPE_CHUNK (512)
#define MIN(a,b) ((a)<(b)?(a):(b))
    int dsize = 0, i = 0, chunk_start = i, chunk_limit;
    for (;;)
    {
        if (size - chunk_start <= 3) {
            for (/*i = chunk_start*/; i < size; ++i)
                dst[dsize++] = src[i++];
            return dsize;
        }
        chunk_limit = MIN(chunk_start + VC1_UNESCAPE_CHUNK, size - 3);
        for (/*i = chunk_start*/; i < chunk_limit; ++i)
        {
            uint32_t w = *(uint32_t *)(src + i);
            if ((w &~ 0x03000000) == 0x00030000)
                break;
        }
        if (i < chunk_limit)
        {
            memcpy(dst + dsize, src + chunk_start, i + 2 - chunk_start);
            dsize += i + 2 - chunk_start;
            i += 3;
        }
        else
        {
            memcpy(dst + dsize, src + chunk_start, i - chunk_start);
            dsize += i - chunk_start;
        }
        chunk_start = i;
    }
}

#elif VERSION == 3

int ff_vc1_unescape_buffer_helper_neon(const uint8_t *src, int size, uint8_t *dst);

static int vc1_unescape_buffer(const uint8_t *src, int size, uint8_t *dst)
{
    int dsize = 0;
    while (size >= 4)
    {
        bool found = false;
        while (!found && (((uintptr_t) dst) & 7) && size >= 4)
        {
            found = (*(uint32_t *)src &~ 0x03000000) == 0x00030000;
            if (!found)
            {
                *dst++ = *src++;
                --size;
                ++dsize;
            }
        }
        if (!found)
        {
            int skip = size - ff_vc1_unescape_buffer_helper_neon(src, size, dst);
            dst += skip;
            src += skip;
            size -= skip;
            dsize += skip;
            while (!found && size >= 4)
            {
                found = (*(uint32_t *)src &~ 0x03000000) == 0x00030000;
                if (!found)
                {
                    *dst++ = *src++;
                    --size;
                    ++dsize;
                }
            }
        }
        if (found)
        {
            *dst++ = *src++;
            *dst++ = *src++;
            ++src;
            size -= 3;
            dsize += 2;
        }
    }
    while (size > 0)
    {
        *dst++ = *src++;
        --size;
        ++dsize;
    }
    return dsize;
}

#elif VERSION == 4

#define HAVE_FAST_UNALIGNED 1
#define HAVE_FAST_64BIT 1

#define AV_INPUT_BUFFER_PADDING_SIZE 64

union unaligned_32 { uint32_t l; };
union unaligned_64 { uint64_t l; };

#   define AV_RN(s, p) (((const union unaligned_##s *) (p))->l)
#   define AV_RN32(p) AV_RN(32, p)
#   define AV_RN64(p) AV_RN(64, p)

typedef struct H2645NAL
{
    const uint8_t *data;
    int size;
    int raw_size;
    const uint8_t *raw_data;
    int skipped_bytes;
} H2645NAL;

static H2645NAL nal_store, *nal = &nal_store;

static int vc1_unescape_buffer(const uint8_t *src, int size, uint8_t *dst)
{
    int length = size;
    int small_padding = 0;

    int i, si, di;
//    uint8_t *dst;

    nal->skipped_bytes = 0;
#define STARTCODE_TEST                                                  \
        if (i + 2 < length && src[i + 1] == 0 && src[i + 2] <= 3) {     \
            if (src[i + 2] != 3 && src[i + 2] != 0) {                   \
                /* startcode, so we must be past the end */             \
                length = i;                                             \
            }                                                           \
            break;                                                      \
        }
#if HAVE_FAST_UNALIGNED
#define FIND_FIRST_ZERO                                                 \
        if (i > 0 && !src[i])                                           \
            i--;                                                        \
        while (src[i])                                                  \
            i++
#if HAVE_FAST_64BIT
    for (i = 0; i + 1 < length; i += 9) {
        if (!((~AV_RN64(src + i) &
               (AV_RN64(src + i) - 0x0100010001000101ULL)) &
              0x8000800080008080ULL))
            continue;
        FIND_FIRST_ZERO;
        STARTCODE_TEST;
        i -= 7;
    }
#else
    for (i = 0; i + 1 < length; i += 5) {
        if (!((~AV_RN32(src + i) &
               (AV_RN32(src + i) - 0x01000101U)) &
              0x80008080U))
            continue;
        FIND_FIRST_ZERO;
        STARTCODE_TEST;
        i -= 3;
    }
#endif /* HAVE_FAST_64BIT */
#else
    for (i = 0; i + 1 < length; i += 2) {
        if (src[i])
            continue;
        if (i > 0 && src[i - 1] == 0)
            i--;
        STARTCODE_TEST;
    }
#endif /* HAVE_FAST_UNALIGNED */

    if (i >= length - 1 && small_padding) { // no escaped 0
        nal->data     =
        nal->raw_data = src;
        nal->size     =
        nal->raw_size = length;
        return length;
    } else if (i > length)
        i = length;

//    dst = &rbsp->rbsp_buffer[rbsp->rbsp_buffer_size];

    memcpy(dst, src, i);
    si = di = i;
    while (si + 2 < length) {
        // remove escapes (very rare 1:2^22)
        if (src[si + 2] > 3) {
            dst[di++] = src[si++];
            dst[di++] = src[si++];
        } else if (src[si] == 0 && src[si + 1] == 0 && src[si + 2] != 0) {
            if (src[si + 2] == 3) { // escape
                dst[di++] = 0;
                dst[di++] = 0;
                si       += 3;

//                if (nal->skipped_bytes_pos) {
//                    nal->skipped_bytes++;
//                    if (nal->skipped_bytes_pos_size < nal->skipped_bytes) {
//                        nal->skipped_bytes_pos_size *= 2;
//                        av_assert0(nal->skipped_bytes_pos_size >= nal->skipped_bytes);
//                        av_reallocp_array(&nal->skipped_bytes_pos,
//                                nal->skipped_bytes_pos_size,
//                                sizeof(*nal->skipped_bytes_pos));
//                        if (!nal->skipped_bytes_pos) {
//                            nal->skipped_bytes_pos_size = 0;
//                            return AVERROR(ENOMEM);
//                        }
//                    }
//                    if (nal->skipped_bytes_pos)
//                        nal->skipped_bytes_pos[nal->skipped_bytes-1] = di - 1;
//                }
                continue;
            } else // next start code
                goto nsc;
        }

        dst[di++] = src[si++];
    }
    while (si < length)
        dst[di++] = src[si++];

nsc:
    memset(dst + di, 0, AV_INPUT_BUFFER_PADDING_SIZE);

    nal->data = dst;
    nal->size = di;
    nal->raw_data = src;
    nal->raw_size = si;
//    rbsp->rbsp_buffer_size += si;

    return si;
}

#endif

static int __attribute__((noinline)) call(int (*fn)(const uint8_t *, int, uint8_t *), const uint8_t *src, int size, uint8_t *dst)
{
    return fn(src, size, dst);
}

void rand_buf(void *buf, size_t len)
{
    for (uint16_t *p = buf; len > 0; len -= sizeof *p)
        *p++ = rand();
}

static uint64_t gettime(void)
{
    struct timeval tv;

    gettimeofday (&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char *argv[])
{
    uint64_t t1, t2, t3;
    size_t iterations = 1;
    bool help = false;
    int alignment[2] = { 0, 0 };

    int opt;
    while ((opt = getopt(argc, argv, "hi:a:")) != -1) {
        switch (opt) {
        case 'h': help = true; break;
        case 'i': iterations = atoi(optarg); break;
        case 'a': alignment[0] = strtoul(optarg, &optarg, 10); if (*optarg++ == ',') alignment[1] = strtoul(optarg, NULL, 10); else help = true; break;
        }
    }
    if (help || optind < argc-1) {
        fprintf(stderr, "Syntax: %s [-h] [-i <iterations>] [-a <input alignment>,<output alignment>]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

#define BUFFER_SIZE (2*1024*1024)
    uint8_t *raw_in = malloc(BUFFER_SIZE + 64);
    uint8_t *raw_out = malloc(BUFFER_SIZE + 64);
    uint8_t *in = raw_in + ((alignment[0] - (uintptr_t) raw_in) & 63);
    uint8_t *out = raw_out + ((alignment[1] - (uintptr_t) raw_out) & 63);

    srand(0);
    rand_buf(in, BUFFER_SIZE);
    memset(out, 0xff, BUFFER_SIZE);

    while (iterations--)
    {
        t1 = gettime();
        call(control, in, BUFFER_SIZE, out);
        t2 = gettime();
        call(vc1_unescape_buffer, in, BUFFER_SIZE, out);
        t3 = gettime();
        printf("%6.2f\n", ((double)BUFFER_SIZE) / ((t3 - t2) - (t2 - t1)));
        fflush(stdout);
    }
}
