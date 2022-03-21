#ifdef __ARM_ARCH_ISA_A64

/*
 * VC-1 AArch64 NEON optimisations
 *
 * Copyright (c) 2022 Ben Avison <bavison@riscosopen.org>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libavutil/aarch64/asm.S"

// Copy at most the specified number of bytes from source to destination buffer,
// stopping at a multiple of 32 bytes, none of which are the start of an escape sequence
// On entry:
//   x0 -> source buffer
//   w1 = max number of bytes to copy
//   x2 -> destination buffer, optimally 8-byte aligned
// On exit:
//   w0 = number of bytes not copied
function ff_vc1_unescape_buffer_helper_neon, export=1
        // Offset by 80 to screen out cases that are too short for us to handle,
        // and also make it easy to test for loop termination, or to determine
        // whether we need an odd number of half-iterations of the loop.
        subs    w1, w1, #80
        b.mi    90f

        // Set up useful constants
        movi    v20.4s, #3, lsl #24
        movi    v21.4s, #3, lsl #16

        tst     w1, #32
        b.ne    1f

            ld1     {v0.16b, v1.16b, v2.16b}, [x0], #48
            ext     v25.16b, v0.16b, v1.16b, #1
            ext     v26.16b, v0.16b, v1.16b, #2
            ext     v27.16b, v0.16b, v1.16b, #3
            ext     v29.16b, v1.16b, v2.16b, #1
            ext     v30.16b, v1.16b, v2.16b, #2
            ext     v31.16b, v1.16b, v2.16b, #3
            bic     v24.16b, v0.16b, v20.16b
            bic     v25.16b, v25.16b, v20.16b
            bic     v26.16b, v26.16b, v20.16b
            bic     v27.16b, v27.16b, v20.16b
            bic     v28.16b, v1.16b, v20.16b
            bic     v29.16b, v29.16b, v20.16b
            bic     v30.16b, v30.16b, v20.16b
            bic     v31.16b, v31.16b, v20.16b
            eor     v24.16b, v24.16b, v21.16b
            eor     v25.16b, v25.16b, v21.16b
            eor     v26.16b, v26.16b, v21.16b
            eor     v27.16b, v27.16b, v21.16b
            eor     v28.16b, v28.16b, v21.16b
            eor     v29.16b, v29.16b, v21.16b
            eor     v30.16b, v30.16b, v21.16b
            eor     v31.16b, v31.16b, v21.16b
            cmeq    v24.4s, v24.4s, #0
            cmeq    v25.4s, v25.4s, #0
            cmeq    v26.4s, v26.4s, #0
            cmeq    v27.4s, v27.4s, #0
            add     w1, w1, #32
            b       3f

1:        ld1     {v3.16b, v4.16b, v5.16b}, [x0], #48
          ext     v25.16b, v3.16b, v4.16b, #1
          ext     v26.16b, v3.16b, v4.16b, #2
          ext     v27.16b, v3.16b, v4.16b, #3
          ext     v29.16b, v4.16b, v5.16b, #1
          ext     v30.16b, v4.16b, v5.16b, #2
          ext     v31.16b, v4.16b, v5.16b, #3
          bic     v24.16b, v3.16b, v20.16b
          bic     v25.16b, v25.16b, v20.16b
          bic     v26.16b, v26.16b, v20.16b
          bic     v27.16b, v27.16b, v20.16b
          bic     v28.16b, v4.16b, v20.16b
          bic     v29.16b, v29.16b, v20.16b
          bic     v30.16b, v30.16b, v20.16b
          bic     v31.16b, v31.16b, v20.16b
          eor     v24.16b, v24.16b, v21.16b
          eor     v25.16b, v25.16b, v21.16b
          eor     v26.16b, v26.16b, v21.16b
          eor     v27.16b, v27.16b, v21.16b
          eor     v28.16b, v28.16b, v21.16b
          eor     v29.16b, v29.16b, v21.16b
          eor     v30.16b, v30.16b, v21.16b
          eor     v31.16b, v31.16b, v21.16b
          cmeq    v24.4s, v24.4s, #0
          cmeq    v25.4s, v25.4s, #0
          cmeq    v26.4s, v26.4s, #0
          cmeq    v27.4s, v27.4s, #0
          // Drop through...
2:          mov     v0.16b, v5.16b
            ld1     {v1.16b, v2.16b}, [x0], #32
          cmeq    v28.4s, v28.4s, #0
          cmeq    v29.4s, v29.4s, #0
          cmeq    v30.4s, v30.4s, #0
          cmeq    v31.4s, v31.4s, #0
          orr     v24.16b, v24.16b, v25.16b
          orr     v26.16b, v26.16b, v27.16b
          orr     v28.16b, v28.16b, v29.16b
          orr     v30.16b, v30.16b, v31.16b
            ext     v25.16b, v0.16b, v1.16b, #1
          orr     v22.16b, v24.16b, v26.16b
            ext     v26.16b, v0.16b, v1.16b, #2
            ext     v27.16b, v0.16b, v1.16b, #3
            ext     v29.16b, v1.16b, v2.16b, #1
          orr     v23.16b, v28.16b, v30.16b
            ext     v30.16b, v1.16b, v2.16b, #2
            ext     v31.16b, v1.16b, v2.16b, #3
            bic     v24.16b, v0.16b, v20.16b
            bic     v25.16b, v25.16b, v20.16b
            bic     v26.16b, v26.16b, v20.16b
          orr     v22.16b, v22.16b, v23.16b
            bic     v27.16b, v27.16b, v20.16b
            bic     v28.16b, v1.16b, v20.16b
            bic     v29.16b, v29.16b, v20.16b
            bic     v30.16b, v30.16b, v20.16b
            bic     v31.16b, v31.16b, v20.16b
          addv    s22, v22.4s
            eor     v24.16b, v24.16b, v21.16b
            eor     v25.16b, v25.16b, v21.16b
            eor     v26.16b, v26.16b, v21.16b
            eor     v27.16b, v27.16b, v21.16b
            eor     v28.16b, v28.16b, v21.16b
          mov     w3, v22.s[0]
            eor     v29.16b, v29.16b, v21.16b
            eor     v30.16b, v30.16b, v21.16b
            eor     v31.16b, v31.16b, v21.16b
            cmeq    v24.4s, v24.4s, #0
            cmeq    v25.4s, v25.4s, #0
            cmeq    v26.4s, v26.4s, #0
            cmeq    v27.4s, v27.4s, #0
          cbnz    w3, 90f
          st1     {v3.16b, v4.16b}, [x2], #32
3:            mov     v3.16b, v2.16b
              ld1     {v4.16b, v5.16b}, [x0], #32
            cmeq    v28.4s, v28.4s, #0
            cmeq    v29.4s, v29.4s, #0
            cmeq    v30.4s, v30.4s, #0
            cmeq    v31.4s, v31.4s, #0
            orr     v24.16b, v24.16b, v25.16b
            orr     v26.16b, v26.16b, v27.16b
            orr     v28.16b, v28.16b, v29.16b
            orr     v30.16b, v30.16b, v31.16b
              ext     v25.16b, v3.16b, v4.16b, #1
            orr     v22.16b, v24.16b, v26.16b
              ext     v26.16b, v3.16b, v4.16b, #2
              ext     v27.16b, v3.16b, v4.16b, #3
              ext     v29.16b, v4.16b, v5.16b, #1
            orr     v23.16b, v28.16b, v30.16b
              ext     v30.16b, v4.16b, v5.16b, #2
              ext     v31.16b, v4.16b, v5.16b, #3
              bic     v24.16b, v3.16b, v20.16b
              bic     v25.16b, v25.16b, v20.16b
              bic     v26.16b, v26.16b, v20.16b
            orr     v22.16b, v22.16b, v23.16b
              bic     v27.16b, v27.16b, v20.16b
              bic     v28.16b, v4.16b, v20.16b
              bic     v29.16b, v29.16b, v20.16b
              bic     v30.16b, v30.16b, v20.16b
              bic     v31.16b, v31.16b, v20.16b
            addv    s22, v22.4s
              eor     v24.16b, v24.16b, v21.16b
              eor     v25.16b, v25.16b, v21.16b
              eor     v26.16b, v26.16b, v21.16b
              eor     v27.16b, v27.16b, v21.16b
              eor     v28.16b, v28.16b, v21.16b
            mov     w3, v22.s[0]
              eor     v29.16b, v29.16b, v21.16b
              eor     v30.16b, v30.16b, v21.16b
              eor     v31.16b, v31.16b, v21.16b
              cmeq    v24.4s, v24.4s, #0
              cmeq    v25.4s, v25.4s, #0
              cmeq    v26.4s, v26.4s, #0
              cmeq    v27.4s, v27.4s, #0
            cbnz    w3, 91f
            st1     {v0.16b, v1.16b}, [x2], #32
        subs    w1, w1, #64
        b.pl    2b

90:     add     w0, w1, #80
        ret

91:     sub     w1, w1, #32
        b       90b
endfunc


#else // 32-bit


#include "libavutil/arm/asm.S"

@ Copy at most the specified number of bytes from source to destination buffer,
@ stopping at a multiple of 16 bytes, none of which are the start of an escape sequence
@ On entry:
@   r0 -> source buffer
@   r1 = max number of bytes to copy
@   r2 -> destination buffer, optimally 8-byte aligned
@ On exit:
@   r0 = number of bytes not copied
function ff_vc1_unescape_buffer_helper_neon, export=1
        @ Offset by 48 to screen out cases that are too short for us to handle,
        @ and also make it easy to test for loop termination, or to determine
        @ whether we need an odd number of half-iterations of the loop.
        subs    r1, r1, #48
        bmi     90f

        @ Set up useful constants
        vmov.i32        q0, #0x3000000
        vmov.i32        q1, #0x30000

        tst             r1, #16
        bne             1f

          vld1.8          {q8, q9}, [r0]!
          vbic            q12, q8, q0
          vext.8          q13, q8, q9, #1
          vext.8          q14, q8, q9, #2
          vext.8          q15, q8, q9, #3
          veor            q12, q12, q1
          vbic            q13, q13, q0
          vbic            q14, q14, q0
          vbic            q15, q15, q0
          vceq.i32        q12, q12, #0
          veor            q13, q13, q1
          veor            q14, q14, q1
          veor            q15, q15, q1
          vceq.i32        q13, q13, #0
          vceq.i32        q14, q14, #0
          vceq.i32        q15, q15, #0
          add             r1, r1, #16
          b               3f

1:      vld1.8          {q10, q11}, [r0]!
        vbic            q12, q10, q0
        vext.8          q13, q10, q11, #1
        vext.8          q14, q10, q11, #2
        vext.8          q15, q10, q11, #3
        veor            q12, q12, q1
        vbic            q13, q13, q0
        vbic            q14, q14, q0
        vbic            q15, q15, q0
        vceq.i32        q12, q12, #0
        veor            q13, q13, q1
        veor            q14, q14, q1
        veor            q15, q15, q1
        vceq.i32        q13, q13, #0
        vceq.i32        q14, q14, #0
        vceq.i32        q15, q15, #0
        @ Drop through...
2:        vmov            q8, q11
          vld1.8          {q9}, [r0]!
        vorr            q13, q12, q13
        vorr            q15, q14, q15
          vbic            q12, q8, q0
        vorr            q3, q13, q15
          vext.8          q13, q8, q9, #1
          vext.8          q14, q8, q9, #2
          vext.8          q15, q8, q9, #3
          veor            q12, q12, q1
        vorr            d6, d6, d7
          vbic            q13, q13, q0
          vbic            q14, q14, q0
          vbic            q15, q15, q0
          vceq.i32        q12, q12, #0
        vmov            r3, r12, d6
          veor            q13, q13, q1
          veor            q14, q14, q1
          veor            q15, q15, q1
          vceq.i32        q13, q13, #0
          vceq.i32        q14, q14, #0
          vceq.i32        q15, q15, #0
        orrs            r3, r3, r12
        bne             90f
        vst1.64         {q10}, [r2]!
3:          vmov            q10, q9
            vld1.8          {q11}, [r0]!
          vorr            q13, q12, q13
          vorr            q15, q14, q15
            vbic            q12, q10, q0
          vorr            q3, q13, q15
            vext.8          q13, q10, q11, #1
            vext.8          q14, q10, q11, #2
            vext.8          q15, q10, q11, #3
            veor            q12, q12, q1
          vorr            d6, d6, d7
            vbic            q13, q13, q0
            vbic            q14, q14, q0
            vbic            q15, q15, q0
            vceq.i32        q12, q12, #0
          vmov            r3, r12, d6
            veor            q13, q13, q1
            veor            q14, q14, q1
            veor            q15, q15, q1
            vceq.i32        q13, q13, #0
            vceq.i32        q14, q14, #0
            vceq.i32        q15, q15, #0
          orrs            r3, r3, r12
          bne             91f
          vst1.64         {q8}, [r2]!
        subs            r1, r1, #32
        bpl             2b

90:     add             r0, r1, #48
        bx              lr

91:     sub             r1, r1, #16
        b               90b
endfunc


#endif // 64-bit
