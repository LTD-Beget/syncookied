# 1 "sha1_ssse3_asm.S"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "sha1_ssse3_asm.S"
# 31 "sha1_ssse3_asm.S"
# 1 "./linux/linkage.h" 1



# 1 "./linux/compiler.h" 1
# 5 "./linux/linkage.h" 2
# 1 "./linux/stringify.h" 1
# 6 "./linux/linkage.h" 2
# 1 "./linux/export.h" 1
# 7 "./linux/linkage.h" 2
# 32 "sha1_ssse3_asm.S" 2
# 73 "sha1_ssse3_asm.S"
.macro SHA1_VECTOR_ASM name
 .globl \name ; .align 4,0x90 ; \name:

 push %rbx
 push %rbp
 push %r12

 mov %rsp, %r12
 sub $64, %rsp # allocate workspace
 and $~15, %rsp # align stack

 mov %rdi, %r9
 mov %rsi, %r10

 shl $6, %rdx # multiply by 64
 add %rsi, %rdx
 mov %rdx, %r11

 lea K_XMM_AR(%rip), %r8
 xmm_mov BSWAP_SHUFB_CTL(%rip), %xmm10

 SHA1_PIPELINED_MAIN_BODY

 # cleanup workspace
 mov $8, %ecx
 mov %rsp, %rdi
 xor %rax, %rax
 rep stosq

 mov %r12, %rsp # deallocate workspace

 pop %r12
 pop %rbp
 pop %rbx
 ret

 .type \name, @function ; .size \name, .-\name
.endm




.macro SHA1_PIPELINED_MAIN_BODY
 INIT_REGALLOC

 mov (%r9), A
 mov 4(%r9), B
 mov 8(%r9), C
 mov 12(%r9), D
 mov 16(%r9), E

  .set i, 0
  .rept 16
 W_PRECALC i
    .set i, (i+1)
  .endr

.align 4
1:
 RR F1,A,B,C,D,E,0
 RR F1,D,E,A,B,C,2
 RR F1,B,C,D,E,A,4
 RR F1,E,A,B,C,D,6
 RR F1,C,D,E,A,B,8

 RR F1,A,B,C,D,E,10
 RR F1,D,E,A,B,C,12
 RR F1,B,C,D,E,A,14
 RR F1,E,A,B,C,D,16
 RR F1,C,D,E,A,B,18

 RR F2,A,B,C,D,E,20
 RR F2,D,E,A,B,C,22
 RR F2,B,C,D,E,A,24
 RR F2,E,A,B,C,D,26
 RR F2,C,D,E,A,B,28

 RR F2,A,B,C,D,E,30
 RR F2,D,E,A,B,C,32
 RR F2,B,C,D,E,A,34
 RR F2,E,A,B,C,D,36
 RR F2,C,D,E,A,B,38

 RR F3,A,B,C,D,E,40
 RR F3,D,E,A,B,C,42
 RR F3,B,C,D,E,A,44
 RR F3,E,A,B,C,D,46
 RR F3,C,D,E,A,B,48

 RR F3,A,B,C,D,E,50
 RR F3,D,E,A,B,C,52
 RR F3,B,C,D,E,A,54
 RR F3,E,A,B,C,D,56
 RR F3,C,D,E,A,B,58

 add $64, %r10 # move to the next 64-byte block
 cmp %r11, %r10 # if the current is the last one use
 cmovae %r8, %r10 # dummy source to avoid buffer overrun

 RR F4,A,B,C,D,E,60
 RR F4,D,E,A,B,C,62
 RR F4,B,C,D,E,A,64
 RR F4,E,A,B,C,D,66
 RR F4,C,D,E,A,B,68

 RR F4,A,B,C,D,E,70
 RR F4,D,E,A,B,C,72
 RR F4,B,C,D,E,A,74
 RR F4,E,A,B,C,D,76
 RR F4,C,D,E,A,B,78

 UPDATE_HASH (%r9), A
 UPDATE_HASH 4(%r9), B
 UPDATE_HASH 8(%r9), C
 UPDATE_HASH 12(%r9), D
 UPDATE_HASH 16(%r9), E

 RESTORE_RENAMED_REGS
 cmp %r8, %r10 # %r8 means, we reached the end
 jne 1b
.endm

.macro INIT_REGALLOC
  .set A, %ecx
  .set B, %esi
  .set C, %edi
  .set D, %ebp
  .set E, %edx
  .set T1, %eax
  .set T2, %ebx
.endm

.macro RESTORE_RENAMED_REGS
 # order is important (%edi is where it should be)
 mov B, %esi
 mov D, %ebp
 mov A, %ecx
 mov E, %edx
.endm

.macro SWAP_REG_NAMES a, b
  .set _T, \a
  .set \a, \b
  .set \b, _T
.endm

.macro F1 b, c, d
 mov \c, T1
 SWAP_REG_NAMES \c, T1
 xor \d, T1
 and \b, T1
 xor \d, T1
.endm

.macro F2 b, c, d
 mov \d, T1
 SWAP_REG_NAMES \d, T1
 xor \c, T1
 xor \b, T1
.endm

.macro F3 b, c ,d
 mov \c, T1
 SWAP_REG_NAMES \c, T1
 mov \b, T2
 or \b, T1
 and \c, T2
 and \d, T1
 or T2, T1
.endm

.macro F4 b, c, d
 F2 \b, \c, \d
.endm

.macro UPDATE_HASH hash, val
 add \hash, \val
 mov \val, \hash
.endm
# 264 "sha1_ssse3_asm.S"
.macro RR F, a, b, c, d, e, round
 add (((\round) & 15) * 4)(%rsp), \e
 \F \b, \c, \d # t1 = F(b, c, d);
 W_PRECALC (\round + 16)
 rol $30, \b
 add T1, \e
 add (((\round + 1) & 15) * 4)(%rsp), \d

 \F \a, \b, \c
 W_PRECALC (\round + 16 + 1)
 rol $5, \a
 add \a, \e
 add T1, \d
 ror $7, \a # (a <<r 5) >>r 7) => a <<r 30)

 mov \e, T1
 SWAP_REG_NAMES \e, T1

 rol $5, T1
 add T1, \d

 # write: \a, \b
 # rotate: \a<=\d, \b<=\e, \c<=\a, \d<=\b, \e<=\c
.endm

.macro W_PRECALC r
  .set i, \r

  .if (i < 20)
    .set K_XMM, 0
  .elseif (i < 40)
    .set K_XMM, 16
  .elseif (i < 60)
    .set K_XMM, 32
  .elseif (i < 80)
    .set K_XMM, 48
  .endif

  .if ((i < 16) || ((i >= 80) && (i < (80 + 16))))
    .set i, ((\r) % 80) # pre-compute for the next iteration
    .if (i == 0)
 W_PRECALC_RESET
    .endif
 W_PRECALC_00_15
  .elseif (i<32)
 W_PRECALC_16_31
  .elseif (i < 80)
 W_PRECALC_32_79
  .endif
.endm

.macro W_PRECALC_RESET
  .set W, %xmm1
  .set W_minus_04, %xmm2
  .set W_minus_08, %xmm3
  .set W_minus_12, %xmm4
  .set W_minus_16, %xmm5
  .set W_minus_20, %xmm6
  .set W_minus_24, %xmm7
  .set W_minus_28, %xmm8
  .set W_minus_32, W
.endm

.macro W_PRECALC_ROTATE
  .set W_minus_32, W_minus_28
  .set W_minus_28, W_minus_24
  .set W_minus_24, W_minus_20
  .set W_minus_20, W_minus_16
  .set W_minus_16, W_minus_12
  .set W_minus_12, W_minus_08
  .set W_minus_08, W_minus_04
  .set W_minus_04, W
  .set W, W_minus_32
.endm

.macro W_PRECALC_SSSE3

.macro W_PRECALC_00_15
 W_PRECALC_00_15_SSSE3
.endm
.macro W_PRECALC_16_31
 W_PRECALC_16_31_SSSE3
.endm
.macro W_PRECALC_32_79
 W_PRECALC_32_79_SSSE3
.endm


.macro W_PRECALC_00_15_SSSE3
  .if ((i & 3) == 0)
 movdqu (i*4)(%r10), %xmm0
  .elseif ((i & 3) == 1)
 pshufb %xmm10, %xmm0
 movdqa %xmm0, W
  .elseif ((i & 3) == 2)
 paddd (%r8), %xmm0
  .elseif ((i & 3) == 3)
 movdqa %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm
# 375 "sha1_ssse3_asm.S"
.macro W_PRECALC_16_31_SSSE3
  # blended scheduling of vector and scalar instruction streams, one 4-wide
  # vector iteration / 4 scalar rounds
  .if ((i & 3) == 0)
 movdqa W_minus_12, W
 palignr $8, W_minus_16, W # w[i-14]
 movdqa W_minus_04, %xmm0
 psrldq $4, %xmm0 # w[i-3]
 pxor W_minus_08, W
  .elseif ((i & 3) == 1)
 pxor W_minus_16, %xmm0
 pxor %xmm0, W
 movdqa W, %xmm9
 movdqa W, %xmm0
 pslldq $12, %xmm9
  .elseif ((i & 3) == 2)
 psrld $31, W
 pslld $1, %xmm0
 por W, %xmm0
 movdqa %xmm9, W
 psrld $30, %xmm9
 pslld $2, W
  .elseif ((i & 3) == 3)
 pxor W, %xmm0
 pxor %xmm9, %xmm0
 movdqa %xmm0, W
 paddd K_XMM(%r8), %xmm0
 movdqa %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm







.macro W_PRECALC_32_79_SSSE3
  .if ((i & 3) == 0)
 movdqa W_minus_04, %xmm0
 pxor W_minus_28, W # W is W_minus_32 before xor
 palignr $8, W_minus_08, %xmm0
  .elseif ((i & 3) == 1)
 pxor W_minus_16, W
 pxor %xmm0, W
 movdqa W, %xmm0
  .elseif ((i & 3) == 2)
 psrld $30, W
 pslld $2, %xmm0
 por W, %xmm0
  .elseif ((i & 3) == 3)
 movdqa %xmm0, W
 paddd K_XMM(%r8), %xmm0
 movdqa %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm

.endm







.section .rodata
.align 16

K_XMM_AR:
 .long 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
 .long 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
 .long 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
 .long 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6

BSWAP_SHUFB_CTL:
 .long 0x00010203
 .long 0x04050607
 .long 0x08090a0b
 .long 0x0c0d0e0f


.section .text

W_PRECALC_SSSE3
.macro xmm_mov a, b
 movdqu \a,\b
.endm





SHA1_VECTOR_ASM sha1_transform_ssse3



.macro W_PRECALC_AVX

.purgem W_PRECALC_00_15
.macro W_PRECALC_00_15
    W_PRECALC_00_15_AVX
.endm
.purgem W_PRECALC_16_31
.macro W_PRECALC_16_31
    W_PRECALC_16_31_AVX
.endm
.purgem W_PRECALC_32_79
.macro W_PRECALC_32_79
    W_PRECALC_32_79_AVX
.endm

.macro W_PRECALC_00_15_AVX
  .if ((i & 3) == 0)
 vmovdqu (i*4)(%r10), %xmm0
  .elseif ((i & 3) == 1)
 vpshufb %xmm10, %xmm0, W
  .elseif ((i & 3) == 2)
 vpaddd (%r8), W, %xmm0
  .elseif ((i & 3) == 3)
 vmovdqa %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm

.macro W_PRECALC_16_31_AVX
  .if ((i & 3) == 0)
 vpalignr $8, W_minus_16, W_minus_12, W # w[i-14]
 vpsrldq $4, W_minus_04, %xmm0 # w[i-3]
 vpxor W_minus_08, W, W
 vpxor W_minus_16, %xmm0, %xmm0
  .elseif ((i & 3) == 1)
 vpxor %xmm0, W, W
 vpslldq $12, W, %xmm9
 vpslld $1, W, %xmm0
  .elseif ((i & 3) == 2)
 vpsrld $31, W, W
 vpor W, %xmm0, %xmm0
 vpslld $2, %xmm9, W
 vpsrld $30, %xmm9, %xmm9
  .elseif ((i & 3) == 3)
 vpxor W, %xmm0, %xmm0
 vpxor %xmm9, %xmm0, W
 vpaddd K_XMM(%r8), W, %xmm0
 vmovdqu %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm

.macro W_PRECALC_32_79_AVX
  .if ((i & 3) == 0)
 vpalignr $8, W_minus_08, W_minus_04, %xmm0
 vpxor W_minus_28, W, W # W is W_minus_32 before xor
  .elseif ((i & 3) == 1)
 vpxor W_minus_16, %xmm0, %xmm0
 vpxor %xmm0, W, W
  .elseif ((i & 3) == 2)
 vpslld $2, W, %xmm0
 vpsrld $30, W, W
 vpor W, %xmm0, W
  .elseif ((i & 3) == 3)
 vpaddd K_XMM(%r8), W, %xmm0
 vmovdqu %xmm0, (((i&~3) & 15) * 4)(%rsp)
 W_PRECALC_ROTATE
  .endif
.endm

.endm

W_PRECALC_AVX
.purgem xmm_mov
.macro xmm_mov a, b
 vmovdqu \a,\b
.endm






SHA1_VECTOR_ASM sha1_transform_avx
