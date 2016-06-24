/*
 * SHA1 routine optimized to do word accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 *
 * This was based on the git SHA1 implementation.
 */
# 1 "sha1.c"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "sha1.c"
# 12 "sha1.c"
# 1 "./linux/be_byteshift.h" 1







# 1 "/usr/include/linux/types.h" 1 3 4



# 1 "/usr/include/x86_64-linux-gnu/asm/types.h" 1 3 4



# 1 "/usr/include/asm-generic/types.h" 1 3 4






# 1 "/usr/include/asm-generic/int-ll64.h" 1 3 4
# 11 "/usr/include/asm-generic/int-ll64.h" 3 4
# 1 "/usr/include/x86_64-linux-gnu/asm/bitsperlong.h" 1 3 4
# 10 "/usr/include/x86_64-linux-gnu/asm/bitsperlong.h" 3 4
# 1 "/usr/include/asm-generic/bitsperlong.h" 1 3 4
# 11 "/usr/include/x86_64-linux-gnu/asm/bitsperlong.h" 2 3 4
# 12 "/usr/include/asm-generic/int-ll64.h" 2 3 4







typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;


__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
# 8 "/usr/include/asm-generic/types.h" 2 3 4
# 5 "/usr/include/x86_64-linux-gnu/asm/types.h" 2 3 4
# 5 "/usr/include/linux/types.h" 2 3 4



# 1 "/usr/include/linux/posix_types.h" 1 3 4



# 1 "/usr/include/linux/stddef.h" 1 3 4
# 5 "/usr/include/linux/posix_types.h" 2 3 4
# 24 "/usr/include/linux/posix_types.h" 3 4
typedef struct {
 unsigned long fds_bits[1024 / (8 * sizeof(long))];
} __kernel_fd_set;


typedef void (*__kernel_sighandler_t)(int);


typedef int __kernel_key_t;
typedef int __kernel_mqd_t;

# 1 "/usr/include/x86_64-linux-gnu/asm/posix_types.h" 1 3 4





# 1 "/usr/include/x86_64-linux-gnu/asm/posix_types_64.h" 1 3 4
# 10 "/usr/include/x86_64-linux-gnu/asm/posix_types_64.h" 3 4
typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;


typedef unsigned long __kernel_old_dev_t;


# 1 "/usr/include/asm-generic/posix_types.h" 1 3 4
# 14 "/usr/include/asm-generic/posix_types.h" 3 4
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;



typedef __kernel_ulong_t __kernel_ino_t;



typedef unsigned int __kernel_mode_t;



typedef int __kernel_pid_t;



typedef int __kernel_ipc_pid_t;



typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;



typedef __kernel_long_t __kernel_suseconds_t;



typedef int __kernel_daddr_t;



typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;
# 71 "/usr/include/asm-generic/posix_types.h" 3 4
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;




typedef struct {
 int val[2];
} __kernel_fsid_t;





typedef __kernel_long_t __kernel_off_t;
typedef long long __kernel_loff_t;
typedef __kernel_long_t __kernel_time_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef char * __kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
# 18 "/usr/include/x86_64-linux-gnu/asm/posix_types_64.h" 2 3 4
# 7 "/usr/include/x86_64-linux-gnu/asm/posix_types.h" 2 3 4
# 36 "/usr/include/linux/posix_types.h" 2 3 4
# 9 "/usr/include/linux/types.h" 2 3 4
# 27 "/usr/include/linux/types.h" 3 4
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;
# 9 "./linux/be_byteshift.h" 2

static inline __u16 __get_unaligned_be16(const __u8 *p)
{
    return p[0] << 8 | p[1];
}

static inline __u32 __get_unaligned_be32(const __u8 *p)
{
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline __u64 __get_unaligned_be64(const __u8 *p)
{
    return (__u64)__get_unaligned_be32(p) << 32 |
           __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(__u16 val, __u8 *p)
{
    *p++ = val >> 8;
    *p++ = val;
}

static inline void __put_unaligned_be32(__u32 val, __u8 *p)
{
    __put_unaligned_be16(val >> 16, p);
    __put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(__u64 val, __u8 *p)
{
    __put_unaligned_be32(val >> 32, p);
    __put_unaligned_be32(val, p + 4);
}

static inline __u16 get_unaligned_be16(const void *p)
{
    return __get_unaligned_be16((const __u8 *)p);
}

static inline __u32 get_unaligned_be32(const void *p)
{
    return __get_unaligned_be32((const __u8 *)p);
}

static inline __u64 get_unaligned_be64(const void *p)
{
    return __get_unaligned_be64((const __u8 *)p);
}

static inline void put_unaligned_be16(__u16 val, void *p)
{
    __put_unaligned_be16(val, (__u8 *) p);
}

static inline void put_unaligned_be32(__u32 val, void *p)
{
    __put_unaligned_be32(val, (__u8 *) p);
}

static inline void put_unaligned_be64(__u64 val, void *p)
{
    __put_unaligned_be64(val, (__u8 *) p);
}
# 13 "sha1.c" 2
# 1 "./linux/cryptohash.h" 1
# 14 "./linux/cryptohash.h"
void sha_init(__u32 *buf);
void sha_transform(__u32 *digest, const char *data, __u32 *W);
# 14 "sha1.c" 2






static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}






static inline __u32 ror32(__u32 word, unsigned int shift)
{
    return (word >> shift) | (word << (32 - shift));
}
# 102 "sha1.c"
void sha_transform(__u32 *digest, const char *data, __u32 *array)
{
    __u32 A, B, C, D, E;

    A = digest[0];
    B = digest[1];
    C = digest[2];
    D = digest[3];
    E = digest[4];


    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 0); (*(volatile __u32 *)&(array[(0)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((((C^D)&B)^D)) + (0x5a827999); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 1); (*(volatile __u32 *)&(array[(1)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((((B^C)&A)^C)) + (0x5a827999); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 2); (*(volatile __u32 *)&(array[(2)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((((A^B)&E)^B)) + (0x5a827999); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 3); (*(volatile __u32 *)&(array[(3)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((((E^A)&D)^A)) + (0x5a827999); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 4); (*(volatile __u32 *)&(array[(4)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((((D^E)&C)^E)) + (0x5a827999); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 5); (*(volatile __u32 *)&(array[(5)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((((C^D)&B)^D)) + (0x5a827999); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 6); (*(volatile __u32 *)&(array[(6)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((((B^C)&A)^C)) + (0x5a827999); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 7); (*(volatile __u32 *)&(array[(7)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((((A^B)&E)^B)) + (0x5a827999); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 8); (*(volatile __u32 *)&(array[(8)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((((E^A)&D)^A)) + (0x5a827999); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 9); (*(volatile __u32 *)&(array[(9)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((((D^E)&C)^E)) + (0x5a827999); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 10); (*(volatile __u32 *)&(array[(10)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((((C^D)&B)^D)) + (0x5a827999); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 11); (*(volatile __u32 *)&(array[(11)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((((B^C)&A)^C)) + (0x5a827999); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 12); (*(volatile __u32 *)&(array[(12)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((((A^B)&E)^B)) + (0x5a827999); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 13); (*(volatile __u32 *)&(array[(13)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((((E^A)&D)^A)) + (0x5a827999); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 14); (*(volatile __u32 *)&(array[(14)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((((D^E)&C)^E)) + (0x5a827999); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = get_unaligned_be32((__u32 *)data + 15); (*(volatile __u32 *)&(array[(15)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((((C^D)&B)^D)) + (0x5a827999); B = ror32(B, 2); } while (0);


    do { __u32 TEMP = rol32((array[(16 +13)&15]) ^ (array[(16 +8)&15]) ^ (array[(16 +2)&15]) ^ (array[(16)&15]), 1); (*(volatile __u32 *)&(array[(16)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((((B^C)&A)^C)) + (0x5a827999); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(17 +13)&15]) ^ (array[(17 +8)&15]) ^ (array[(17 +2)&15]) ^ (array[(17)&15]), 1); (*(volatile __u32 *)&(array[(17)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((((A^B)&E)^B)) + (0x5a827999); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(18 +13)&15]) ^ (array[(18 +8)&15]) ^ (array[(18 +2)&15]) ^ (array[(18)&15]), 1); (*(volatile __u32 *)&(array[(18)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((((E^A)&D)^A)) + (0x5a827999); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(19 +13)&15]) ^ (array[(19 +8)&15]) ^ (array[(19 +2)&15]) ^ (array[(19)&15]), 1); (*(volatile __u32 *)&(array[(19)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((((D^E)&C)^E)) + (0x5a827999); C = ror32(C, 2); } while (0);


    do { __u32 TEMP = rol32((array[(20 +13)&15]) ^ (array[(20 +8)&15]) ^ (array[(20 +2)&15]) ^ (array[(20)&15]), 1); (*(volatile __u32 *)&(array[(20)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0x6ed9eba1); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(21 +13)&15]) ^ (array[(21 +8)&15]) ^ (array[(21 +2)&15]) ^ (array[(21)&15]), 1); (*(volatile __u32 *)&(array[(21)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0x6ed9eba1); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(22 +13)&15]) ^ (array[(22 +8)&15]) ^ (array[(22 +2)&15]) ^ (array[(22)&15]), 1); (*(volatile __u32 *)&(array[(22)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0x6ed9eba1); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(23 +13)&15]) ^ (array[(23 +8)&15]) ^ (array[(23 +2)&15]) ^ (array[(23)&15]), 1); (*(volatile __u32 *)&(array[(23)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0x6ed9eba1); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(24 +13)&15]) ^ (array[(24 +8)&15]) ^ (array[(24 +2)&15]) ^ (array[(24)&15]), 1); (*(volatile __u32 *)&(array[(24)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0x6ed9eba1); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(25 +13)&15]) ^ (array[(25 +8)&15]) ^ (array[(25 +2)&15]) ^ (array[(25)&15]), 1); (*(volatile __u32 *)&(array[(25)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0x6ed9eba1); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(26 +13)&15]) ^ (array[(26 +8)&15]) ^ (array[(26 +2)&15]) ^ (array[(26)&15]), 1); (*(volatile __u32 *)&(array[(26)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0x6ed9eba1); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(27 +13)&15]) ^ (array[(27 +8)&15]) ^ (array[(27 +2)&15]) ^ (array[(27)&15]), 1); (*(volatile __u32 *)&(array[(27)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0x6ed9eba1); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(28 +13)&15]) ^ (array[(28 +8)&15]) ^ (array[(28 +2)&15]) ^ (array[(28)&15]), 1); (*(volatile __u32 *)&(array[(28)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0x6ed9eba1); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(29 +13)&15]) ^ (array[(29 +8)&15]) ^ (array[(29 +2)&15]) ^ (array[(29)&15]), 1); (*(volatile __u32 *)&(array[(29)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0x6ed9eba1); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(30 +13)&15]) ^ (array[(30 +8)&15]) ^ (array[(30 +2)&15]) ^ (array[(30)&15]), 1); (*(volatile __u32 *)&(array[(30)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0x6ed9eba1); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(31 +13)&15]) ^ (array[(31 +8)&15]) ^ (array[(31 +2)&15]) ^ (array[(31)&15]), 1); (*(volatile __u32 *)&(array[(31)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0x6ed9eba1); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(32 +13)&15]) ^ (array[(32 +8)&15]) ^ (array[(32 +2)&15]) ^ (array[(32)&15]), 1); (*(volatile __u32 *)&(array[(32)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0x6ed9eba1); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(33 +13)&15]) ^ (array[(33 +8)&15]) ^ (array[(33 +2)&15]) ^ (array[(33)&15]), 1); (*(volatile __u32 *)&(array[(33)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0x6ed9eba1); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(34 +13)&15]) ^ (array[(34 +8)&15]) ^ (array[(34 +2)&15]) ^ (array[(34)&15]), 1); (*(volatile __u32 *)&(array[(34)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0x6ed9eba1); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(35 +13)&15]) ^ (array[(35 +8)&15]) ^ (array[(35 +2)&15]) ^ (array[(35)&15]), 1); (*(volatile __u32 *)&(array[(35)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0x6ed9eba1); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(36 +13)&15]) ^ (array[(36 +8)&15]) ^ (array[(36 +2)&15]) ^ (array[(36)&15]), 1); (*(volatile __u32 *)&(array[(36)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0x6ed9eba1); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(37 +13)&15]) ^ (array[(37 +8)&15]) ^ (array[(37 +2)&15]) ^ (array[(37)&15]), 1); (*(volatile __u32 *)&(array[(37)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0x6ed9eba1); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(38 +13)&15]) ^ (array[(38 +8)&15]) ^ (array[(38 +2)&15]) ^ (array[(38)&15]), 1); (*(volatile __u32 *)&(array[(38)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0x6ed9eba1); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(39 +13)&15]) ^ (array[(39 +8)&15]) ^ (array[(39 +2)&15]) ^ (array[(39)&15]), 1); (*(volatile __u32 *)&(array[(39)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0x6ed9eba1); C = ror32(C, 2); } while (0);


    do { __u32 TEMP = rol32((array[(40 +13)&15]) ^ (array[(40 +8)&15]) ^ (array[(40 +2)&15]) ^ (array[(40)&15]), 1); (*(volatile __u32 *)&(array[(40)&15]) = (TEMP)); E += TEMP + rol32(A,5) + (((B&C)+(D&(B^C)))) + (0x8f1bbcdc); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(41 +13)&15]) ^ (array[(41 +8)&15]) ^ (array[(41 +2)&15]) ^ (array[(41)&15]), 1); (*(volatile __u32 *)&(array[(41)&15]) = (TEMP)); D += TEMP + rol32(E,5) + (((A&B)+(C&(A^B)))) + (0x8f1bbcdc); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(42 +13)&15]) ^ (array[(42 +8)&15]) ^ (array[(42 +2)&15]) ^ (array[(42)&15]), 1); (*(volatile __u32 *)&(array[(42)&15]) = (TEMP)); C += TEMP + rol32(D,5) + (((E&A)+(B&(E^A)))) + (0x8f1bbcdc); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(43 +13)&15]) ^ (array[(43 +8)&15]) ^ (array[(43 +2)&15]) ^ (array[(43)&15]), 1); (*(volatile __u32 *)&(array[(43)&15]) = (TEMP)); B += TEMP + rol32(C,5) + (((D&E)+(A&(D^E)))) + (0x8f1bbcdc); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(44 +13)&15]) ^ (array[(44 +8)&15]) ^ (array[(44 +2)&15]) ^ (array[(44)&15]), 1); (*(volatile __u32 *)&(array[(44)&15]) = (TEMP)); A += TEMP + rol32(B,5) + (((C&D)+(E&(C^D)))) + (0x8f1bbcdc); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(45 +13)&15]) ^ (array[(45 +8)&15]) ^ (array[(45 +2)&15]) ^ (array[(45)&15]), 1); (*(volatile __u32 *)&(array[(45)&15]) = (TEMP)); E += TEMP + rol32(A,5) + (((B&C)+(D&(B^C)))) + (0x8f1bbcdc); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(46 +13)&15]) ^ (array[(46 +8)&15]) ^ (array[(46 +2)&15]) ^ (array[(46)&15]), 1); (*(volatile __u32 *)&(array[(46)&15]) = (TEMP)); D += TEMP + rol32(E,5) + (((A&B)+(C&(A^B)))) + (0x8f1bbcdc); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(47 +13)&15]) ^ (array[(47 +8)&15]) ^ (array[(47 +2)&15]) ^ (array[(47)&15]), 1); (*(volatile __u32 *)&(array[(47)&15]) = (TEMP)); C += TEMP + rol32(D,5) + (((E&A)+(B&(E^A)))) + (0x8f1bbcdc); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(48 +13)&15]) ^ (array[(48 +8)&15]) ^ (array[(48 +2)&15]) ^ (array[(48)&15]), 1); (*(volatile __u32 *)&(array[(48)&15]) = (TEMP)); B += TEMP + rol32(C,5) + (((D&E)+(A&(D^E)))) + (0x8f1bbcdc); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(49 +13)&15]) ^ (array[(49 +8)&15]) ^ (array[(49 +2)&15]) ^ (array[(49)&15]), 1); (*(volatile __u32 *)&(array[(49)&15]) = (TEMP)); A += TEMP + rol32(B,5) + (((C&D)+(E&(C^D)))) + (0x8f1bbcdc); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(50 +13)&15]) ^ (array[(50 +8)&15]) ^ (array[(50 +2)&15]) ^ (array[(50)&15]), 1); (*(volatile __u32 *)&(array[(50)&15]) = (TEMP)); E += TEMP + rol32(A,5) + (((B&C)+(D&(B^C)))) + (0x8f1bbcdc); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(51 +13)&15]) ^ (array[(51 +8)&15]) ^ (array[(51 +2)&15]) ^ (array[(51)&15]), 1); (*(volatile __u32 *)&(array[(51)&15]) = (TEMP)); D += TEMP + rol32(E,5) + (((A&B)+(C&(A^B)))) + (0x8f1bbcdc); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(52 +13)&15]) ^ (array[(52 +8)&15]) ^ (array[(52 +2)&15]) ^ (array[(52)&15]), 1); (*(volatile __u32 *)&(array[(52)&15]) = (TEMP)); C += TEMP + rol32(D,5) + (((E&A)+(B&(E^A)))) + (0x8f1bbcdc); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(53 +13)&15]) ^ (array[(53 +8)&15]) ^ (array[(53 +2)&15]) ^ (array[(53)&15]), 1); (*(volatile __u32 *)&(array[(53)&15]) = (TEMP)); B += TEMP + rol32(C,5) + (((D&E)+(A&(D^E)))) + (0x8f1bbcdc); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(54 +13)&15]) ^ (array[(54 +8)&15]) ^ (array[(54 +2)&15]) ^ (array[(54)&15]), 1); (*(volatile __u32 *)&(array[(54)&15]) = (TEMP)); A += TEMP + rol32(B,5) + (((C&D)+(E&(C^D)))) + (0x8f1bbcdc); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(55 +13)&15]) ^ (array[(55 +8)&15]) ^ (array[(55 +2)&15]) ^ (array[(55)&15]), 1); (*(volatile __u32 *)&(array[(55)&15]) = (TEMP)); E += TEMP + rol32(A,5) + (((B&C)+(D&(B^C)))) + (0x8f1bbcdc); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(56 +13)&15]) ^ (array[(56 +8)&15]) ^ (array[(56 +2)&15]) ^ (array[(56)&15]), 1); (*(volatile __u32 *)&(array[(56)&15]) = (TEMP)); D += TEMP + rol32(E,5) + (((A&B)+(C&(A^B)))) + (0x8f1bbcdc); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(57 +13)&15]) ^ (array[(57 +8)&15]) ^ (array[(57 +2)&15]) ^ (array[(57)&15]), 1); (*(volatile __u32 *)&(array[(57)&15]) = (TEMP)); C += TEMP + rol32(D,5) + (((E&A)+(B&(E^A)))) + (0x8f1bbcdc); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(58 +13)&15]) ^ (array[(58 +8)&15]) ^ (array[(58 +2)&15]) ^ (array[(58)&15]), 1); (*(volatile __u32 *)&(array[(58)&15]) = (TEMP)); B += TEMP + rol32(C,5) + (((D&E)+(A&(D^E)))) + (0x8f1bbcdc); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(59 +13)&15]) ^ (array[(59 +8)&15]) ^ (array[(59 +2)&15]) ^ (array[(59)&15]), 1); (*(volatile __u32 *)&(array[(59)&15]) = (TEMP)); A += TEMP + rol32(B,5) + (((C&D)+(E&(C^D)))) + (0x8f1bbcdc); C = ror32(C, 2); } while (0);


    do { __u32 TEMP = rol32((array[(60 +13)&15]) ^ (array[(60 +8)&15]) ^ (array[(60 +2)&15]) ^ (array[(60)&15]), 1); (*(volatile __u32 *)&(array[(60)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0xca62c1d6); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(61 +13)&15]) ^ (array[(61 +8)&15]) ^ (array[(61 +2)&15]) ^ (array[(61)&15]), 1); (*(volatile __u32 *)&(array[(61)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0xca62c1d6); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(62 +13)&15]) ^ (array[(62 +8)&15]) ^ (array[(62 +2)&15]) ^ (array[(62)&15]), 1); (*(volatile __u32 *)&(array[(62)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0xca62c1d6); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(63 +13)&15]) ^ (array[(63 +8)&15]) ^ (array[(63 +2)&15]) ^ (array[(63)&15]), 1); (*(volatile __u32 *)&(array[(63)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0xca62c1d6); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(64 +13)&15]) ^ (array[(64 +8)&15]) ^ (array[(64 +2)&15]) ^ (array[(64)&15]), 1); (*(volatile __u32 *)&(array[(64)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0xca62c1d6); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(65 +13)&15]) ^ (array[(65 +8)&15]) ^ (array[(65 +2)&15]) ^ (array[(65)&15]), 1); (*(volatile __u32 *)&(array[(65)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0xca62c1d6); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(66 +13)&15]) ^ (array[(66 +8)&15]) ^ (array[(66 +2)&15]) ^ (array[(66)&15]), 1); (*(volatile __u32 *)&(array[(66)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0xca62c1d6); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(67 +13)&15]) ^ (array[(67 +8)&15]) ^ (array[(67 +2)&15]) ^ (array[(67)&15]), 1); (*(volatile __u32 *)&(array[(67)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0xca62c1d6); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(68 +13)&15]) ^ (array[(68 +8)&15]) ^ (array[(68 +2)&15]) ^ (array[(68)&15]), 1); (*(volatile __u32 *)&(array[(68)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0xca62c1d6); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(69 +13)&15]) ^ (array[(69 +8)&15]) ^ (array[(69 +2)&15]) ^ (array[(69)&15]), 1); (*(volatile __u32 *)&(array[(69)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0xca62c1d6); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(70 +13)&15]) ^ (array[(70 +8)&15]) ^ (array[(70 +2)&15]) ^ (array[(70)&15]), 1); (*(volatile __u32 *)&(array[(70)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0xca62c1d6); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(71 +13)&15]) ^ (array[(71 +8)&15]) ^ (array[(71 +2)&15]) ^ (array[(71)&15]), 1); (*(volatile __u32 *)&(array[(71)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0xca62c1d6); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(72 +13)&15]) ^ (array[(72 +8)&15]) ^ (array[(72 +2)&15]) ^ (array[(72)&15]), 1); (*(volatile __u32 *)&(array[(72)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0xca62c1d6); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(73 +13)&15]) ^ (array[(73 +8)&15]) ^ (array[(73 +2)&15]) ^ (array[(73)&15]), 1); (*(volatile __u32 *)&(array[(73)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0xca62c1d6); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(74 +13)&15]) ^ (array[(74 +8)&15]) ^ (array[(74 +2)&15]) ^ (array[(74)&15]), 1); (*(volatile __u32 *)&(array[(74)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0xca62c1d6); C = ror32(C, 2); } while (0);
    do { __u32 TEMP = rol32((array[(75 +13)&15]) ^ (array[(75 +8)&15]) ^ (array[(75 +2)&15]) ^ (array[(75)&15]), 1); (*(volatile __u32 *)&(array[(75)&15]) = (TEMP)); E += TEMP + rol32(A,5) + ((B^C^D)) + (0xca62c1d6); B = ror32(B, 2); } while (0);
    do { __u32 TEMP = rol32((array[(76 +13)&15]) ^ (array[(76 +8)&15]) ^ (array[(76 +2)&15]) ^ (array[(76)&15]), 1); (*(volatile __u32 *)&(array[(76)&15]) = (TEMP)); D += TEMP + rol32(E,5) + ((A^B^C)) + (0xca62c1d6); A = ror32(A, 2); } while (0);
    do { __u32 TEMP = rol32((array[(77 +13)&15]) ^ (array[(77 +8)&15]) ^ (array[(77 +2)&15]) ^ (array[(77)&15]), 1); (*(volatile __u32 *)&(array[(77)&15]) = (TEMP)); C += TEMP + rol32(D,5) + ((E^A^B)) + (0xca62c1d6); E = ror32(E, 2); } while (0);
    do { __u32 TEMP = rol32((array[(78 +13)&15]) ^ (array[(78 +8)&15]) ^ (array[(78 +2)&15]) ^ (array[(78)&15]), 1); (*(volatile __u32 *)&(array[(78)&15]) = (TEMP)); B += TEMP + rol32(C,5) + ((D^E^A)) + (0xca62c1d6); D = ror32(D, 2); } while (0);
    do { __u32 TEMP = rol32((array[(79 +13)&15]) ^ (array[(79 +8)&15]) ^ (array[(79 +2)&15]) ^ (array[(79)&15]), 1); (*(volatile __u32 *)&(array[(79)&15]) = (TEMP)); A += TEMP + rol32(B,5) + ((C^D^E)) + (0xca62c1d6); C = ror32(C, 2); } while (0);

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
}





void sha_init(__u32 *buf)
{
    buf[0] = 0x67452301;
    buf[1] = 0xefcdab89;
    buf[2] = 0x98badcfe;
    buf[3] = 0x10325476;
    buf[4] = 0xc3d2e1f0;
}
