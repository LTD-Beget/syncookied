#include <linux/types.h>
#include <stdint.h>

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define __force
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
 
enum {
 false = 0,
 true = 1
};

static __always_inline void
set_bit(long nr, volatile unsigned long *addr)
{
 if ((__builtin_constant_p(nr))) {
  asm volatile("" "orb %1,%0"
   : "+m" (*(volatile long *) ((void *)(addr) + ((nr)>>3)))
   : "iq" ((u8)(1 << ((nr) & 7)))
   : "memory");
 } else {
  asm volatile("" "bts %1,%0"
   : "+m" (*(volatile long *) (addr)) : "Ir" (nr) : "memory");
 }
}

static inline void __set_bit(long nr, volatile unsigned long *addr)
{
 asm volatile("bts %1,%0" : "+m" (*(volatile long *) (addr)) : "Ir" (nr) : "memory");
}

static __always_inline void
clear_bit(long nr, volatile unsigned long *addr)
{
 if ((__builtin_constant_p(nr))) {
  asm volatile("" "andb %1,%0"
   : "+m" (*(volatile long *) ((void *)(addr) + ((nr)>>3)))
   : "iq" ((u8)~(1 << ((nr) & 7))));
 } else {
  asm volatile("" "btr %1,%0"
   : "+m" (*(volatile long *) (addr))
   : "Ir" (nr));
 }
}

static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
{
 barrier();
 clear_bit(nr, addr);
}

static inline void __clear_bit(long nr, volatile unsigned long *addr)
{
 asm volatile("btr %1,%0" : "+m" (*(volatile long *) (addr)) : "Ir" (nr));
}

static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
{
 barrier();
 __clear_bit(nr, addr);
}

static inline void __change_bit(long nr, volatile unsigned long *addr)
{
 asm volatile("btc %1,%0" : "+m" (*(volatile long *) (addr)) : "Ir" (nr));
}

static inline void change_bit(long nr, volatile unsigned long *addr)
{
 if ((__builtin_constant_p(nr))) {
  asm volatile("" "xorb %1,%0"
   : "+m" (*(volatile long *) ((void *)(addr) + ((nr)>>3)))
   : "iq" ((u8)(1 << ((nr) & 7))));
 } else {
  asm volatile("" "btc %1,%0"
   : "+m" (*(volatile long *) (addr))
   : "Ir" (nr));
 }
}
# 204 "/usr/src/kernel/arch/x86/include/asm/bitops.h"
static inline int test_and_set_bit(long nr, volatile unsigned long *addr)
{
 do { char c; asm volatile ("" "bts" " %2, " "%0" "; set" "c" " %1" : "+m" (*addr), "=qm" (c) : "Ir" (nr) : "memory"); return c != 0; } while (0);
}
# 216 "/usr/src/kernel/arch/x86/include/asm/bitops.h"
static __always_inline int
test_and_set_bit_lock(long nr, volatile unsigned long *addr)
{
 return test_and_set_bit(nr, addr);
}
# 231 "/usr/src/kernel/arch/x86/include/asm/bitops.h"
static inline int __test_and_set_bit(long nr, volatile unsigned long *addr)
{
 int oldbit;

 asm("bts %2,%1\n\t"
     "sbb %0,%0"
     : "=r" (oldbit), "+m" (*(volatile long *) (addr))
     : "Ir" (nr));
 return oldbit;
}
# 250 "/usr/src/kernel/arch/x86/include/asm/bitops.h"
static inline int test_and_clear_bit(long nr, volatile unsigned long *addr)
{
 do { char c; asm volatile ("" "btr" " %2, " "%0" "; set" "c" " %1" : "+m" (*addr), "=qm" (c) : "Ir" (nr) : "memory"); return c != 0; } while (0);
}
# 271 "/usr/src/kernel/arch/x86/include/asm/bitops.h"
static inline int __test_and_clear_bit(long nr, volatile unsigned long *addr)
{
 int oldbit;

 asm volatile("btr %2,%1\n\t"
       "sbb %0,%0"
       : "=r" (oldbit), "+m" (*(volatile long *) (addr))
       : "Ir" (nr));
 return oldbit;
}


static inline int __test_and_change_bit(long nr, volatile unsigned long *addr)
{
 int oldbit;

 asm volatile("btc %2,%1\n\t"
       "sbb %0,%0"
       : "=r" (oldbit), "+m" (*(volatile long *) (addr))
       : "Ir" (nr) : "memory");

 return oldbit;
}

static inline int test_and_change_bit(long nr, volatile unsigned long *addr)
{
 do { char c; asm volatile ("" "btc" " %2, " "%0" "; set" "c" " %1" : "+m" (*addr), "=qm" (c) : "Ir" (nr) : "memory"); return c != 0; } while (0);
}

static __always_inline int constant_test_bit(long nr, const volatile unsigned long *addr)
{
 return ((1UL << (nr & (32 -1))) &
  (addr[nr >> 5])) != 0;
}

static inline int variable_test_bit(long nr, volatile const unsigned long *addr)
{
 int oldbit;

 asm volatile("bt %2,%1\n\t"
       "sbb %0,%0"
       : "=r" (oldbit)
       : "m" (*(unsigned long *)addr), "Ir" (nr));

 return oldbit;
}

static inline unsigned long __ffs(unsigned long word)
{
 asm("rep; bsf %1,%0"
  : "=r" (word)
  : "rm" (word));
 return word;
}







static inline unsigned long ffz(unsigned long word)
{
 asm("rep; bsf %1,%0"
  : "=r" (word)
  : "r" (~word));
 return word;
}







static inline unsigned long __fls(unsigned long word)
{
 asm("bsr %1,%0"
     : "=r" (word)
     : "rm" (word));
 return word;
}

static inline int get_bitmask_order(unsigned int count)
{
 int order;

 order = fls(count);
 return order;
}

static inline int get_count_order(unsigned int count)
{
 int order;

 order = fls(count) - 1;
 if (count & (count - 1))
  order++;
 return order;
}

static __always_inline unsigned long hweight_long(unsigned long w)
{
 return sizeof(w) == 4 ? hweight32(w) : hweight64(w);
}






static inline __u64 rol64(__u64 word, unsigned int shift)
{
 return (word << shift) | (word >> (64 - shift));
}






static inline __u64 ror64(__u64 word, unsigned int shift)
{
 return (word >> shift) | (word << (64 - shift));
}






static inline __u32 rol32(__u32 word, unsigned int shift)
{
 return (word << shift) | (word >> ((-shift) & 31));
}






static inline __u32 ror32(__u32 word, unsigned int shift)
{
 return (word >> shift) | (word << (32 - shift));
}






static inline __u16 rol16(__u16 word, unsigned int shift)
{
 return (word << shift) | (word >> (16 - shift));
}






static inline __u16 ror16(__u16 word, unsigned int shift)
{
 return (word >> shift) | (word << (16 - shift));
}






static inline __u8 rol8(__u8 word, unsigned int shift)
{
 return (word << shift) | (word >> (8 - shift));
}






static inline __u8 ror8(__u8 word, unsigned int shift)
{
 return (word >> shift) | (word << (8 - shift));
}

static inline __s32 sign_extend32(__u32 value, int index)
{
 __u8 shift = 31 - index;
 return (__s32)(value << shift) >> shift;
}






static inline __s64 sign_extend64(__u64 value, int index)
{
 __u8 shift = 63 - index;
 return (__s64)(value << shift) >> shift;
}

static inline unsigned fls_long(unsigned long l)
{
 if (sizeof(l) == 4)
  return fls(l);
 return fls64(l);
}

static inline unsigned long __ffs64(u64 word)
{

 if (((u32)word) == 0UL)
  return __ffs((u32)(word >> 32)) + 32;



 return __ffs((unsigned long)word);
}

static __inline__ __u32 __arch_swab32(__u32 val)
{
 __asm__("bswapl %0" : "=r" (val) : "0" (val));
 return val;
}


static __inline__ __u64 __arch_swab64(__u64 val)
{

 __asm__("bswapq %0" : "=r" (val) : "0" (val));
 return val;

}


static inline __attribute__ ((__const__)) __u16 __fswab16(__u16 val)
{





 return ((__u16)( (((__u16)(val) & (__u16)0x00ffU) << 8) | (((__u16)(val) & (__u16)0xff00U) >> 8)));

}

static inline __attribute__ ((__const__)) __u32 __fswab32(__u32 val)
{



 return __arch_swab32(val);



}

static inline __attribute__ ((__const__)) __u64 __fswab64(__u64 val)
{



 return __arch_swab64(val);







}

static inline __attribute__ ((__const__)) __u32 __fswahw32(__u32 val)
{



 return ((__u32)( (((__u32)(val) & (__u32)0x0000ffffUL) << 16) | (((__u32)(val) & (__u32)0xffff0000UL) >> 16)));

}

static inline __attribute__ ((__const__)) __u32 __fswahb32(__u32 val)
{



 return ((__u32)( (((__u32)(val) & (__u32)0x00ff00ffUL) << 8) | (((__u32)(val) & (__u32)0xff00ff00UL) >> 8)));

}

static inline __u16 __swab16p(const __u16 *p)
{



 return (__builtin_constant_p((__u16)(*p)) ? ((__u16)( (((__u16)(*p) & (__u16)0x00ffU) << 8) | (((__u16)(*p) & (__u16)0xff00U) >> 8))) : __fswab16(*p));

}





static inline __u32 __swab32p(const __u32 *p)
{



 return (__builtin_constant_p((__u32)(*p)) ? ((__u32)( (((__u32)(*p) & (__u32)0x000000ffUL) << 24) | (((__u32)(*p) & (__u32)0x0000ff00UL) << 8) | (((__u32)(*p) & (__u32)0x00ff0000UL) >> 8) | (((__u32)(*p) & (__u32)0xff000000UL) >> 24))) : __fswab32(*p));

}





static inline __u64 __swab64p(const __u64 *p)
{



 return (__builtin_constant_p((__u64)(*p)) ? ((__u64)( (((__u64)(*p) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)(*p) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)(*p) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)(*p) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)(*p) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)(*p) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)(*p) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)(*p) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64(*p));

}







static inline __u32 __swahw32p(const __u32 *p)
{



 return (__builtin_constant_p((__u32)(*p)) ? ((__u32)( (((__u32)(*p) & (__u32)0x0000ffffUL) << 16) | (((__u32)(*p) & (__u32)0xffff0000UL) >> 16))) : __fswahw32(*p));

}







static inline __u32 __swahb32p(const __u32 *p)
{



 return (__builtin_constant_p((__u32)(*p)) ? ((__u32)( (((__u32)(*p) & (__u32)0x00ff00ffUL) << 8) | (((__u32)(*p) & (__u32)0xff00ff00UL) >> 8))) : __fswahb32(*p));

}





static inline void __swab16s(__u16 *p)
{



 *p = __swab16p(p);

}




static inline void __swab32s(__u32 *p)
{



 *p = __swab32p(p);

}





static inline void __swab64s(__u64 *p)
{



 *p = __swab64p(p);

}







static inline void __swahw32s(__u32 *p)
{



 *p = __swahw32p(p);

}







static inline void __swahb32s(__u32 *p)
{



 *p = __swahb32p(p);

}
static inline __le64 __cpu_to_le64p(const __u64 *p)
{
 return (__force __le64)*p;
}
static inline __u64 __le64_to_cpup(const __le64 *p)
{
 return (__force __u64)*p;
}
static inline __le32 __cpu_to_le32p(const __u32 *p)
{
 return (__force __le32)*p;
}
static inline __u32 __le32_to_cpup(const __le32 *p)
{
 return (__force __u32)*p;
}
static inline __le16 __cpu_to_le16p(const __u16 *p)
{
 return (__force __le16)*p;
}
static inline __u16 __le16_to_cpup(const __le16 *p)
{
 return (__force __u16)*p;
}
static inline __be64 __cpu_to_be64p(const __u64 *p)
{
 return (__force __be64)__swab64p(p);
}
static inline __u64 __be64_to_cpup(const __be64 *p)
{
 return __swab64p((__u64 *)p);
}
static inline __be32 __cpu_to_be32p(const __u32 *p)
{
 return (__force __be32)__swab32p(p);
}
static inline __u32 __be32_to_cpup(const __be32 *p)
{
 return __swab32p((__u32 *)p);
}
static inline __be16 __cpu_to_be16p(const __u16 *p)
{
 return (__force __be16)__swab16p(p);
}
static inline __u16 __be16_to_cpup(const __be16 *p)
{
 return __swab16p((__u16 *)p);
}
static inline void le16_add_cpu(__le16 *var, u16 val)
{
 *var = ((__force __le16)(__u16)(((__force __u16)(__le16)(*var)) + val));
}

static inline void le32_add_cpu(__le32 *var, u32 val)
{
 *var = ((__force __le32)(__u32)(((__force __u32)(__le32)(*var)) + val));
}

static inline void le64_add_cpu(__le64 *var, u64 val)
{
 *var = ((__force __le64)(__u64)(((__force __u64)(__le64)(*var)) + val));
}

static inline void be16_add_cpu(__be16 *var, u16 val)
{
 *var = ((__force __be16)(__builtin_constant_p((__u16)(((__builtin_constant_p((__u16)((__force __u16)(__be16)(*var))) ? ((__u16)( (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0x00ffU) << 8) | (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0xff00U) >> 8))) : __fswab16((__force __u16)(__be16)(*var))) + val))) ? ((__u16)( (((__u16)(((__builtin_constant_p((__u16)((__force __u16)(__be16)(*var))) ? ((__u16)( (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0x00ffU) << 8) | (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0xff00U) >> 8))) : __fswab16((__force __u16)(__be16)(*var))) + val)) & (__u16)0x00ffU) << 8) | (((__u16)(((__builtin_constant_p((__u16)((__force __u16)(__be16)(*var))) ? ((__u16)( (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0x00ffU) << 8) | (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0xff00U) >> 8))) : __fswab16((__force __u16)(__be16)(*var))) + val)) & (__u16)0xff00U) >> 8))) : __fswab16(((__builtin_constant_p((__u16)((__force __u16)(__be16)(*var))) ? ((__u16)( (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0x00ffU) << 8) | (((__u16)((__force __u16)(__be16)(*var)) & (__u16)0xff00U) >> 8))) : __fswab16((__force __u16)(__be16)(*var))) + val))));
}

static inline void be32_add_cpu(__be32 *var, u32 val)
{
 *var = ((__force __be32)(__builtin_constant_p((__u32)(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val))) ? ((__u32)( (((__u32)(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val)) & (__u32)0x000000ffUL) << 24) | (((__u32)(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val)) & (__u32)0x0000ff00UL) << 8) | (((__u32)(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val)) & (__u32)0xff000000UL) >> 24))) : __fswab32(((__builtin_constant_p((__u32)((__force __u32)(__be32)(*var))) ? ((__u32)( (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x000000ffUL) << 24) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x0000ff00UL) << 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0x00ff0000UL) >> 8) | (((__u32)((__force __u32)(__be32)(*var)) & (__u32)0xff000000UL) >> 24))) : __fswab32((__force __u32)(__be32)(*var))) + val))));
}

static inline void be64_add_cpu(__be64 *var, u64 val)
{
 *var = ((__force __be64)(__builtin_constant_p((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val))) ? ((__u64)( (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64(((__builtin_constant_p((__u64)((__force __u64)(__be64)(*var))) ? ((__u64)( (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000000000ffULL) << 56) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000000000ff00ULL) << 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000000000ff0000ULL) << 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00000000ff000000ULL) << 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x000000ff00000000ULL) >> 8) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x0000ff0000000000ULL) >> 24) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0x00ff000000000000ULL) >> 40) | (((__u64)((__force __u64)(__be64)(*var)) & (__u64)0xff00000000000000ULL) >> 56))) : __fswab64((__force __u64)(__be64)(*var))) + val))));
}




static inline __sum16 csum_fold(__wsum sum)
{
 asm("  addl %1,%0\n"
     "  adcl $0xffff,%0"
     : "=r" (sum)
     : "r" ((__force u32)sum << 16),
       "0" ((__force u32)sum & 0xffff0000));
 return (__force __sum16)(~(__force u32)sum >> 16);
}

static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
 unsigned int sum;

 asm("  movl (%1), %0\n"
     "  subl $4, %2\n"
     "  jbe 2f\n"
     "  addl 4(%1), %0\n"
     "  adcl 8(%1), %0\n"
     "  adcl 12(%1), %0\n"
     "1: adcl 16(%1), %0\n"
     "  lea 4(%1), %1\n"
     "  decl %2\n"
     "  jne	1b\n"
     "  adcl $0, %0\n"
     "  movl %0, %2\n"
     "  shrl $16, %0\n"
     "  addw %w2, %w0\n"
     "  adcl $0, %0\n"
     "  notl %0\n"
     "2:"



     : "=r" (sum), "=r" (iph), "=r" (ihl)
     : "1" (iph), "2" (ihl)
     : "memory");
 return (__force __sum16)sum;
}

static inline __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len,
     unsigned short proto, __wsum sum)
{
 asm("  addl %1, %0\n"
     "  adcl %2, %0\n"
     "  adcl %3, %0\n"
     "  adcl $0, %0\n"
     : "=r" (sum)
     : "g" (daddr), "g" (saddr),
       "g" ((len + proto)<<8), "0" (sum));
 return sum;
}

static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
     unsigned short len,
     unsigned short proto, __wsum sum)
{
 return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

#if 0
extern __sum16
csum_ipv6_magic(const struct in6_addr *saddr, const struct in6_addr *daddr,
  __u32 len, unsigned short proto, __wsum sum);
#endif

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
 asm("addl %2,%0\n\t"
     "adcl $0,%0"
     : "=r" (a)
     : "0" (a), "rm" (b));
 return a;
}


static inline __wsum csum_add(__wsum csum, __wsum addend)
{
 return (__force __wsum)add32_with_carry((__force unsigned)csum,
      (__force unsigned)addend);
}

static inline unsigned short from32to16(unsigned a)
{
 unsigned short b = a >> 16;
 asm("addw %w2,%w0\n\t"
     "adcw $0,%w0\n"
     : "=r" (b)
     : "0" (b), "r" (a));
 return b;
}

static unsigned do_csum(const unsigned char *buff, unsigned len)
{
 unsigned odd, count;
 unsigned long result = 0;

 if (unlikely(len == 0))
  return result;
 odd = 1 & (unsigned long) buff;
 if (unlikely(odd)) {
  result = *buff << 8;
  len--;
  buff++;
 }
 count = len >> 1;
 if (count) {
  if (2 & (unsigned long) buff) {
   result += *(unsigned short *)buff;
   count--;
   len -= 2;
   buff += 2;
  }
  count >>= 1;
  if (count) {
   unsigned long zero;
   unsigned count64;
   if (4 & (unsigned long) buff) {
    result += *(unsigned int *) buff;
    count--;
    len -= 4;
    buff += 4;
   }
   count >>= 1;


   zero = 0;
   count64 = count >> 3;
   while (count64) {
    asm("addq 0*8(%[src]),%[res]\n\t"
        "adcq 1*8(%[src]),%[res]\n\t"
        "adcq 2*8(%[src]),%[res]\n\t"
        "adcq 3*8(%[src]),%[res]\n\t"
        "adcq 4*8(%[src]),%[res]\n\t"
        "adcq 5*8(%[src]),%[res]\n\t"
        "adcq 6*8(%[src]),%[res]\n\t"
        "adcq 7*8(%[src]),%[res]\n\t"
        "adcq %[zero],%[res]"
        : [res] "=r" (result)
        : [src] "r" (buff), [zero] "r" (zero),
        "[res]" (result));
    buff += 64;
    count64--;
   }


   count %= 8;
   while (count) {
    asm("addq %1,%0\n\t"
        "adcq %2,%0\n"
         : "=r" (result)
        : "m" (*(unsigned long *)buff),
        "r" (zero), "0" (result));
    --count;
     buff += 8;
   }
   result = add32_with_carry(result>>32,
        result&0xffffffff);

   if (len & 4) {
    result += *(unsigned int *) buff;
    buff += 4;
   }
  }
  if (len & 2) {
   result += *(unsigned short *) buff;
   buff += 2;
  }
 }
 if (len & 1)
  result += *buff;
 result = add32_with_carry(result>>32, result & 0xffffffff);
 if (unlikely(odd)) {
  result = from32to16(result);
  result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
 }
 return result;
}

__wsum csum_partial(const void *buff, int len, __wsum sum)
{
 return (__force __wsum)add32_with_carry(do_csum(buff, len),
      (__force u32)sum);
}

__sum16 csum_partial_folded(const void *buff, int len, __wsum sum)
{
 return csum_fold((__force __wsum)add32_with_carry(do_csum(buff, len),
      (__force u32)sum));
}

__sum16 ip_compute_csum(const void *buff, int len)
{
 return csum_fold(csum_partial(buff,len,0));
}
