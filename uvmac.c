/* --------------------------------------------------------------------------
 * UVMAC computes unconditionally secure Message Authentication Codes by
 * combining the VHASH implemented by Ted Krovetz (tdk@acm.org) and Wei Dai
 * toghether with one-time pad encryption.
 * This adaptation is proposed by Jean-Daniel Bancal. It is herby placed in the
 * public domain. The authors offers no warranty. Use at your own risk.
 * Please send bug reports to the authors.
 * Last modified: 10 JUL 20, 1700 PDT
 * ----------------------------------------------------------------------- */

#include "uvmac.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

/* Enable code tuned for 64-bit registers; otherwise tuned for 32-bit */
#ifndef UVMAC_ARCH_64
#define UVMAC_ARCH_64 (__x86_64__ || __ppc64__ || _M_X64)
#endif

/* Enable code tuned for Intel SSE2 instruction set                   */
#if ((__SSE2__ || (_M_IX86_FP >= 2)) && ( ! UVMAC_ARCH_64))
#define UVMAC_USE_SSE2    1
#include <emmintrin.h>
#endif

/* Native word reads. Update (or define via compiler) if incorrect */
#ifndef UVMAC_ARCH_BIG_ENDIAN       /* Assume big-endian unless on the list */
#define UVMAC_ARCH_BIG_ENDIAN \
    (!(__x86_64__ || __i386__ || _M_IX86 || \
       _M_X64 || __ARMEL__ || __MIPSEL__))
#endif

/* ----------------------------------------------------------------------- */
/* Constants and masks                                                     */

const uint64_t p64   = UINT64_C(0xfffffffffffffeff);  /* 2^64 - 257 prime  */
const uint64_t m62   = UINT64_C(0x3fffffffffffffff);  /* 62-bit mask       */
const uint64_t m63   = UINT64_C(0x7fffffffffffffff);  /* 63-bit mask       */
const uint64_t m64   = UINT64_C(0xffffffffffffffff);  /* 64-bit mask       */
const uint64_t mpoly = UINT64_C(0x1fffffff1fffffff);  /* Poly key mask     */

/* ----------------------------------------------------------------------- *
 * The following routines are used in this implementation. They are
 * written via macros to simulate zero-overhead call-by-reference.
 * All have default implemantations for when they are not defined in an
 * architecture-specific manner.
 *
 * MUL64: 64x64->128-bit multiplication
 * PMUL64: assumes top bits cleared on inputs
 * ADD128: 128x128->128-bit addition
 * GET_REVERSED_64: load and byte-reverse 64-bit word
 * ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
#if (__GNUC__ && (__x86_64__ || __amd64__))
/* ----------------------------------------------------------------------- */

#define ADD128(rh,rl,ih,il)                                               \
    asm ("addq %3, %1 \n\t"                                               \
         "adcq %2, %0"                                                    \
    : "+r"(rh),"+r"(rl)                                                   \
    : "r"(ih),"r"(il) : "cc");

#define MUL64(rh,rl,i1,i2)                                                \
    asm ("mulq %3" : "=a"(rl), "=d"(rh) : "a"(i1), "r"(i2) : "cc")

#define PMUL64 MUL64

#define GET_REVERSED_64(p)                                                \
    ({uint64_t x;                                                         \
     asm ("bswapq %0" : "=r" (x) : "0"(*(uint64_t *)(p))); x;})

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && __i386__)
/* ----------------------------------------------------------------------- */

#define GET_REVERSED_64(p)                                                \
    ({ uint64_t x;                                                        \
    uint32_t *tp = (uint32_t *)(p);                                       \
    asm  ("bswap %%edx\n\t"                                               \
          "bswap %%eax"                                                   \
    : "=A"(x)                                                             \
    : "a"(tp[1]), "d"(tp[0]));                                            \
    x; })

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && __ppc64__)
/* ----------------------------------------------------------------------- */

#define ADD128(rh,rl,ih,il)                                               \
    asm volatile (  "addc %1, %1, %3 \n\t"                                \
                    "adde %0, %0, %2"                                     \
    : "+r"(rh),"+r"(rl)                                                   \
    : "r"(ih),"r"(il));

#define MUL64(rh,rl,i1,i2)                                                \
{ uint64_t _i1 = (i1), _i2 = (i2);                                        \
    rl = _i1 * _i2;                                                       \
    asm volatile ("mulhdu %0, %1, %2" : "=r" (rh) : "r" (_i1), "r" (_i2));\
}

#define PMUL64 MUL64

#define GET_REVERSED_64(p)                                                \
    ({ uint32_t hi, lo, *_p = (uint32_t *)(p);                            \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(hi) : "b%"(4), "r"(_p) );  \
       ((uint64_t)hi << 32) | (uint64_t)lo; } )

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && (__ppc__ || __PPC__))
/* ----------------------------------------------------------------------- */

#define GET_REVERSED_64(p)                                                \
    ({ uint32_t hi, lo, *_p = (uint32_t *)(p);                            \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(lo) : "b%"(0), "r"(_p) );  \
       asm volatile ("lwbrx %0, %1, %2" : "=r"(hi) : "b%"(4), "r"(_p) );  \
       ((uint64_t)hi << 32) | (uint64_t)lo; } )

/* ----------------------------------------------------------------------- */
#elif (__GNUC__ && (__ARMEL__ || __ARM__))
/* ----------------------------------------------------------------------- */

#define bswap32(v)                                                        \
({ uint32_t tmp,out;                                                      \
    asm volatile(                                                         \
        "eor    %1, %2, %2, ror #16\n"                                    \
        "bic    %1, %1, #0x00ff0000\n"                                    \
        "mov    %0, %2, ror #8\n"                                         \
        "eor    %0, %0, %1, lsr #8"                                       \
    : "=r" (out), "=&r" (tmp)                                             \
    : "r" (v));                                                           \
    out;})

/* ----------------------------------------------------------------------- */
#elif _MSC_VER
/* ----------------------------------------------------------------------- */

#include <intrin.h>

#if (_M_IA64 || _M_X64) && \
    (!defined(__INTEL_COMPILER) || __INTEL_COMPILER >= 1000)
#define MUL64(rh,rl,i1,i2)   (rl) = _umul128(i1,i2,&(rh));
#pragma intrinsic(_umul128)
#define PMUL64 MUL64
#endif

/* MSVC uses add, adc in this version */
#define ADD128(rh,rl,ih,il)                                          \
    {   uint64_t _il = (il);                                         \
        (rl) += (_il);                                               \
        (rh) += (ih) + ((rl) < (_il));                               \
    }

#if _MSC_VER >= 1300
#define GET_REVERSED_64(p) _byteswap_uint64(*(uint64_t *)(p))
#pragma intrinsic(_byteswap_uint64)
#endif

#if _MSC_VER >= 1400 && \
    (!defined(__INTEL_COMPILER) || __INTEL_COMPILER >= 1000)
#define MUL32(i1,i2)    (__emulu((uint32_t)(i1),(uint32_t)(i2)))
#pragma intrinsic(__emulu)
#endif

/* ----------------------------------------------------------------------- */
#endif
/* ----------------------------------------------------------------------- */

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n)))
#define NOINLINE      __attribute__ ((noinline))
#define FASTCALL
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#define NOINLINE      __declspec(noinline)
#define FASTCALL      __fastcall
#else
#define ALIGN(n)
#define NOINLINE
#define FASTCALL
#endif

/* ----------------------------------------------------------------------- */
/* Default implementations, if not defined above                           */
/* ----------------------------------------------------------------------- */

#ifndef ADD128
#define ADD128(rh,rl,ih,il)                                              \
    {   uint64_t _il = (il);                                             \
        (rl) += (_il);                                                   \
        if ((rl) < (_il)) (rh)++;                                        \
        (rh) += (ih);                                                    \
    }
#endif

#ifndef MUL32
#define MUL32(i1,i2)    ((uint64_t)(uint32_t)(i1)*(uint32_t)(i2))
#endif

#ifndef PMUL64              /* rh may not be same as i1 or i2 */
#define PMUL64(rh,rl,i1,i2) /* Assumes m doesn't overflow     */         \
    {   uint64_t _i1 = (i1), _i2 = (i2);                                 \
        uint64_t m = MUL32(_i1,_i2>>32) + MUL32(_i1>>32,_i2);            \
        rh         = MUL32(_i1>>32,_i2>>32);                             \
        rl         = MUL32(_i1,_i2);                                     \
        ADD128(rh,rl,(m >> 32),(m << 32));                               \
    }
#endif

#ifndef MUL64
#define MUL64(rh,rl,i1,i2)                                               \
    {   uint64_t _i1 = (i1), _i2 = (i2);                                 \
        uint64_t m1= MUL32(_i1,_i2>>32);                                 \
        uint64_t m2= MUL32(_i1>>32,_i2);                                 \
        rh         = MUL32(_i1>>32,_i2>>32);                             \
        rl         = MUL32(_i1,_i2);                                     \
        ADD128(rh,rl,(m1 >> 32),(m1 << 32));                             \
        ADD128(rh,rl,(m2 >> 32),(m2 << 32));                             \
    }
#endif

#ifndef GET_REVERSED_64
#ifndef bswap64
#ifndef bswap32
#define bswap32(x)                                                        \
  ({ uint32_t bsx = (x);                                                  \
      ((((bsx) & 0xff000000u) >> 24) | (((bsx) & 0x00ff0000u) >>  8) |    \
       (((bsx) & 0x0000ff00u) <<  8) | (((bsx) & 0x000000ffu) << 24)); })
#endif
#define bswap64(x)                                                        \
     ({ union { uint64_t ll; uint32_t l[2]; } w, r;                       \
         w.ll = (x);                                                      \
         r.l[0] = bswap32 (w.l[1]);                                       \
         r.l[1] = bswap32 (w.l[0]);                                       \
         r.ll; })
#endif
#define GET_REVERSED_64(p) bswap64(*(uint64_t *)(p))
#endif

/* ----------------------------------------------------------------------- */

#if (UVMAC_PREFER_BIG_ENDIAN)
#  define get64PE get64BE
#else
#  define get64PE get64LE
#endif

#if (UVMAC_ARCH_BIG_ENDIAN)
#  define get64BE(ptr) (*(uint64_t *)(ptr))
#  define get64LE(ptr) GET_REVERSED_64(ptr)
#else /* assume little-endian */
#  define get64BE(ptr) GET_REVERSED_64(ptr)
#  define get64LE(ptr) (*(uint64_t *)(ptr))
#endif


/* --------------------------------------------------------------------- *
 * For highest performance the L1 NH and L2 polynomial hashes should be
 * carefully implemented to take advantage of one's target architechture.
 * Here these two hash functions are defined multiple time; once for
 * 64-bit architectures, once for 32-bit SSE2 architectures, and once
 * for the rest (32-bit) architectures.
 * For each, nh_16 *must* be defined (works on multiples of 16 bytes).
 * Optionally, nh_vhash_nhbytes can be defined (for multiples of
 * UVMAC_NHBYTES), and nh_16_2 and nh_vhash_nhbytes_2 (versions that do two
 * NH computations at once).
 * --------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
#if UVMAC_ARCH_64
/* ----------------------------------------------------------------------- */

#define nh_16(mp, kp, nw, rh, rl)                                            \
{   int i; uint64_t th, tl;                                                  \
    rh = rl = 0;                                                             \
    for (i = 0; i < nw; i+= 2) {                                             \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i  ],get64PE((mp)+i+1)+(kp)[i+1]);\
        ADD128(rh,rl,th,tl);                                                 \
    }                                                                        \
}
#define nh_16_2(mp, kp, nw, rh, rl, rh1, rl1)                                \
{   int i; uint64_t th, tl;                                                  \
    rh1 = rl1 = rh = rl = 0;                                                 \
    for (i = 0; i < nw; i+= 2) {                                             \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i  ],get64PE((mp)+i+1)+(kp)[i+1]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i+2],get64PE((mp)+i+1)+(kp)[i+3]);\
        ADD128(rh1,rl1,th,tl);                                               \
    }                                                                        \
}

#if (UVMAC_NHBYTES >= 64) /* These versions do 64-bytes of message at a time */
#define nh_vhash_nhbytes(mp, kp, nw, rh, rl)                                  \
{   int i; uint64_t th, tl;                                                  \
    rh = rl = 0;                                                             \
    for (i = 0; i < nw; i+= 8) {                                             \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i  ],get64PE((mp)+i+1)+(kp)[i+1]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+2)+(kp)[i+2],get64PE((mp)+i+3)+(kp)[i+3]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+4)+(kp)[i+4],get64PE((mp)+i+5)+(kp)[i+5]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+6)+(kp)[i+6],get64PE((mp)+i+7)+(kp)[i+7]);\
        ADD128(rh,rl,th,tl);                                                 \
    }                                                                        \
}
#define nh_vhash_nhbytes_2(mp, kp, nw, rh, rl, rh1, rl1)                      \
{   int i; uint64_t th, tl;                                                  \
    rh1 = rl1 = rh = rl = 0;                                                 \
    for (i = 0; i < nw; i+= 8) {                                             \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i  ],get64PE((mp)+i+1)+(kp)[i+1]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i  )+(kp)[i+2],get64PE((mp)+i+1)+(kp)[i+3]);\
        ADD128(rh1,rl1,th,tl);                                               \
        MUL64(th,tl,get64PE((mp)+i+2)+(kp)[i+2],get64PE((mp)+i+3)+(kp)[i+3]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+2)+(kp)[i+4],get64PE((mp)+i+3)+(kp)[i+5]);\
        ADD128(rh1,rl1,th,tl);                                               \
        MUL64(th,tl,get64PE((mp)+i+4)+(kp)[i+4],get64PE((mp)+i+5)+(kp)[i+5]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+4)+(kp)[i+6],get64PE((mp)+i+5)+(kp)[i+7]);\
        ADD128(rh1,rl1,th,tl);                                               \
        MUL64(th,tl,get64PE((mp)+i+6)+(kp)[i+6],get64PE((mp)+i+7)+(kp)[i+7]);\
        ADD128(rh,rl,th,tl);                                                 \
        MUL64(th,tl,get64PE((mp)+i+6)+(kp)[i+8],get64PE((mp)+i+7)+(kp)[i+9]);\
        ADD128(rh1,rl1,th,tl);                                               \
    }                                                                        \
}
#endif

#define poly_step(ah, al, kh, kl, mh, ml)                   \
{   uint64_t t1h, t1l, t2h, t2l, t3h, t3l, z=0;             \
    /* compute ab*cd, put bd into result registers */       \
    PMUL64(t3h,t3l,al,kh);                                  \
    PMUL64(t2h,t2l,ah,kl);                                  \
    PMUL64(t1h,t1l,ah,2*kh);                                \
    PMUL64(ah,al,al,kl);                                    \
    /* add 2 * ac to result */                              \
    ADD128(ah,al,t1h,t1l);                                  \
    /* add together ad + bc */                              \
    ADD128(t2h,t2l,t3h,t3l);                                \
    /* now (ah,al), (t2l,2*t2h) need summing */             \
    /* first add the high registers, carrying into t2h */   \
    ADD128(t2h,ah,z,t2l);                                   \
    /* double t2h and add top bit of ah */                  \
    t2h = 2 * t2h + (ah >> 63);                             \
    ah &= m63;                                              \
    /* now add the low registers */                         \
    ADD128(ah,al,mh,ml);                                    \
    ADD128(ah,al,z,t2h);                                    \
}

/* ----------------------------------------------------------------------- */
#elif UVMAC_USE_SSE2
/* ----------------------------------------------------------------------- */

// macros from Crypto++ for sharing inline assembly code between MSVC and GNU C
#if defined(__GNUC__)
	// define these in two steps to allow arguments to be expanded
	#define GNU_AS2(x, y) #x ", " #y ";"
	#define GNU_AS3(x, y, z) #x ", " #y ", " #z ";"
	#define GNU_ASL(x) "\n" #x ":"
	#define GNU_ASJ(x, y, z) #x " " #y #z ";"
	#define AS2(x, y) GNU_AS2(x, y)
	#define AS3(x, y, z) GNU_AS3(x, y, z)
	#define ASS(x, y, a, b, c, d) #x ", " #y ", " #a "*64+" #b "*16+" #c "*4+" #d ";"
	#define ASL(x) GNU_ASL(x)
	#define ASJ(x, y, z) GNU_ASJ(x, y, z)
#else
	#define AS2(x, y) __asm {x, y}
	#define AS3(x, y, z) __asm {x, y, z}
	#define ASS(x, y, a, b, c, d) __asm {x, y, _MM_SHUFFLE(a, b, c, d)}
	#define ASL(x) __asm {label##x:}
	#define ASJ(x, y, z) __asm {x label##y}
#endif

static void NOINLINE nh_16_func(const uint64_t *mp, const uint64_t *kp, size_t nw, uint64_t *rh, uint64_t *rl)
{
	// This assembly version, using MMX registers, is just as fast as the
	// intrinsics version (which uses XMM registers) on the Intel Core 2,
	// but is much faster on the Pentium 4. In order to schedule multiplies
	// as early as possible, the loop interleaves operations for the current
	// block and the next block. To mask out high 32-bits, we use "movd"
	// to move the lower 32-bits to the stack and then back. Surprisingly,
	// this is faster than any other method.
#ifdef __GNUC__
	__asm__ __volatile__
	(
		".intel_syntax noprefix;"
#else
		AS2(	mov		esi, mp)
		AS2(	mov		edi, kp)
		AS2(	mov		ecx, nw)
		AS2(	mov		eax, rl)
		AS2(	mov		edx, rh)
#endif
		AS2(	sub		esp, 12)
		AS2(	movq	mm6, [esi])
		AS2(	paddq	mm6, [edi])
		AS2(	movq	mm5, [esi+8])
		AS2(	paddq	mm5, [edi+8])
		AS2(	add		esi, 16)
		AS2(	add		edi, 16)
		AS2(	movq	mm4, mm6)
		ASS(	pshufw	mm2, mm6, 1, 0, 3, 2)
		AS2(	pmuludq	mm6, mm5)
		ASS(	pshufw	mm3, mm5, 1, 0, 3, 2)
		AS2(	pmuludq	mm5, mm2)
		AS2(	pmuludq	mm2, mm3)
		AS2(	pmuludq	mm3, mm4)
		AS2(	pxor	mm7, mm7)
		AS2(	movd	[esp], mm6)
		AS2(	psrlq	mm6, 32)
		AS2(	movd	[esp+4], mm5)
		AS2(	psrlq	mm5, 32)
		AS2(	sub		ecx, 2)
		ASJ(	jz,		1, f)
		ASL(0)
		AS2(	movq	mm0, [esi])
		AS2(	paddq	mm0, [edi])
		AS2(	movq	mm1, [esi+8])
		AS2(	paddq	mm1, [edi+8])
		AS2(	add		esi, 16)
		AS2(	add		edi, 16)
		AS2(	movq	mm4, mm0)
		AS2(	paddq	mm5, mm2)
		ASS(	pshufw	mm2, mm0, 1, 0, 3, 2)
		AS2(	pmuludq	mm0, mm1)
		AS2(	movd	[esp+8], mm3)
		AS2(	psrlq	mm3, 32)
		AS2(	paddq	mm5, mm3)
		ASS(	pshufw	mm3, mm1, 1, 0, 3, 2)
		AS2(	pmuludq	mm1, mm2)
		AS2(	pmuludq	mm2, mm3)
		AS2(	pmuludq	mm3, mm4)
		AS2(	movd	mm4, [esp])
		AS2(	paddq	mm7, mm4)
		AS2(	movd	mm4, [esp+4])
		AS2(	paddq	mm6, mm4)
		AS2(	movd	mm4, [esp+8])
		AS2(	paddq	mm6, mm4)
		AS2(	movd	[esp], mm0)
		AS2(	psrlq	mm0, 32)
		AS2(	paddq	mm6, mm0)
		AS2(	movd	[esp+4], mm1)
		AS2(	psrlq	mm1, 32)
		AS2(	paddq	mm5, mm1)
		AS2(	sub		ecx, 2)
		ASJ(	jnz,	0, b)
		ASL(1)
		AS2(	paddq	mm5, mm2)
		AS2(	movd	[esp+8], mm3)
		AS2(	psrlq	mm3, 32)
		AS2(	paddq	mm5, mm3)
		AS2(	movd	mm4, [esp])
		AS2(	paddq	mm7, mm4)
		AS2(	movd	mm4, [esp+4])
		AS2(	paddq	mm6, mm4)
		AS2(	movd	mm4, [esp+8])
		AS2(	paddq	mm6, mm4)

		ASS(	pshufw	mm0, mm7, 3, 2, 1, 0)
		AS2(	psrlq	mm7, 32)
		AS2(	paddq	mm6, mm7)
		AS2(	punpckldq	mm0, mm6)
		AS2(	psrlq	mm6, 32)
		AS2(	paddq	mm5, mm6)
		AS2(	movq	[eax], mm0)
		AS2(	movq	[edx], mm5)
		AS2(	add		esp, 12)
#ifdef __GNUC__
		".att_syntax prefix;"
		:
		: "S" (mp), "D" (kp), "c" (nw), "a" (rl), "d" (rh)
		: "memory", "cc"
	);
#endif
}
#define nh_16(mp, kp, nw, rh, rl)   nh_16_func(mp, kp, nw, &(rh), &(rl));

static void poly_step_func(uint64_t *ahi, uint64_t *alo, const uint64_t *kh,
               const uint64_t *kl, const uint64_t *mh, const uint64_t *ml)
{
	// This code tries to schedule the multiplies as early as possible to overcome
	// the long latencies on the Pentium 4. It also minimizes "movq" instructions
	// which are very expensive on the P4.

#define a0 [eax+0]
#define a1 [eax+4]
#define a2 [ebx+0]
#define a3 [ebx+4]
#define k0 [ecx+0]
#define k1 [ecx+4]
#define k2 [edx+0]
#define k3 [edx+4]

#ifdef __GNUC__
	uint32_t temp;
	__asm__ __volatile__
	(
		"mov %%ebx, %0;"
		"mov %1, %%ebx;"
		".intel_syntax noprefix;"
#else
		AS2(	mov		ebx, ahi)
		AS2(	mov		edx, kh)
		AS2(	mov		eax, alo)
		AS2(	mov		ecx, kl)
		AS2(	mov		esi, mh)
		AS2(	mov		edi, ml)
#endif

		AS2(	movd	mm0, a3)
		AS2(	movq	mm4, mm0)
		AS2(	pmuludq	mm0, k3)		// a3*k3
		AS2(	movd	mm1, a0)
		AS2(	pmuludq	mm1, k2)		// a0*k2
		AS2(	movd	mm2, a1)
		AS2(	movd	mm6, k1)
		AS2(	pmuludq	mm2, mm6)		// a1*k1
		AS2(	movd	mm3, a2)
		AS2(	movq	mm5, mm3)
		AS2(	movd	mm7, k0)
		AS2(	pmuludq	mm3, mm7)		// a2*k0
		AS2(	pmuludq	mm4, mm7)		// a3*k0
		AS2(	pmuludq	mm5, mm6)		// a2*k1
		AS2(	psllq	mm0, 1)
		AS2(	paddq	mm0, [esi])
		AS2(	paddq	mm0, mm1)
		AS2(	movd	mm1, a1)
		AS2(	paddq	mm4, mm5)
		AS2(	movq	mm5, mm1)
		AS2(	pmuludq	mm1, k2)		// a1*k2
		AS2(	paddq	mm0, mm2)
		AS2(	movd	mm2, a0)
		AS2(	paddq	mm0, mm3)
		AS2(	movq	mm3, mm2)
		AS2(	pmuludq	mm2, k3)		// a0*k3
		AS2(	pmuludq	mm3, mm7)		// a0*k0
		AS2(	movd	esi, mm0)
		AS2(	psrlq	mm0, 32)
		AS2(	pmuludq	mm7, mm5)		// a1*k0
		AS2(	pmuludq	mm5, k3)		// a1*k3
		AS2(	paddq	mm0, mm1)
		AS2(	movd	mm1, a2)
		AS2(	pmuludq	mm1, k2)		// a2*k2
		AS2(	paddq	mm0, mm2)
		AS2(	paddq	mm0, mm4)
		AS2(	movq	mm4, mm0)
		AS2(	movd	mm2, a3)
		AS2(	pmuludq	mm2, mm6)		// a3*k1
		AS2(	pmuludq	mm6, a0)		// a0*k1
		AS2(	psrlq	mm0, 31)
		AS2(	paddq	mm0, mm3)
		AS2(	movd	mm3, [edi])
		AS2(	paddq	mm0, mm3)
		AS2(	movd	mm3, a2)
		AS2(	pmuludq	mm3, k3)		// a2*k3
		AS2(	paddq	mm5, mm1)
		AS2(	movd	mm1, a3)
		AS2(	pmuludq	mm1, k2)		// a3*k2
		AS2(	paddq	mm5, mm2)
		AS2(	movd	mm2, [edi+4])
		AS2(	psllq	mm5, 1)
		AS2(	paddq	mm0, mm5)
		AS2(	movq	mm5, mm0)
		AS2(	psllq	mm4, 33)
		AS2(	psrlq	mm0, 32)
		AS2(	paddq	mm6, mm7)
		AS2(	movd	mm7, esi)
		AS2(	paddq	mm0, mm6)
		AS2(	paddq	mm0, mm2)
		AS2(	paddq	mm3, mm1)
		AS2(	psllq	mm3, 1)
		AS2(	paddq	mm0, mm3)
		AS2(	psrlq	mm4, 1)
		AS2(	punpckldq	mm5, mm0)
		AS2(	psrlq	mm0, 32)
		AS2(	por		mm4, mm7)
		AS2(	paddq	mm0, mm4)
		AS2(	movq	a0, mm5)
		AS2(	movq	a2, mm0)
#ifdef __GNUC__
		".att_syntax prefix;"
		"mov %0, %%ebx;"
		: "=m" (temp)
		: "m" (ahi), "D" (ml), "d" (kh), "a" (alo), "S" (mh), "c" (kl)
		: "memory", "cc"
	);
#endif


#undef a0
#undef a1
#undef a2
#undef a3
#undef k0
#undef k1
#undef k2
#undef k3
}

#define poly_step(ah, al, kh, kl, mh, ml)   \
        poly_step_func(&(ah), &(al), &(kh), &(kl), &(mh), &(ml))

/* ----------------------------------------------------------------------- */
#else /* not UVMAC_ARCH_64 and not SSE2 */
/* ----------------------------------------------------------------------- */

#ifndef nh_16
#define nh_16(mp, kp, nw, rh, rl)                                       \
{   uint64_t t1,t2,m1,m2,t;                                             \
    int i;                                                              \
    rh = rl = t = 0;                                                    \
    for (i = 0; i < nw; i+=2)  {                                        \
        t1  = get64PE(mp+i) + kp[i];                                    \
        t2  = get64PE(mp+i+1) + kp[i+1];                                \
        m2  = MUL32(t1 >> 32, t2);                                      \
        m1  = MUL32(t1, t2 >> 32);                                      \
        ADD128(rh,rl,MUL32(t1 >> 32,t2 >> 32),MUL32(t1,t2));            \
        rh += (uint64_t)(uint32_t)(m1 >> 32) + (uint32_t)(m2 >> 32);    \
        t  += (uint64_t)(uint32_t)m1 + (uint32_t)m2;                    \
    }                                                                   \
    ADD128(rh,rl,(t >> 32),(t << 32));                                  \
}
#endif

static void poly_step_func(uint64_t *ahi, uint64_t *alo, const uint64_t *kh,
               const uint64_t *kl, const uint64_t *mh, const uint64_t *ml)
{

#if UVMAC_ARCH_BIG_ENDIAN
#define INDEX_HIGH 0
#define INDEX_LOW 1
#else
#define INDEX_HIGH 1
#define INDEX_LOW 0
#endif

#define a0 *(((uint32_t*)alo)+INDEX_LOW)
#define a1 *(((uint32_t*)alo)+INDEX_HIGH)
#define a2 *(((uint32_t*)ahi)+INDEX_LOW)
#define a3 *(((uint32_t*)ahi)+INDEX_HIGH)
#define k0 *(((uint32_t*)kl)+INDEX_LOW)
#define k1 *(((uint32_t*)kl)+INDEX_HIGH)
#define k2 *(((uint32_t*)kh)+INDEX_LOW)
#define k3 *(((uint32_t*)kh)+INDEX_HIGH)

    uint64_t p, q, t;
    uint32_t t2;

    p = MUL32(a3, k3);
    p += p;
    p += *(uint64_t *)mh;
    p += MUL32(a0, k2);
    p += MUL32(a1, k1);
    p += MUL32(a2, k0);
    t = (uint32_t)(p);
    p >>= 32;
    p += MUL32(a0, k3);
    p += MUL32(a1, k2);
    p += MUL32(a2, k1);
    p += MUL32(a3, k0);
    t |= ((uint64_t)((uint32_t)p & 0x7fffffff)) << 32;
    p >>= 31;
    p += (uint64_t)(((uint32_t*)ml)[INDEX_LOW]);
    p += MUL32(a0, k0);
    q =  MUL32(a1, k3);
    q += MUL32(a2, k2);
    q += MUL32(a3, k1);
    q += q;
    p += q;
    t2 = (uint32_t)(p);
    p >>= 32;
    p += (uint64_t)(((uint32_t*)ml)[INDEX_HIGH]);
    p += MUL32(a0, k1);
    p += MUL32(a1, k0);
    q =  MUL32(a2, k3);
    q += MUL32(a3, k2);
    q += q;
    p += q;
    *(uint64_t *)(alo) = (p << 32) | t2;
    p >>= 32;
    *(uint64_t *)(ahi) = p + t;

#undef a0
#undef a1
#undef a2
#undef a3
#undef k0
#undef k1
#undef k2
#undef k3
}

#define poly_step(ah, al, kh, kl, mh, ml)   \
        poly_step_func(&(ah), &(al), &(kh), &(kl), &(mh), &(ml))

/* ----------------------------------------------------------------------- */
#endif  /* end of specialized NH and poly definitions */
/* ----------------------------------------------------------------------- */

/* At least nh_16 is defined. Defined others as needed  here               */
#ifndef nh_16_2
#define nh_16_2(mp, kp, nw, rh, rl, rh2, rl2)                           \
    nh_16(mp, kp, nw, rh, rl);                                          \
    nh_16(mp, ((kp)+2), nw, rh2, rl2);
#endif
#ifndef nh_vhash_nhbytes
#define nh_vhash_nhbytes(mp, kp, nw, rh, rl)                             \
    nh_16(mp, kp, nw, rh, rl)
#endif
#ifndef nh_vhash_nhbytes_2
#define nh_vhash_nhbytes_2(mp, kp, nw, rh, rl, rh2, rl2)                 \
    nh_vhash_nhbytes(mp, kp, nw, rh, rl);                                \
    nh_vhash_nhbytes(mp, ((kp)+2), nw, rh2, rl2);
#endif

/* ----------------------------------------------------------------------- */

void vhash_abort(uvmax_ctx_t *ctx)
{
    ctx->polytmp[0] = ctx->polykey[0] ;
    ctx->polytmp[1] = ctx->polykey[1] ;
#if (UVMAC_TAG_LEN == 128)
    ctx->polytmp[2] = ctx->polykey[2] ;
    ctx->polytmp[3] = ctx->polykey[3] ;
#endif
    ctx->first_block_processed = 0;
}

/* ----------------------------------------------------------------------- */
static uint64_t l3hash(uint64_t p1, uint64_t p2,
                       uint64_t k1, uint64_t k2, uint64_t len)
{
    uint64_t rh, rl, t, z=0;

    /* fully reduce (p1,p2)+(len,0) mod p127 */
    t = p1 >> 63;
    p1 &= m63;
    ADD128(p1, p2, len, t);
    /* At this point, (p1,p2) is at most 2^127+(len<<64) */
    t = (p1 > m63) + ((p1 == m63) && (p2 == m64));
    ADD128(p1, p2, z, t);
    p1 &= m63;

    /* compute (p1,p2)/(2^64-2^32) and (p1,p2)%(2^64-2^32) */
    t = p1 + (p2 >> 32);
    t += (t >> 32);
    t += (uint32_t)t > 0xfffffffeu;
    p1 += (t >> 32);
    p2 += (p1 << 32);

    /* compute (p1+k1)%p64 and (p2+k2)%p64 */
    p1 += k1;
    p1 += (0 - (p1 < k1)) & 257;
    p2 += k2;
    p2 += (0 - (p2 < k2)) & 257;

    /* compute (p1+k1)*(p2+k2)%p64 */
    MUL64(rh, rl, p1, p2);
    t = rh >> 56;
    ADD128(t, rl, z, rh);
    rh <<= 8;
    ADD128(t, rl, z, rh);
    t += t << 8;
    rl += t;
    rl += (0 - (rl < t)) & 257;
    rl += (0 - (rl > p64-1)) & 257;
    return rl;
}

/* ----------------------------------------------------------------------- */

void vhash_update(unsigned char *m,
                  unsigned int   mbytes, /* Pos multiple of UVMAC_NHBYTES */
                  uvmax_ctx_t    *ctx)
{
    uint64_t rh, rl, *mptr;
    const uint64_t *kptr = (uint64_t *)ctx->nhkey;
    int i;
    uint64_t ch, cl;
    uint64_t pkh = ctx->polykey[0];
    uint64_t pkl = ctx->polykey[1];
#if (UVMAC_TAG_LEN == 128)
    uint64_t ch2, cl2, rh2, rl2;
    uint64_t pkh2 = ctx->polykey[2];
    uint64_t pkl2 = ctx->polykey[3];
#endif

    mptr = (uint64_t *)m;
    i = mbytes / UVMAC_NHBYTES;  /* Must be non-zero */

    ch = ctx->polytmp[0];
    cl = ctx->polytmp[1];
#if (UVMAC_TAG_LEN == 128)
    ch2 = ctx->polytmp[2];
    cl2 = ctx->polytmp[3];
#endif

    if ( ! ctx->first_block_processed) {
        ctx->first_block_processed = 1;
#if (UVMAC_TAG_LEN == 64)
        nh_vhash_nhbytes(mptr,kptr,UVMAC_NHBYTES/8,rh,rl);
#else
        nh_vhash_nhbytes_2(mptr,kptr,UVMAC_NHBYTES/8,rh,rl,rh2,rl2);
        rh2 &= m62;
        ADD128(ch2,cl2,rh2,rl2);
#endif
        rh &= m62;
        ADD128(ch,cl,rh,rl);
        mptr += (UVMAC_NHBYTES/sizeof(uint64_t));
        i--;
    }

    while (i--) {
#if (UVMAC_TAG_LEN == 64)
        nh_vhash_nhbytes(mptr,kptr,UVMAC_NHBYTES/8,rh,rl);
#else
        nh_vhash_nhbytes_2(mptr,kptr,UVMAC_NHBYTES/8,rh,rl,rh2,rl2);
        rh2 &= m62;
        poly_step(ch2,cl2,pkh2,pkl2,rh2,rl2);
#endif
        rh &= m62;
        poly_step(ch,cl,pkh,pkl,rh,rl);
        mptr += (UVMAC_NHBYTES/sizeof(uint64_t));
    }

    ctx->polytmp[0] = ch;
    ctx->polytmp[1] = cl;
#if (UVMAC_TAG_LEN == 128)
    ctx->polytmp[2] = ch2;
    ctx->polytmp[3] = cl2;
#endif
#if UVMAC_USE_SSE2
    _mm_empty(); /* SSE2 version of poly_step uses mmx instructions */
#endif
}

/* ----------------------------------------------------------------------- */

uint64_t xvhash(unsigned char m[],
                unsigned int mbytes,
                uint64_t *tagl,
                uvmax_ctx_t *ctx)
{
    uint64_t ch, cl, rh, rl, *mptr;
#if (UVMAC_TAG_LEN == 128)
    uint64_t ch2, cl2, rh2, rl2;
#endif
    const uint64_t *kptr = (uint64_t *)ctx->nhkey;
    int i, remaining;

    remaining = mbytes % UVMAC_NHBYTES;
    i = mbytes-remaining;
    mptr = (uint64_t *)(m+i);
    if (i) vhash_update(m,i,ctx);

    ch = ctx->polytmp[0];
    cl = ctx->polytmp[1];
#if (UVMAC_TAG_LEN == 128)
    ch2 = ctx->polytmp[2];
    cl2 = ctx->polytmp[3];
#endif

    if (remaining) {
#if (UVMAC_TAG_LEN == 128)
        nh_16_2(mptr,kptr,2*((remaining+15)/16),rh,rl,rh2,rl2);
        rh2 &= m62;
#else
        nh_16(mptr,kptr,2*((remaining+15)/16),rh,rl);
#endif
        rh &= m62;
        if (i) {
            poly_step(ch,cl,ctx->polykey[0],ctx->polykey[1],rh,rl);
#if (UVMAC_TAG_LEN == 128)
            poly_step(ch2,cl2,ctx->polykey[2],ctx->polykey[3],rh2,rl2);
#endif
        } else {
            ADD128(ch,cl,rh,rl);
#if (UVMAC_TAG_LEN == 128)
            ADD128(ch2,cl2,rh2,rl2);
#endif
        }
    }

#if UVMAC_USE_SSE2
    _mm_empty(); /* SSE2 version of poly_step uses mmx instructions */
#endif
    vhash_abort(ctx);
    remaining *= 8;
#if (UVMAC_TAG_LEN == 128)
    *tagl = l3hash(ch2, cl2, ctx->l3key[2], ctx->l3key[3],remaining);
#endif
    return l3hash(ch, cl, ctx->l3key[0], ctx->l3key[1],remaining);
}

uint64_t vhash(unsigned char m[],
               unsigned int mbytes,
               uint64_t *tagl,
               uvmax_ctx_t *ctx)
{
    uint64_t rh, rl, *mptr;
    const uint64_t *kptr = (uint64_t *)ctx->nhkey;
    int i, remaining;
    uint64_t ch, cl;
    uint64_t pkh = ctx->polykey[0];
    uint64_t pkl = ctx->polykey[1];
#if (UVMAC_TAG_LEN == 128)
    uint64_t ch2, cl2, rh2, rl2;
        uint64_t pkh2 = ctx->polykey[2];
        uint64_t pkl2 = ctx->polykey[3];
#endif

    mptr = (uint64_t *)m;
    i = mbytes / UVMAC_NHBYTES;
    remaining = mbytes % UVMAC_NHBYTES;

    if (ctx->first_block_processed)
    {
        ch = ctx->polytmp[0];
        cl = ctx->polytmp[1];
#if (UVMAC_TAG_LEN == 128)
        ch2 = ctx->polytmp[2];
        cl2 = ctx->polytmp[3];
#endif
    }
    else if (i)
    {
#if (UVMAC_TAG_LEN == 64)
        nh_vhash_nhbytes(mptr,kptr,UVMAC_NHBYTES/8,ch,cl);
#else
        nh_vhash_nhbytes_2(mptr,kptr,UVMAC_NHBYTES/8,ch,cl,ch2,cl2);
        ch2 &= m62;
        ADD128(ch2,cl2,pkh2,pkl2);
#endif
        ch &= m62;
        ADD128(ch,cl,pkh,pkl);
        mptr += (UVMAC_NHBYTES/sizeof(uint64_t));
        i--;
    }
    else if (remaining)
    {
#if (UVMAC_TAG_LEN == 64)
        nh_16(mptr,kptr,2*((remaining+15)/16),ch,cl);
#else
        nh_16_2(mptr,kptr,2*((remaining+15)/16),ch,cl,ch2,cl2);
        ch2 &= m62;
        ADD128(ch2,cl2,pkh2,pkl2);
#endif
        ch &= m62;
        ADD128(ch,cl,pkh,pkl);
        mptr += (UVMAC_NHBYTES/sizeof(uint64_t));
        goto do_l3;
    }
    else /* Empty String */
    {
        ch = pkh; cl = pkl;
#if (UVMAC_TAG_LEN == 128)
        ch2 = pkh2; cl2 = pkl2;
#endif
        goto do_l3;
    }

    while (i--) {
#if (UVMAC_TAG_LEN == 64)
        nh_vhash_nhbytes(mptr,kptr,UVMAC_NHBYTES/8,rh,rl);
#else
        nh_vhash_nhbytes_2(mptr,kptr,UVMAC_NHBYTES/8,rh,rl,rh2,rl2);
        rh2 &= m62;
        poly_step(ch2,cl2,pkh2,pkl2,rh2,rl2);
#endif
        rh &= m62;
        poly_step(ch,cl,pkh,pkl,rh,rl);
        mptr += (UVMAC_NHBYTES/sizeof(uint64_t));
    }
    if (remaining) {
#if (UVMAC_TAG_LEN == 64)
        nh_16(mptr,kptr,2*((remaining+15)/16),rh,rl);
#else
        nh_16_2(mptr,kptr,2*((remaining+15)/16),rh,rl,rh2,rl2);
        rh2 &= m62;
        poly_step(ch2,cl2,pkh2,pkl2,rh2,rl2);
#endif
        rh &= m62;
        poly_step(ch,cl,pkh,pkl,rh,rl);
    }

    do_l3:
#if UVMAC_USE_SSE2
    _mm_empty(); /* SSE2 version of poly_step uses mmx instructions */
#endif
    vhash_abort(ctx);
    remaining *= 8;
#if (UVMAC_TAG_LEN == 128)
    *tagl = l3hash(ch2, cl2, ctx->l3key[2], ctx->l3key[3],remaining);
#endif
    return l3hash(ch, cl, ctx->l3key[0], ctx->l3key[1],remaining);
}

/* ----------------------------------------------------------------------- */

uint64_t uvmac(unsigned char m[],
               unsigned int mbytes,
               uint64_t *tagl,
               uvmax_ctx_t *ctx,
               uint64_t* consumable_key,
               const uint64_t consumable_key_length,
               uint64_t* consumable_key_position)
{
#if (UVMAC_TAG_LEN == 64)
    uint64_t *out_p;
    uint64_t p, h;
    out_p = get64bitsOfKey(consumable_key, consumable_key_length, consumable_key_position);
    p = get64BE(out_p);
    h = vhash(m, mbytes, (uint64_t *)0, ctx);
    return p + h;
#else
    uint64_t *out_p;
    uint64_t th,tl;
    out_p = get64bitsOfKey(consumable_key, consumable_key_length, consumable_key_position);
    th = vhash(m, mbytes, &tl, ctx);
    th += get64BE(out_p);
    out_p = get64bitsOfKey(consumable_key, consumable_key_length, consumable_key_position);
    *tagl = tl + get64BE(out_p);
    return th;
#endif
}

/* ----------------------------------------------------------------------- */

void uvmac_set_key(unsigned char user_key[], const uint32_t key_length, uvmax_ctx_t *ctx)
{
    uint64_t *out;
    unsigned i;

    uint64_t key_position = 0;

    /* Fill nh key */
    for (i = 0; i < sizeof(ctx->nhkey)/8; i++) {
        out = get64bitsOfKey((uint64_t*) user_key, key_length, &key_position);
        ctx->nhkey[i  ] = get64BE(out);
    }

    /* Fill poly key */
    for (i = 0; i < sizeof(ctx->polykey)/8; i++) {
        out = get64bitsOfKey((uint64_t*) user_key, key_length, &key_position);
        ctx->polytmp[i  ] = ctx->polykey[i  ] = get64BE(out) & mpoly;
    }

    /* Fill ip key */
    for (i = 0; i < sizeof(ctx->l3key)/8; i++) {
        do {
            out = get64bitsOfKey((uint64_t*) user_key, key_length, &key_position);
            ctx->l3key[i  ] = get64BE(out);
        } while (ctx->l3key[i] >= p64);
    }

    /* Reset other elements */
    ctx->first_block_processed = 0;
}

/* ----------------------------------------------------------------------- */

uint64_t* get64bitsOfKey(uint64_t* consumable_key, const uint64_t key_length, uint64_t* key_position)
{
    if ((*key_position) + 1 > key_length)
    {
        printf("Error: All available key has been used already, no fresh key available anymore.\n");
        assert(0);
    }
    // We return a pointer to the next two 64-bit registers of the key
    uint64_t *out = consumable_key + (*key_position);
    // ... and increment the position
    (*key_position) = (*key_position) + 1;
//    printf("At position %lu out of %lu\n", (*key_position), key_length);
    return out;
}

/* ----------------------------------------------------------------------- */

#if UVMAC_RUN_TESTS

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

unsigned prime(void)  /* Wake variable speed cpu, get rough speed estimate */
{
    volatile uint64_t i;
    volatile uint64_t j=1;
    unsigned cnt=0;
    volatile clock_t ticks = clock();
    do {
        for (i = 0; i < 500000; i++) {
            uint64_t x = get64PE(&j);
            j = x * x + (uint64_t)ticks;
        }
        cnt++;
    } while (clock() - ticks < (CLOCKS_PER_SEC/2));
    return cnt;  /* cnt is millions of iterations per second */
}

int main(void)
{
    ALIGN(16) uvmax_ctx_t ctx;
    uint64_t res, tagl;
    void *p;
    unsigned char *m;
#if (UVMAC_TAG_LEN == 64)
    ALIGN(4) unsigned char key[] = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";
    uint64_t key_length = 20;
#else
    ALIGN(4) unsigned char key[] = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";
    uint64_t key_length = 26;
#endif
    unsigned int  vector_lengths[] = {0,3,48,300,3000000};
#if (UVMAC_TAG_LEN == 64)
    ALIGN(4) char *should_be[] = {"8124D03C89C8B774","1E59621DEA8080AA",
                                  "C92F7FC29A334AF6","FC48C8853C7E9CAB",
                                  "70CC2C64273263C4"};
#else
    ALIGN(4) char *should_be[] = {"8124D03C89C8B7748124D03C89C8B774",
                         "1E59621DEA8080AA1E59621DEA8080AA",
                         "C92F7FC29A334AF6C92F7FC29A334AF6",
                         "FC48C8853C7E9CABFC48C8853C7E9CAB",
                         "70CC2C64273263C470CC2C64273263C4"};
#endif
    unsigned speed_lengths[] = {16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
    unsigned i, j, *speed_iters;
    clock_t ticks;
    double cpb;
    const unsigned int buf_len = 3 * (1 << 20);

    j = prime();
    i = sizeof(speed_lengths)/sizeof(speed_lengths[0]);
    speed_iters = (unsigned *)malloc(i*sizeof(speed_iters[0]));
    speed_iters[i-1] = j * (1 << 12);
    while (--i) speed_iters[i-1] = (unsigned)(1.3 * speed_iters[i]);

    /* Initialize context and message buffer, all 16-byte aligned */
    p = malloc(buf_len + 32);
    m = (unsigned char *)(((size_t)p + 16) & ~((size_t)15));
    memset(m, 0, buf_len + 16);
    uvmac_set_key(key, key_length, &ctx);

    /* Initialize running key used for one-time-pad */
    ALIGN(4) unsigned char running_key_data[] = "abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh";
    uint64_t *running_key = (uint64_t*) &running_key_data;
    uint64_t running_key_length = 20; // Enough for 20 64-bits tags or 10 128-bits ones, but for test purposes we repeatedly use the same key
    uint64_t running_key_position = 0;


    /* Generate vectors */
    for (i = 0; i < sizeof(vector_lengths)/sizeof(unsigned int); i++) {
        for (j = 0; j < vector_lengths[i]; j++)
            m[j] = (unsigned char)('a'+j%3);
        res = uvmac(m, vector_lengths[i], &tagl, &ctx, running_key, running_key_length, &running_key_position);
#if (UVMAC_TAG_LEN == 64)
        printf("\'abc\' * %7u: %016lX Should be: %s\n",
               vector_lengths[i]/3,res,should_be[i]);
#else
        printf("\'abc\' * %7u: %016lX%016lX\nShould be      : %s\n",
              vector_lengths[i]/3,res,tagl,should_be[i]);
#endif

        // Do it again, but with vhash_update
        if (vector_lengths[i] > UVMAC_NHBYTES) {
            long unsigned int firstPart = (vector_lengths[i]/UVMAC_NHBYTES)*UVMAC_NHBYTES;
            vhash_update(m, firstPart, &ctx);
            res = uvmac(m+firstPart, vector_lengths[i]-firstPart, &tagl, &ctx, running_key, running_key_length, &running_key_position);
#if (UVMAC_TAG_LEN == 64)
            printf("\'abc\' * %7u: %016lX Should be: %s - computed in two parts: %lu+%lu\n",
                   vector_lengths[i] / 3, res, should_be[i], firstPart, vector_lengths[i]-firstPart);
#else
            printf("\'abc\' * %7u: %016lX%016lX\nShould be      : %s - computed in two parts: %lu+%lu\n",
                  vector_lengths[i]/3,res,tagl,should_be[i],firstPart,vector_lengths[i]-firstPart);
#endif
        }
    }

    /* Speed test */
    for (i = 0; i < sizeof(speed_lengths)/sizeof(unsigned int); i++) {
        ticks = clock();
        for (j = 0; j < speed_iters[i]; j++) {
#if HASH_ONLY
            res = vhash(m, speed_lengths[i], &tagl, &ctx);
#else
            res = uvmac(m, speed_lengths[i], &tagl, &ctx, running_key, running_key_length, &running_key_position);
            running_key_position = 0;
#endif
        }
        ticks = clock() - ticks;
        cpb = ((ticks*UVMAC_HZ)/
               ((double)CLOCKS_PER_SEC*speed_lengths[i]*speed_iters[i]));
        printf("%4u bytes, %2.2f cpb\n", speed_lengths[i], cpb);
    }
    return 1;
}

#endif
