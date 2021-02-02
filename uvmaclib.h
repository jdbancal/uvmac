#ifndef HEADER_UVMAC_H
#define HEADER_UVMAC_H

/* --------------------------------------------------------------------------
 * UVMAC computes unconditionally secure Message Authentication Codes by
 * combining the VHASH implemented by Ted Krovetz (tdk@acm.org) and Wei Dai
 * toghether with one-time pad encryption. It therefore does not rely on AES or
 * another cryptographic primitive with a security relying on computational
 * hardness.
 * VHASH is (2^(-61))-almost-delta-universal for all messages of length up to
 * 2^63 bits.
 * This adaptation is proposed by Jean-Daniel Bancal. It is herby placed in the
 * public domain. The authors offers no warranty. Use at your own risk.
 * Please send bug reports to the authors.
 * Last modified: 02 FEB 21, 1500 GMT
 * ----------------------------------------------------------------------- */

/* --------------------------------------------------------------------------
 * User definable settings.
 * ----------------------------------------------------------------------- */
#define UVMAC_TAG_LEN   64 /* Must be 64 or 128 - 64 sufficient for most    */
#define UVMAC_NHBYTES  128 /* Must 2^i for any 3 < i < 13. Standard = 128   */
#define UVMAC_PREFER_BIG_ENDIAN  0  /* Prefer non-x86 */

#define UVMAC_RUN_TESTS 0  /* Set to non-zero to check vectors and speed    */
#define UVMAC_HZ (448e6)  /* Set to hz of host machine to get speed        */
#define UVMAC_HASH_ONLY 0  /* Set to non-zero to time hash only (not-mac)   */
/* Speeds of cpus I have access to
#define hz (2400e6)  glyme Core 2 "Conroe"
#define hz (2000e6)  jupiter G5
#define hz (1592e6)  titan
#define hz (2793e6)  athena/gaia
#define hz (1250e6)  isis G4
#define hz (2160e6)  imac Core 2 "Merom"
#define hz (266e6)   ppc/arm
#define hz (400e6)   mips
*/

/* --------------------------------------------------------------------------
 * The following parameter defines the key length required for universal
 * hashing (the same all the time, i.e. this does not include the key needed
 * for encrypting the tag; a new such key of length UVMAC_TAG_LEN is needed
 * for each tag).
 *   Essentially, the requirements are:
 *     1280 bits for 64-bits tags
 *     1664 for 128-bits tags
 * Concretely, a bit less randomness is needed (c.f. ip key section of
 * function uvmac_set_key).
 * ----------------------------------------------------------------------- */
#define UVMAC_KEY_LEN  (UVMAC_NHBYTES/8)+2*(UVMAC_TAG_LEN/64-1)+4*UVMAC_TAG_LEN/64 /* in units of 64 bits */


/* --------------------------------------------------------------------------
 * This implementation uses uint32_t and uint64_t as names for unsigned 32-
 * and 64-bit integer types. These are defined in C99 stdint.h. The
 * following may need adaptation if you are not running a C99 or
 * Microsoft C environment.
 * ----------------------------------------------------------------------- */
#define UVMAC_USE_STDINT 1  /* Set to zero if system has no stdint.h        */

#if UVMAC_USE_STDINT && !_MSC_VER /* Try stdint.h if non-Microsoft          */
#ifdef  __cplusplus
#define __STDC_CONSTANT_MACROS
#endif
#include <stdint.h>
#elif (_MSC_VER)                  /* Microsoft C does not have stdint.h    */
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#define UINT64_C(v) v ## UI64
#else                             /* Guess sensibly - may need adaptation  */
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define UINT64_C(v) v ## ULL
#endif

/* --------------------------------------------------------------------- */

typedef struct {
    uint64_t nhkey  [(UVMAC_NHBYTES/8)+2*(UVMAC_TAG_LEN/64-1)];
    uint64_t polykey[2*UVMAC_TAG_LEN/64];
    uint64_t l3key  [2*UVMAC_TAG_LEN/64];
    uint64_t polytmp[2*UVMAC_TAG_LEN/64];
    int first_block_processed;
} uvmax_ctx_t;

/* --------------------------------------------------------------------------
 * Consumable key management
 * key_length and key_positions are in units of 64 bits
 * ----------------------------------------------------------------------- */
uint64_t* get64bitsOfKey(uint64_t* consumable_key, const uint64_t key_length, uint64_t* key_position);

/* --------------------------------------------------------------------- */
#ifdef  __cplusplus
extern "C" {
#endif
/* --------------------------------------------------------------------------
 *                        <<<<< USAGE NOTES >>>>>
 *
 * Given msg m (mbytes in length) and a key
 * this function returns a tag as its output. The tag is returned as
 * a number. When UVMAC_TAG_LEN == 64, the 'return'ed integer is the tag,
 * and *tagl is meaningless. When UVMAC_TAG_LEN == 128 the tag is the
 * number y * 2^64 + *tagl where y is the function's return value.
 * If you want to consider tags to be strings, then you must do so with
 * an agreed upon endian orientation for interoperability, and convert
 * the results appropriately. VHASH hashes m without creating any tag.
 * Consecutive substrings forming a prefix of a message may be passed
 * to vhash_update, with vhash or uvmac being called with the remainder
 * to produce the output.
 *
 * Requirements:
 * - On 32-bit architectures with SSE2 instructions, ctx and m MUST be
 *   begin on 16-byte memory boundaries.
 * - m MUST be your message followed by zeroes to the nearest 16-byte
 *   boundary. If m is a length multiple of 16 bytes, then it is already
 *   at a 16-byte boundary and needs no padding. mbytes should be your
 *   message length without any padding.
 * - An initial key should be provided to initialize the universal hashing
 *   parameters. This key can be reused indefinitely. Another key must be
 *   provided each time a tag is computed. This consumable key can be used only
 *   once (a long enough key can be used in several chunks as controled by the
 *   variable consumable_key_position). This one-time usage key plays the role
 *   of both a nonce and unconditional encryption through one-time-pad.
 * - vhash_update MUST have mbytes be a positive multiple of UVMAC_NHBYTES
 * ----------------------------------------------------------------------- */

#define uvmac_update vhash_update

void vhash_update(unsigned char m[],
                  unsigned int mbytes,
                  uvmax_ctx_t *ctx);

uint64_t uvmac(unsigned char m[],
               unsigned int mbytes,
               uint64_t *tagl,
               uvmax_ctx_t *ctx,
               uint64_t* consumable_key,
               const uint64_t consumable_key_length,
               uint64_t* consumable_key_position);

uint64_t vhash(unsigned char m[],
               unsigned int mbytes,
               uint64_t *tagl,
               uvmax_ctx_t *ctx);

/* --------------------------------------------------------------------------
 * When passed a UVMAC_KEY_LEN bit user_key, this function initialazies ctx.
 * WARNING: the extracted l3key should be smaller than p64 (otherwise additional
 * bits will be extracted from user_key and a length of UVMAC_KEY_LEN will not be
 * sufficient)
 * ----------------------------------------------------------------------- */

void uvmac_set_key(unsigned char user_key[], const uint32_t key_length, uvmax_ctx_t *ctx);

/* --------------------------------------------------------------------------
 * This function aborts current hash and resets ctx, ready for a new message.
 * ----------------------------------------------------------------------- */

void vhash_abort(uvmax_ctx_t *ctx);

/* --------------------------------------------------------------------- */

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_UVMAC_H */
