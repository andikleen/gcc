#ifndef RAPIDHASH_H
#define RAPIDHASH_H 1

#include <string.h>

/* Rapid hash. Originally from Nicolas de Carli And Wang Yi. This hash
   is optimized for 64bit hosts, and prefers hosts that support a
   64x64->128 multiply.  */

namespace rapidhash
{

constexpr uint64_t default_seed = 0xbdd89aa982704029ull;

inline void mum(uint64_t &a, uint64_t &b)
{
#ifdef __SIZEOF_INT128__
  __uint128_t r = a;
  r *= b;
  a = (uint64_t)r;
  b = (uint64_t)(r >> 64);
#else
  uint64_t ha = a >> 32;
  uint64_t hb = b >> 32;
  uint64_t la = (uint32_t)a;
  uint64_t lb = (uint32_t)b;
  uint64_t rh = ha*hb;
  uint64_t rm0 = ha * lb;
  uint64_t rm1 = hb * la;
  uint64_t rl = la * lb;
  uint64_t t = rl + (rm0 << 32);
  uint64_t c = t < rl;
  uint64_t lo = t + (rm1 << 32);
  c += lo < t;
  uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
  a = lo;
  b = hi;
#endif
}

inline uint64_t mix(uint64_t a, uint64_t b)
{
  mum (a, b);
  return a ^ b;
}

inline uint64_t read64(const uint8_t *p)
{
  uint64_t v;
  memcpy (&v, p, 8);
  return v;
}

inline uint64_t read32(const uint8_t *p)
{
  uint32_t v;
  memcpy (&v, p, 4);
  return v;
}

constexpr uint64_t rapid_seed[3] =
  {
    0x2d358dccaa6c78a5ull,
    0x8bb84b93962eacc9ull,
    0x4b33a62ed433d4a3ull
  };

inline uint64_t hash(const void *buf, size_t len, uint64_t seed)
{
  const uint8_t *p = (const uint8_t *)buf;
  uint64_t a, b;
  seed ^= mix (seed ^ rapid_seed[0], rapid_seed[1]) ^ len;
  if (len <= 16)
    {
      if (len >= 4)
	{
	  const uint8_t *plast = p + len - 4;
	  a = (read32 (p) << 32) | read32 (plast);
	  const uint64_t delta = (len & 24) >> (len>>3);
	  b = (read32 (p + delta) << 32) | read32 (plast - delta);
	}
      else
	{
	  a = 0;
	  memcpy (&a, p, len);
	  b = 0;
	}
    }
  else
    {
      size_t i = len;
      if (i > 48)
	{
	  uint64_t see1 = seed;
	  uint64_t see2 = seed;
	  do
	    {
	      seed = mix (read64 (p) ^ rapid_seed[0],
			  read64 (p + 8) ^ seed);
	      see1 = mix (read64 (p + 16) ^ rapid_seed[1],
				read64 (p + 24) ^ see1);
	      see2 = mix (read64 (p + 32) ^ rapid_seed[2],
				read64 (p + 40) ^ see2);
	      p += 48;
	      i -= 48;
	    } while (i >= 48);
	  seed ^= see1 ^ see2;
	}
      if (i > 16)
	{
	  seed = mix (read64 (p) ^ rapid_seed[2],
		      read64 (p + 8) ^ seed ^ rapid_seed[1]);
	  if (i > 32)
	    seed = mix (read64 (p + 16) ^ rapid_seed[2],
			      read64 (p + 24) ^ seed);
	}
      a = read64 (p + i - 16);
      b = read64 (p + i - 8);
    }
  a ^= rapid_seed[1];
  b ^= seed;
  mum (a, b);
  return mix (a ^ rapid_seed[0] ^ len, b ^ rapid_seed[1]);
}

inline uint64_t merge(uint64_t seed, uint64_t other)
{
  seed ^= mix (seed ^ rapid_seed[0], rapid_seed[1]);
  uint64_t a = other ^ rapid_seed[1];
  uint64_t b = seed;
  return mix (a ^ rapid_seed[0], b ^ rapid_seed[1]);
}

typedef uint64_t hashval_t;

} /* rapid */

#endif
