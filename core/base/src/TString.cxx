// @(#)root/base:$Id$
// Author: Fons Rademakers   04/08/95

/*************************************************************************
 * Copyright (C) 1995-2000, Rene Brun and Fons Rademakers.               *
 * All rights reserved.                                                  *
 *                                                                       *
 * For the licensing terms see $ROOTSYS/LICENSE.                         *
 * For the list of contributors see $ROOTSYS/README/CREDITS.             *
 *************************************************************************/

//////////////////////////////////////////////////////////////////////////
//                                                                      //
// TString                                                              //
//                                                                      //
// Basic string class.                                                  //
//                                                                      //
// Cannot be stored in a TCollection... use TObjString instead.         //
//                                                                      //
// The underlying string is stored as a char* that can be accessed via  //
// TString::Data().                                                     //
// TString provides Short String Optimization (SSO) so that short       //
// strings (<15 on 64-bit and <11 on 32-bit) are contained in the       //
// TString internal data structure without the need for mallocing the   //
// required space.                                                      //
//                                                                      //
// Substring operations are provided by the TSubString class, which     //
// holds a reference to the original string and its data, along with    //
// the offset and length of the substring. To retrieve the substring    //
// as a TString, construct a TString from it, eg:                       //
//   root [0] TString s("hello world")                                  //
//   root [1] TString s2( s(0,5) )                                      //
//   root [2] s2                                                        //
//   (class TString)"hello"                                             //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

#include "RConfig.h"
#include <stdlib.h>
#include <ctype.h>
#include <list>
#include <algorithm>

#include "snprintf.h"
#include "Varargs.h"
#include "TString.h"
#include "TBuffer.h"
#include "TError.h"
#include "Bytes.h"
#include "TClass.h"
#include "TMD5.h"
#include "TObjArray.h"
#include "TObjString.h"
#include "TVirtualMutex.h"
#include "ThreadLocalStorage.h"


#if defined(R__WIN32)
#define strtoull _strtoui64
#endif

#ifdef R__GLOBALSTL
namespace std { using ::list; }
#endif

ClassImp(TString)

// Amount to shift hash values to avoid clustering
const UInt_t kHashShift = 5;

// ------------------------------------------------------------------------
//
// In what follows, fCap is the length of the underlying representation
// vector. Hence, the capacity for a null terminated string held in this
// vector is fCap-1.  The variable fSize is the length of the held
// string, excluding the terminating null.
//
// The algorithms make no assumptions about whether internal strings
// hold embedded nulls. However, they do assume that any string
// passed in as an argument that does not have a length count is null
// terminated and therefore has no embedded nulls.
//
// The internal string is always null terminated.
//
// ------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////////
//                                                                      //
//  TString                                                             //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

//______________________________________________________________________________
TString::TString()
{
   // TString default ctor.

   Zero();
}

//______________________________________________________________________________
TString::TString(Ssiz_t ic)
{
   // Create TString able to contain ic characters.

   Init(ic, 0);
}

//______________________________________________________________________________
TString::TString(const char *cs)
{
   // Create TString and initialize it with string cs.

   if (cs) {
      Ssiz_t n = strlen(cs);
      char *data = Init(n, n);
      memcpy(data, cs, n);
   } else
      Init(0, 0);
}

//______________________________________________________________________________
TString::TString(const std::string &s)
{
   // Create TString and initialize it with string cs.

   Ssiz_t n = s.length();
   char *data = Init(n, n);
   memcpy(data, s.c_str(), n);
}

//______________________________________________________________________________
TString::TString(const char *cs, Ssiz_t n)
{
   // Create TString and initialize it with the first n characters of cs.

   char *data = Init(n, n);
   memcpy(data, cs, n);
}

//______________________________________________________________________________
void TString::InitChar(char c)
{
   // Initialize a string with a single character.

   char *data = Init(1, 1);
   data[0] = c;
}

//______________________________________________________________________________
TString::TString(char c)
{
   // Initialize a string with a single character.

   InitChar(c);
}

//______________________________________________________________________________
TString::TString(char c, Ssiz_t n)
{
   // Initialize the first n locations of a TString with character c.

   char *data = Init(n, n);
   while (n--) data[n] = c;
}

//______________________________________________________________________________
TString::TString(const TString &s)
{
   // Copy constructor.

   if (!s.IsLong())
      fRep.fRaw = s.fRep.fRaw;
   else {
      Ssiz_t n = s.GetLongSize();
      char *data = Init(n, n);
      memcpy(data, s.GetLongPointer(), n);
   }
}

//______________________________________________________________________________
TString::TString(const TSubString& substr)
{
   // Copy a TSubString in a TString.

   Ssiz_t len = substr.IsNull() ? 0 : substr.Length();
   char *data = Init(len, len);
   memcpy(data, substr.Data(), len);
}

//______________________________________________________________________________
TString::TString(const char *a1, Ssiz_t n1, const char *a2, Ssiz_t n2)
{
   // Special constructor to initialize with the concatenation of a1 and a2.

   if (!a1) n1=0;
   if (!a2) n2=0;
   Ssiz_t tot = n1+n2;
   char *data = Init(tot, tot);
   memcpy(data,    a1, n1);
   memcpy(data+n1, a2, n2);
}

//______________________________________________________________________________
TString::~TString()
{
   // Delete a TString.

   UnLink();
}

//______________________________________________________________________________
char *TString::Init(Ssiz_t capacity, Ssiz_t nchar)
{
   // Private member function returning an empty string representation of
   // size capacity and containing nchar characters.

   if (capacity > MaxSize()) {
      Error("TString::Init", "capacity too large (%d, max = %d)", capacity, MaxSize());
      capacity = MaxSize();
      if (nchar > capacity)
         nchar = capacity;
   }

   char *data;
   if (capacity < kMinCap) {
      SetShortSize(nchar);
      data = GetShortPointer();
   } else {
      Ssiz_t cap = Recommend(capacity);
      data = new char[cap+1];
      SetLongCap(cap+1);
      SetLongSize(nchar);
      SetLongPointer(data);
   }
   data[nchar] = 0;  // terminating null

   return data;
}

//______________________________________________________________________________
TString& TString::operator=(char c)
{
   // Assign character c to TString.

   if (!c) {
      UnLink();
      Zero();
      return *this;
   }
   return Replace(0, Length(), &c, 1);
}

//______________________________________________________________________________
TString& TString::operator=(const char *cs)
{
   // Assign string cs to TString.

   if (!cs || !*cs) {
      UnLink();
      Zero();
      return *this;
   }
   return Replace(0, Length(), cs, strlen(cs));
}

//______________________________________________________________________________
TString& TString::operator=(const std::string &s)
{
   // Assign std::string s to TString.

   if (s.length()==0) {
      UnLink();
      Zero();
      return *this;
   }
   return Replace(0, Length(), s.c_str(), s.length());
}

//______________________________________________________________________________
TString& TString::operator=(const TString &rhs)
{
   // Assignment operator.

   if (this != &rhs) {
      UnLink();
      if (!rhs.IsLong())
         fRep.fRaw = rhs.fRep.fRaw;
      else {
         Ssiz_t n = rhs.GetLongSize();
         char *data = Init(n, n);
         memcpy(data, rhs.GetLongPointer(), n);
      }
   }
   return *this;
}

//______________________________________________________________________________
TString& TString::operator=(const TSubString &substr)
{
   // Assign a TSubString substr to TString.

   Ssiz_t len = substr.IsNull() ? 0 : substr.Length();
   if (!len) {
      UnLink();
      Zero();
      return *this;
   }
   return Replace(0, Length(), substr.Data(), len);
}

//______________________________________________________________________________
TString& TString::Append(char c, Ssiz_t rep)
{
   // Append character c rep times to string.

   if (!rep) return *this;

   Ssiz_t len = Length();
   Ssiz_t tot = len + rep;  // Final string length

   if (tot > MaxSize()) {
      Error("TString::Append", "rep too large (%d, max = %d)", rep, MaxSize()-len);
      tot = MaxSize();
      rep = tot - len;
   }

   Ssiz_t capac = Capacity();
   char *data, *p = GetPointer();

   if (capac - tot >= 0) {
      SetSize(tot);
      data = p;
   } else {
      Ssiz_t cap = AdjustCapacity(capac, tot);
      data = new char[cap+1];
      memcpy(data, p, len);
      UnLink();
      SetLongCap(cap+1);
      SetLongSize(tot);
      SetLongPointer(data);
   }
   data[tot] = 0;

   data += len;
   while (rep--)
      *data++ = c;

   return *this;
}

//______________________________________________________________________________
Ssiz_t TString::Capacity(Ssiz_t nc)
{
   // Return string capacity. If nc != current capacity Clone() the string
   // in a string with the desired capacity.

   if (nc > Length())
      Clone(nc);

   return Capacity();
}

//______________________________________________________________________________
int TString::CompareTo(const char *cs2, ECaseCompare cmp) const
{
   // Compare a string to char *cs2. Returns returns zero if the two
   // strings are identical, otherwise returns the difference between
   // the first two differing bytes (treated as unsigned char values,
   // so that `\200' is greater than `\0', for example). Zero-length
   // strings are always identical.

   if (!cs2) return 1;

   const char *cs1 = Data();
   Ssiz_t len = Length();
   Ssiz_t i = 0;
   if (cmp == kExact) {
      for (; cs2[i]; ++i) {
         if (i == len) return -1;
         if (cs1[i] != cs2[i]) return ((cs1[i] > cs2[i]) ? 1 : -1);
      }
   } else {                  // ignore case
      for (; cs2[i]; ++i) {
         if (i == len) return -1;
         char c1 = tolower((unsigned char)cs1[i]);
         char c2 = tolower((unsigned char)cs2[i]);
         if (c1 != c2) return ((c1 > c2) ? 1 : -1);
      }
   }
   return (i < len) ? 1 : 0;
}

//______________________________________________________________________________
int TString::CompareTo(const TString &str, ECaseCompare cmp) const
{
   // Compare a string to another string. Returns returns zero if the two
   // strings are identical, otherwise returns the difference between
   // the first two differing bytes (treated as unsigned char values,
   // so that `\200' is greater than `\0', for example). Zero-length
   // strings are always identical.

   const char *s1 = Data();
   const char *s2 = str.Data();
   Ssiz_t len = Length();
   Ssiz_t slen, sleno = str.Length();
   slen = sleno;
   if (len < slen) slen = len;
   if (cmp == kExact) {
      int result = memcmp(s1, s2, slen);
      if (result != 0) return result;
   } else {
      Ssiz_t i = 0;
      for (; i < slen; ++i) {
         char c1 = tolower((unsigned char)s1[i]);
         char c2 = tolower((unsigned char)s2[i]);
         if (c1 != c2) return ((c1 > c2) ? 1 : -1);
      }
   }
   // strings are equal up to the length of the shorter one.
   slen = sleno;
   if (len == slen) return 0;
   return (len > slen) ? 1 : -1;
}

//______________________________________________________________________________
Int_t TString::CountChar(Int_t c) const
{
   // Return number of times character c occurs in the string.

   Int_t count = 0;
   Int_t len   = Length();
   const char *data  = Data();
   for (Int_t n = 0; n < len; n++)
      if (data[n] == c) count++;

   return count;
}

//______________________________________________________________________________
TString TString::Copy() const
{
   // Copy a string.

   TString temp(*this);
   return temp;
}

//______________________________________________________________________________
Ssiz_t TString::First(char c) const
{
   // Find first occurrence of a character c.

   const char *f = strchr(Data(), c);
   return f ? f - Data() : kNPOS;
}

//______________________________________________________________________________
Ssiz_t TString::First(const char *cs) const
{
   // Find first occurrence of a character in cs.

   const char *f = strpbrk(Data(), cs);
   return f ? f - Data() : kNPOS;
}

#ifndef R__BYTESWAP
//______________________________________________________________________________
inline static UInt_t SwapInt(UInt_t x)
{
   return (((x & 0x000000ffU) << 24) | ((x & 0x0000ff00U) <<  8) |
           ((x & 0x00ff0000U) >>  8) | ((x & 0xff000000U) >> 24));
}
#endif

//______________________________________________________________________________
inline static void Mash(UInt_t& hash, UInt_t chars)
{
   // Utility used by Hash().

   hash = (chars ^
           ((hash << kHashShift) |
            (hash >> (kBitsPerByte*sizeof(UInt_t) - kHashShift))));
}

//______________________________________________________________________________
UInt_t Hash(const char *str)
{
   // Return a case-sensitive hash value (endian independent).

   UInt_t len = str ? strlen(str) : 0;
   UInt_t hv  = len; // Mix in the string length.
   UInt_t i   = hv*sizeof(char)/sizeof(UInt_t);

   if (((ULong_t)str)%sizeof(UInt_t) == 0) {
      // str is word aligned
      const UInt_t *p = (const UInt_t*)str;

      while (i--) {
#ifndef R__BYTESWAP
         UInt_t h = *p++;
         Mash(hv, SwapInt(h));
#else
         Mash(hv, *p++);                   // XOR in the characters.
#endif
      }

      // XOR in any remaining characters:
      if ((i = len*sizeof(char)%sizeof(UInt_t)) != 0) {
         UInt_t h = 0;
         const char* c = (const char*)p;
         while (i--)
            h = ((h << kBitsPerByte*sizeof(char)) | *c++);
         Mash(hv, h);
      }
   } else {
      // str is not word aligned
      UInt_t h;
      const unsigned char *p = (const unsigned char*)str;

      while (i--) {
         memcpy(&h, p, sizeof(UInt_t));
#ifndef R__BYTESWAP
         Mash(hv, SwapInt(h));
#else
         Mash(hv, h);
#endif
         p += sizeof(UInt_t);
      }

      // XOR in any remaining characters:
      if ((i = len*sizeof(char)%sizeof(UInt_t)) != 0) {
         h = 0;
         const char* c = (const char*)p;
         while (i--)
            h = ((h << kBitsPerByte*sizeof(char)) | *c++);
         Mash(hv, h);
      }
   }
   return hv;
}

//______________________________________________________________________________
UInt_t TString::HashCase() const
{
   // Return a case-sensitive hash value (endian independent).

   UInt_t hv       = (UInt_t)Length(); // Mix in the string length.
   UInt_t i        = hv*sizeof(char)/sizeof(UInt_t);
   const UInt_t *p = (const UInt_t*)Data();
   {
      while (i--) {
#ifndef R__BYTESWAP
         UInt_t h = *p++;
         Mash(hv, SwapInt(h));             // XOR in the characters.
#else
         Mash(hv, *p++);                   // XOR in the characters.
#endif
      }
   }
   // XOR in any remaining characters:
   if ((i = Length()*sizeof(char)%sizeof(UInt_t)) != 0) {
      UInt_t h = 0;
      const char* c = (const char*)p;
      while (i--)
         h = ((h << kBitsPerByte*sizeof(char)) | *c++);
      Mash(hv, h);
   }
   return hv;
}

//______________________________________________________________________________
UInt_t TString::HashFoldCase() const
{
   // Return a case-insensitive hash value (endian independent).

   UInt_t hv = (UInt_t)Length();    // Mix in the string length.
   UInt_t i  = hv;
   const unsigned char *p = (const unsigned char*)Data();
   while (i--) {
      Mash(hv, toupper(*p));
      ++p;
   }
   return hv;
}

//______________________________________________________________________________
UInt_t TString::Hash(ECaseCompare cmp) const
{
   // Return hash value.

   return (cmp == kExact) ? HashCase() : HashFoldCase();
}

namespace {
   // MurmurHash3 - a blazingly fast public domain hash!
   // See http://code.google.com/p/smhasher/
   // There are two versions, one optimized for 32 bit and one for 64 bit.
   // They give different hash results!
   // We use only the 64 bit version which also works on 32 bit.

   //-----------------------------------------------------------------------------
   // MurmurHash3 was written by Austin Appleby, and is placed in the public
   // domain. The author hereby disclaims copyright to this source code.

   // Note - The x86 and x64 versions do _not_ produce the same results, as the
   // algorithms are optimized for their respective platforms. You can still
   // compile and run any of them on any platform, but your performance with the
   // non-native version will be less than optimal.

   //-----------------------------------------------------------------------------
   // Platform-specific functions and macros

   // From MurmurHash.h:

#if defined(_MSC_VER)
   // Microsoft Visual Studio
   typedef unsigned char uint8_t;
   typedef unsigned long uint32_t;
   typedef unsigned __int64 uint64_t;
#else	// defined(_MSC_VER)
   // Other compilers
#include <stdint.h>
#endif // !defined(_MSC_VER)

   // From MurmurHash.cpp:
#if defined(_MSC_VER)
   // Microsoft Visual Studio
#define FORCE_INLINE    __forceinline
#include <stdlib.h>
#define ROTL64(x,y)     _rotl64(x,y)
#define BIG_CONSTANT(x) (x)
#else   // defined(_MSC_VER)
   // Other compilers
   inline uint64_t rotl64 ( uint64_t x, int8_t r )
   {
      return (x << r) | (x >> (64 - r));
   }

#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) <= 40101
// gcc v4.1.1 can't inline getblock, so don't really force it.
#define FORCE_INLINE inline
#else
// (at least) in gcc v4.7, __attribute__((always_inline))" does not replace "inline" and they
// need to be used together. 
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#define ROTL64(x,y)     rotl64(x,y)
#define BIG_CONSTANT(x) (x##LLU)
#endif // !defined(_MSC_VER)

   //-----------------------------------------------------------------------------
   FORCE_INLINE uint64_t getblock(const uint64_t* p, int i)
   {
      // Block read - if your platform needs to do endian-swapping or can only
      // handle aligned reads, do the conversion here
      return p[i];
   }

   //-----------------------------------------------------------------------------
   FORCE_INLINE uint64_t fmix(uint64_t k)
   {
      // Finalization mix - force all bits of a hash block to avalanche
      k ^= k >> 33;
      k *= BIG_CONSTANT(0xff51afd7ed558ccd);
      k ^= k >> 33;
      k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
      k ^= k >> 33;

      return k;
   }

   //-----------------------------------------------------------------------------
   static void MurmurHash3_x64_128(const void * key, const int len,
                                   const uint32_t seed, uint64_t out[2] )
   {
      // "key" is input to be hashed.
      // "len" is the number of bytes to hash starting at "key".
      // "seed" is a hash seed, "out" is a buffer (128 bytes) that will receive
      // the results.
      const uint8_t * data = (const uint8_t*)key;
      const int nblocks = len / 16;

      uint64_t h1 = seed;
      uint64_t h2 = seed;

      uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
      uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

      //----------
      // body

      const uint64_t * blocks = (const uint64_t *)(data);

      for(int i = 0; i < nblocks; i++)
         {
            uint64_t k1 = getblock(blocks,i*2+0);
            uint64_t k2 = getblock(blocks,i*2+1);

            k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;

            h1 = ROTL64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;

            k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

            h2 = ROTL64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5;
         }

      //----------
      // tail

      const uint8_t * tail = (const uint8_t*)(data + nblocks*16);

      uint64_t k1 = 0;
      uint64_t k2 = 0;

      switch(len & 15) {
      case 15: k2 ^= uint64_t(tail[14]) << 48;    // fall through
         case 14: k2 ^= uint64_t(tail[13]) << 40; // fall through
         case 13: k2 ^= uint64_t(tail[12]) << 32; // fall through
         case 12: k2 ^= uint64_t(tail[11]) << 24; // fall through
         case 11: k2 ^= uint64_t(tail[10]) << 16; // fall through
         case 10: k2 ^= uint64_t(tail[ 9]) << 8;  // fall through
         case  9: k2 ^= uint64_t(tail[ 8]) << 0;
            k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;
                                                  // fall through
         case  8: k1 ^= uint64_t(tail[ 7]) << 56; // fall through
         case  7: k1 ^= uint64_t(tail[ 6]) << 48; // fall through
         case  6: k1 ^= uint64_t(tail[ 5]) << 40; // fall through
         case  5: k1 ^= uint64_t(tail[ 4]) << 32; // fall through
         case  4: k1 ^= uint64_t(tail[ 3]) << 24; // fall through
         case  3: k1 ^= uint64_t(tail[ 2]) << 16; // fall through
         case  2: k1 ^= uint64_t(tail[ 1]) << 8;  // fall through
         case  1: k1 ^= uint64_t(tail[ 0]) << 0;
            k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;
      };

      //----------
      // finalization

      h1 ^= len; h2 ^= len;

      h1 += h2;
      h2 += h1;

      h1 = fmix(h1);
      h2 = fmix(h2);

      h1 += h2;
      h2 += h1;

      ((uint64_t*)out)[0] = h1;
      ((uint64_t*)out)[1] = h2;
   }

   //-----------------------------------------------------------------------------
}

//______________________________________________________________________________
UInt_t TString::Hash(const void *txt, Int_t ntxt)
{
   // Calculates hash index from any char string. (static function)
   // For string:  i = TString::Hash(string,nstring);
   // For int:     i = TString::Hash(&intword,sizeof(int));
   // For pointer: i = TString::Hash(&pointer,sizeof(void*));
   //
   // This employs two different hash functions, depending on ntxt:
   //   ntxt == sizeof(void*): a simple bitwise xor to get fast pointer hashes
   //   else: MurmurHash3_x64_128 http://code.google.com/p/smhasher/
   if (ntxt != sizeof(void*)) {
      uint64_t buf[2] = {0};
      MurmurHash3_x64_128(txt, ntxt, 0x6384BA69, buf);
      return (UInt_t) buf[0];
   } else {
      // simple, superfast hash for pointers and alike
      UInt_t ret = (UInt_t)0x6384BA69;
      // aligned?
      if (((size_t)txt) % sizeof(void*)) {
         UInt_t* itxt = (UInt_t*)txt;
         ret ^= itxt[0];
         if (sizeof(void*) > sizeof(UInt_t)) {
            ret ^= itxt[1];
         }
      } else {
         const char* ctxt = (const char*) txt;
         for (int i = 0; i < 4; ++i) {
            ret ^= ctxt[i] << (i * 8);
         }
         if (sizeof(void*) > sizeof(UInt_t)) {
            ctxt += 4;
            for (int i = 0; i < 4; ++i) {
               ret ^= ctxt[i] << (i * 8);
            }
         }
      }
      return ret;
   }
}

//______________________________________________________________________________
static int MemIsEqual(const char *p, const char *q, Ssiz_t n)
{
   // Returns false if strings are not equal.

   while (n--)
   {
      if (tolower((unsigned char)*p) != tolower((unsigned char)*q))
         return kFALSE;
      p++; q++;
   }
   return kTRUE;
}

//______________________________________________________________________________
Ssiz_t TString::Index(const char *pattern, Ssiz_t plen, Ssiz_t startIndex,
                      ECaseCompare cmp) const
{
   // Search for a string in the TString. Plen is the length of pattern,
   // startIndex is the index from which to start and cmp selects the type
   // of case-comparison.

   Ssiz_t slen = Length();
   if (slen < startIndex + plen) return kNPOS;
   if (plen == 0) return startIndex;
   slen -= startIndex + plen;
   const char *sp = Data() + startIndex;
   if (cmp == kExact) {
      char first = *pattern;
      for (Ssiz_t i = 0; i <= slen; ++i)
         if (sp[i] == first && memcmp(sp+i+1, pattern+1, plen-1) == 0)
            return i + startIndex;
   } else {
      int first = tolower((unsigned char) *pattern);
      for (Ssiz_t i = 0; i <= slen; ++i)
         if (tolower((unsigned char) sp[i]) == first &&
             MemIsEqual(sp+i+1, pattern+1, plen-1))
            return i + startIndex;
   }
   return kNPOS;
}

//______________________________________________________________________________
Ssiz_t TString::Last(char c) const
{
   // Find last occurrence of a character c.

   const char *f = strrchr(Data(), (unsigned char) c);
   return f ? f - Data() : kNPOS;
}

//______________________________________________________________________________
TString TString::MD5() const
{
   // Return the MD5 digest for this string, in a string representation.
   TMD5 md5;
   md5.Update((const UChar_t*)Data(), Length());
   UChar_t digest[16];
   md5.Final(digest);
   return md5.AsString();
}

//______________________________________________________________________________
Bool_t TString::MaybeRegexp() const
{
   // Returns true if string contains one of the regexp characters "^$.[]*+?".

   const char *specials = "^$.[]*+?";

   if (First(specials) == kNPOS)
      return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::MaybeWildcard() const
{
   // Returns true if string contains one of the wildcard characters "[]*?".

   const char *specials = "[]*?";

   if (First(specials) == kNPOS)
      return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
TString& TString::Prepend(char c, Ssiz_t rep)
{
   // Prepend character c rep times to string.

   if (!rep) return *this;

   Ssiz_t len = Length();
   Ssiz_t tot = len + rep;  // Final string length

   if (tot > MaxSize()) {
      Error("TString::Prepend", "rep too large (%d, max = %d)", rep, MaxSize()-len);
      tot = MaxSize();
      rep = tot - len;
   }

   Ssiz_t capac = Capacity();
   char *data, *p = GetPointer();

   if (capac - tot >= 0) {
      memmove(p + rep, p, len);
      SetSize(tot);
      data = p;
   } else {
      Ssiz_t cap = AdjustCapacity(capac, tot);
      data = new char[cap+1];
      memcpy(data+rep, p, len);
      UnLink();
      SetLongCap(cap+1);
      SetLongSize(tot);
      SetLongPointer(data);
   }
   data[tot] = 0;

   while (rep--)
      *data++ = c;

   return *this;
}

//______________________________________________________________________________
TString &TString::Replace(Ssiz_t pos, Ssiz_t n1, const char *cs, Ssiz_t n2)
{
   // Remove at most n1 characters from self beginning at pos,
   // and replace them with the first n2 characters of cs.

   Ssiz_t len = Length();
   if (pos <= kNPOS || pos > len) {
      Error("TString::Replace",
            "first argument out of bounds: pos = %d, Length = %d", pos, len);
      return *this;
   }

   n1 = TMath::Min(n1, len - pos);
   if (!cs) n2 = 0;

   Ssiz_t tot = len - n1 + n2;  // Final string length
   Ssiz_t rem = len - n1 - pos; // Length of remnant at end of string

   Ssiz_t capac = Capacity();
   char *p = GetPointer();

   if (capac - len + n1 >= n2) {
      if (n1 != n2) {
         if (rem) {
            if (n1 > n2) {
               if (n2) memmove(p + pos, cs, n2);
               memmove(p + pos + n2, p + pos + n1, rem);
               goto finish;
            }
            if (p + pos < cs && cs < p + len) {
               if (p + pos + n1 <= cs)
                  cs += n2 - n1;
               else {    // p + pos < cs < p + pos + n1
                  memmove(p + pos, cs, n1);
                  pos += n1;
                  cs += n2;
                  n2 -= n1;
                  n1 = 0;
               }
            }
            memmove(p + pos + n2, p + pos + n1, rem);
         }
      }
      if (n2) memmove(p + pos, cs, n2);
finish:
      SetSize(tot);
      p[tot] = 0;
   } else {
      Ssiz_t cap = AdjustCapacity(capac, tot);
      char *data = new char[cap+1];
      if (pos) memcpy(data, p, pos);
      if (n2 ) memcpy(data + pos, cs, n2);
      if (rem) memcpy(data + pos + n2, p + pos + n1, rem);
      UnLink();
      SetLongCap(cap+1);
      SetLongSize(tot);
      SetLongPointer(data);
      data[tot] = 0;
   }

   return *this;
}

//______________________________________________________________________________
TString& TString::ReplaceAll(const char *s1, Ssiz_t ls1, const char *s2,
                             Ssiz_t ls2)
{
   // Find & Replace ls1 symbols of s1 with ls2 symbols of s2 if any.

   if (s1 && ls1 > 0) {
      Ssiz_t index = 0;
      while ((index = Index(s1, ls1, index, kExact)) != kNPOS) {
         Replace(index, ls1, s2, ls2);
         index += ls2;
      }
   }
   return *this;
}

//______________________________________________________________________________
TString &TString::Remove(EStripType st, char c)
{
   // Remove char c at begin and/or end of string (like Strip()) but
   // modifies directly the string.

   Ssiz_t start = 0;             // Index of first character
   Ssiz_t end = Length();        // One beyond last character
   const char *direct = Data();  // Avoid a dereference w dumb compiler
   Ssiz_t send = end;

   if (st & kLeading)
      while (start < end && direct[start] == c)
         ++start;
   if (st & kTrailing)
      while (start < end && direct[end-1] == c)
         --end;
   if (end == start) {
      UnLink();
      Zero();
      return *this;
   }
   if (start)
      Remove(0, start);
   if (send != end)
      Remove(send - start - (send - end), send - end);
   return *this;
}

//______________________________________________________________________________
void TString::Resize(Ssiz_t n)
{
   // Resize the string. Truncate or add blanks as necessary.

   if (n < Length())
      Remove(n);                  // Shrank; truncate the string
   else
      Append(' ', n-Length());    // Grew or staid the same
}

//______________________________________________________________________________
TSubString TString::Strip(EStripType st, char c) const
{
   // Return a substring of self stripped at beginning and/or end.

   Ssiz_t start = 0;             // Index of first character
   Ssiz_t end = Length();        // One beyond last character
   const char *direct = Data();  // Avoid a dereference w dumb compiler

   if (st & kLeading)
      while (start < end && direct[start] == c)
         ++start;
   if (st & kTrailing)
      while (start < end && direct[end-1] == c)
         --end;
   if (end == start) start = end = kNPOS;  // make the null substring
   return TSubString(*this, start, end-start);
}

//______________________________________________________________________________
void TString::ToLower()
{
   // Change string to lower-case.

   Ssiz_t n = Length();
   char *p = GetPointer();
   while (n--) {
      *p = tolower((unsigned char)*p);
      p++;
   }
}

//______________________________________________________________________________
void TString::ToUpper()
{
   // Change string to upper case.

   Ssiz_t n = Length();
   char *p = GetPointer();
   while (n--) {
      *p = toupper((unsigned char)*p);
      p++;
   }
}

//______________________________________________________________________________
void TString::AssertElement(Ssiz_t i) const
{
   // Check to make sure a string index is in range.

   if (i == kNPOS || i > Length())
      Error("TString::AssertElement",
            "out of bounds: i = %d, Length = %d", i, Length());
}

//______________________________________________________________________________
Ssiz_t TString::AdjustCapacity(Ssiz_t oldCap, Ssiz_t newCap)
{
   // Calculate a nice capacity greater than or equal to newCap.

   Ssiz_t ms = MaxSize();
   if (newCap > ms - 1) {
      Error("TString::AdjustCapacity", "capacity too large (%d, max = %d)",
            newCap, ms);
   }
   Ssiz_t cap = oldCap < ms / 2 - kAlignment ?
                Recommend(TMath::Max(newCap, 2 * oldCap)) : ms - 1;
   return cap;
}

//______________________________________________________________________________
void TString::Clear()
{
   // Clear string without changing its capacity.

   Clobber(Capacity());
}

//______________________________________________________________________________
void TString::Clobber(Ssiz_t nc)
{
   // Clear string and make sure it has a capacity of nc.

   if (nc > MaxSize()) {
      Error("TString::Clobber", "capacity too large (%d, max = %d)", nc, MaxSize());
      nc = MaxSize();
   }

   if (nc < kMinCap) {
      UnLink();
      Zero();
   } else {
      char *data = GetLongPointer();
      Ssiz_t cap = Recommend(nc);
      if (cap != Capacity()) {
         data = new char[cap+1];
         UnLink();
         SetLongCap(cap+1);
         SetLongPointer(data);
      }
      SetLongSize(0);
      data[0] = 0;
   }
}

//______________________________________________________________________________
void TString::Clone(Ssiz_t tot)
{
   // Make self a distinct copy with capacity of at least tot, where tot cannot
   // be smaller than the current length. Preserve previous contents.

   Ssiz_t len = Length();
   if (len >= tot) return;

   if (tot > MaxSize()) {
      Error("TString::Clone", "tot too large (%d, max = %d)", tot, MaxSize());
      tot = MaxSize();
   }

   Ssiz_t capac = Capacity();
   char *data, *p = GetPointer();

   if (capac - tot < 0) {
      Ssiz_t cap = Recommend(tot);
      data = new char[cap+1];
      memcpy(data, p, len);
      UnLink();
      SetLongCap(cap+1);
      SetLongSize(len);
      SetLongPointer(data);
      data[len] = 0;
   }
}

// ------------------- ROOT I/O ------------------------------------

//______________________________________________________________________________
void TString::FillBuffer(char *&buffer) const
{
   // Copy string into I/O buffer.

   UChar_t nwh;
   Int_t   nchars = Length();

   if (nchars > 254) {
      nwh = 255;
      tobuf(buffer, nwh);
      tobuf(buffer, nchars);
   } else {
      nwh = UChar_t(nchars);
      tobuf(buffer, nwh);
   }
   const char *data = GetPointer();
   for (int i = 0; i < nchars; i++) buffer[i] = data[i];
   buffer += nchars;
}

//______________________________________________________________________________
void TString::ReadBuffer(char *&buffer)
{
   // Read string from I/O buffer.

   UnLink();
   Zero();

   UChar_t nwh;
   Int_t   nchars;

   frombuf(buffer, &nwh);
   if (nwh == 255)
      frombuf(buffer, &nchars);
   else
      nchars = nwh;

   if (nchars < 0) {
      Error("TString::ReadBuffer", "found case with nwh=%d and nchars=%d", nwh, nchars);
      return;
   }

   char *data = Init(nchars, nchars);

   for (int i = 0; i < nchars; i++) frombuf(buffer, &data[i]);
}

//______________________________________________________________________________
TString *TString::ReadString(TBuffer &b, const TClass *clReq)
{
   // Read TString object from buffer. Simplified version of
   // TBuffer::ReadObject (does not keep track of multiple
   // references to same string).  We need to have it here
   // because TBuffer::ReadObject can only handle descendant
   // of TObject.

   R__ASSERT(b.IsReading());

   // Make sure ReadArray is initialized
   b.InitMap();

   // Before reading object save start position
   UInt_t startpos = UInt_t(b.Length());

   UInt_t tag;
   TClass *clRef = b.ReadClass(clReq, &tag);

   TString *a;
   if (!clRef) {

      a = 0;

   } else {

      a = (TString *) clRef->New();
      if (!a) {
         ::Error("TString::ReadObject", "could not create object of class %s",
                 clRef->GetName());
         // Exception
         return a;
      }

      a->Streamer(b);

      b.CheckByteCount(startpos, tag, clRef);
   }

   return a;
}

//______________________________________________________________________________
Int_t TString::Sizeof() const
{
   // Returns size string will occupy on I/O buffer.

   if (Length() > 254)
      return Length()+sizeof(UChar_t)+sizeof(Int_t);
   else
      return Length()+sizeof(UChar_t);
}

//_______________________________________________________________________
void TString::Streamer(TBuffer &b)
{
   // Stream a string object.

   Int_t   nbig;
   UChar_t nwh;
   if (b.IsReading()) {
      b >> nwh;
      if (nwh == 0) {
         UnLink();
         Zero();
      } else {
         if (nwh == 255)
            b >> nbig;
         else
            nbig = nwh;

         Clobber(nbig);
         char *data = GetPointer();
         data[nbig] = 0;
         SetSize(nbig);
         b.ReadFastArray(data, nbig);
      }
   } else {
      nbig = Length();
      if (nbig > 254) {
         nwh = 255;
         b << nwh;
         b << nbig;
      } else {
         nwh = UChar_t(nbig);
         b << nwh;
      }
      const char *data = GetPointer();
      b.WriteFastArray(data, nbig);
   }
}

//______________________________________________________________________________
void TString::WriteString(TBuffer &b, const TString *a)
{
   // Write TString object to buffer. Simplified version of
   // TBuffer::WriteObject (does not keep track of multiple
   // references to the same string).  We need to have it here
   // because TBuffer::ReadObject can only handle descendant
   // of TObject

   R__ASSERT(b.IsWriting());

   // Make sure WriteMap is initialized
   b.InitMap();

   if (!a) {

      b << (UInt_t) 0;

   } else {

      // Reserve space for leading byte count
      UInt_t cntpos = UInt_t(b.Length());
      b.SetBufferOffset(Int_t(cntpos+sizeof(UInt_t)));

      TClass *cl = a->IsA();
      b.WriteClass(cl);

      ((TString *)a)->Streamer(b);

      // Write byte count
      b.SetByteCount(cntpos);
   }
}

//_______________________________________________________________________
#if defined(R__TEMPLATE_OVERLOAD_BUG)
template <>
#endif
TBuffer &operator>>(TBuffer &buf, TString *&s)
{
   // Read string from TBuffer. Function declared in ClassDef.

   s = (TString *) TString::ReadString(buf, TString::Class());
   return buf;
}

//_______________________________________________________________________
TBuffer &operator<<(TBuffer &buf, const TString *s)
{
   // Write TString or derived to TBuffer.

   TString::WriteString(buf, s);
   return buf;
}

// ------------------- Related global functions --------------------

//______________________________________________________________________________
Bool_t operator==(const TString& s1, const char *s2)
{
   // Compare TString with a char *.

   if (!s2) return kFALSE;

   const char *data = s1.Data();
   Ssiz_t len = s1.Length();
   Ssiz_t i;
   for (i = 0; s2[i]; ++i)
      if (data[i] != s2[i] || i == len) return kFALSE;
   return (i == len);
}

//______________________________________________________________________________
TString ToLower(const TString &str)
{
   // Return a lower-case version of str.

   Ssiz_t n = str.Length();
   TString temp((char)0, n);
   const char *uc = str.Data();
         char *lc = (char*)temp.Data();
   // Guard against tolower() being a macro
   while (n--) { *lc++ = tolower((unsigned char)*uc); uc++; }
   return temp;
}

//______________________________________________________________________________
TString ToUpper(const TString &str)
{
   // Return an upper-case version of str.

   Ssiz_t n = str.Length();
   TString temp((char)0, n);
   const char* uc = str.Data();
         char* lc = (char*)temp.Data();
   // Guard against toupper() being a macro
   while (n--) { *lc++ = toupper((unsigned char)*uc); uc++; }
   return temp;
}

//______________________________________________________________________________
TString operator+(const TString &s, const char *cs)
{
   // Use the special concatenation constructor.

   return TString(s.Data(), s.Length(), cs, cs ? strlen(cs) : 0);
}

//______________________________________________________________________________
TString operator+(const char *cs, const TString &s)
{
   // Use the special concatenation constructor.

   return TString(cs, cs ? strlen(cs) : 0, s.Data(), s.Length());
}

//______________________________________________________________________________
TString operator+(const TString &s1, const TString &s2)
{
   // Use the special concatenation constructor.

   return TString(s1.Data(), s1.Length(), s2.Data(), s2.Length());
}

//______________________________________________________________________________
TString operator+(const TString &s, char c)
{
   // Add char to string.

   return TString(s.Data(), s.Length(), &c, 1);
}

//______________________________________________________________________________
TString operator+(const TString &s, Long_t i)
{
   // Add integer to string.

   char si[32];
   snprintf(si, sizeof(si), "%ld", i);
   return TString(s.Data(), s.Length(), si, strlen(si));
}

//______________________________________________________________________________
TString operator+(const TString &s, ULong_t i)
{
   // Add integer to string.

   char si[32];
   snprintf(si, sizeof(si), "%lu", i);
   return TString(s.Data(), s.Length(), si, strlen(si));
}

//______________________________________________________________________________
TString operator+(const TString &s, Long64_t i)
{
   // Add integer to string.

   char si[32];
   snprintf(si, sizeof(si), "%lld", i);
   return TString(s.Data(), s.Length(), si, strlen(si));
}

//______________________________________________________________________________
TString operator+(const TString &s, ULong64_t i)
{
   // Add integer to string.

   char si[32];
   snprintf(si, sizeof(si), "%llu", i);
   return TString(s.Data(), s.Length(), si, strlen(si));
}

//______________________________________________________________________________
TString operator+(char c, const TString &s)
{
   // Add string to integer.

   return TString(&c, 1, s.Data(), s.Length());
}

//______________________________________________________________________________
TString operator+(Long_t i, const TString &s)
{
   // Add string to integer.

   char si[32];
   snprintf(si, sizeof(si), "%ld", i);
   return TString(si, strlen(si), s.Data(), s.Length());
}

//______________________________________________________________________________
TString operator+(ULong_t i, const TString &s)
{
   // Add string to integer.

   char si[32];
   snprintf(si, sizeof(si), "%lu", i);
   return TString(si, strlen(si), s.Data(), s.Length());
}

//______________________________________________________________________________
TString operator+(Long64_t i, const TString &s)
{
   // Add string to integer.

   char si[32];
   snprintf(si, sizeof(si), "%lld", i);
   return TString(si, strlen(si), s.Data(), s.Length());
}

//______________________________________________________________________________
TString operator+(ULong64_t i, const TString &s)
{
   // Add string to integer.

   char si[32];
   snprintf(si, sizeof(si), "%llu", i);
   return TString(si, strlen(si), s.Data(), s.Length());
}

// -------------------- Static Member Functions ----------------------

// ------------------- The static data members access --------------------------

//______________________________________________________________________________
Ssiz_t  TString::GetInitialCapacity()
{
   ::Obsolete("TString::GetInitialCapacity", "v5-30-00", "v5-32-00");
   return 15;
}

//______________________________________________________________________________
Ssiz_t  TString::GetResizeIncrement()
{
   ::Obsolete("TString::GetResizeIncrement", "v5-30-00", "v5-32-00");
   return 16;
}

//______________________________________________________________________________
Ssiz_t  TString::GetMaxWaste()
{
   ::Obsolete("TString::GetMaxWaste", "v5-30-00", "v5-32-00");
   return 15;
}

//______________________________________________________________________________
Ssiz_t TString::InitialCapacity(Ssiz_t)
{
   // Set default initial capacity for all TStrings. Default is 15.

   ::Obsolete("TString::InitialCapacity", "v5-30-00", "v5-32-00");
   return 15;
}

//______________________________________________________________________________
Ssiz_t TString::ResizeIncrement(Ssiz_t)
{
   // Set default resize increment for all TStrings. Default is 16.

   ::Obsolete("TString::ResizeIncrement", "v5-30-00", "v5-32-00");
   return 16;
}

//______________________________________________________________________________
Ssiz_t TString::MaxWaste(Ssiz_t)
{
   // Set maximum space that may be wasted in a string before doing a resize.
   // Default is 15.

   ::Obsolete("TString::MaxWaste", "v5-30-00", "v5-32-00");
   return 15;
}


//////////////////////////////////////////////////////////////////////////
//                                                                      //
//  TSubString                                                          //
//                                                                      //
//////////////////////////////////////////////////////////////////////////

//
// A zero lengthed substring is legal. It can start
// at any character. It is considered to be "pointing"
// to just before the character.
//
// A "null" substring is a zero lengthed substring that
// starts with the nonsense index kNPOS. It can
// be detected with the member function IsNull().
//

//______________________________________________________________________________
TSubString::TSubString(const TString &str, Ssiz_t start, Ssiz_t nextent)
   : fStr((TString&)str), fBegin(start), fExtent(nextent)
{
   // Private constructor.
}

//______________________________________________________________________________
TSubString TString::operator()(Ssiz_t start, Ssiz_t len) const
{
   // Return sub-string of string starting at start with length len.

   if (start < Length() && len > 0) {
      if (start+len > Length())
         len = Length() - start;
   } else {
      start = kNPOS;
      len   = 0;
   }
   return TSubString(*this, start, len);
}

//______________________________________________________________________________
TSubString TString::SubString(const char *pattern, Ssiz_t startIndex,
                              ECaseCompare cmp) const
{
   // Returns a substring matching "pattern", or the null substring
   // if there is no such match.  It would be nice if this could be yet another
   // overloaded version of operator(), but this would result in a type
   // conversion ambiguity with operator(Ssiz_t, Ssiz_t).

   Ssiz_t len = pattern ? strlen(pattern) : 0;
   Ssiz_t i = Index(pattern, len, startIndex, cmp);
   return TSubString(*this, i, i == kNPOS ? 0 : len);
}

//______________________________________________________________________________
char& TSubString::operator[](Ssiz_t i)
{
   // Return character at pos i from sub-string. Check validity of i.

   AssertElement(i);
   return fStr(fBegin+i);
}

//______________________________________________________________________________
char& TSubString::operator()(Ssiz_t i)
{
   // Return character at pos i from sub-string. No check on i.

   return fStr(fBegin+i);
}

//______________________________________________________________________________
TSubString& TSubString::operator=(const TString &str)
{
   // Assign string to sub-string.

   if (!IsNull())
      fStr.Replace(fBegin, fExtent, str.Data(), str.Length());

   return *this;
}

//______________________________________________________________________________
TSubString& TSubString::operator=(const char *cs)
{
   // Assign char* to sub-string.

   if (!IsNull())
      fStr.Replace(fBegin, fExtent, cs, cs ? strlen(cs) : 0);

   return *this;
}

//______________________________________________________________________________
Bool_t operator==(const TSubString& ss, const char *cs)
{
   // Compare sub-string to char *.

   if (ss.IsNull()) return *cs =='\0'; // Two null strings compare equal

   const char* data = ss.fStr.Data() + ss.fBegin;
   Ssiz_t i;
   for (i = 0; cs[i]; ++i)
      if (cs[i] != data[i] || i == ss.fExtent) return kFALSE;
   return (i == ss.fExtent);
}

//______________________________________________________________________________
Bool_t operator==(const TSubString& ss, const TString &s)
{
   // Compare sub-string to string.

   if (ss.IsNull()) return s.IsNull(); // Two null strings compare equal.
   if (ss.fExtent != s.Length()) return kFALSE;
   return !memcmp(ss.fStr.Data() + ss.fBegin, s.Data(), ss.fExtent);
}

//______________________________________________________________________________
Bool_t operator==(const TSubString &s1, const TSubString &s2)
{
   // Compare two sub-strings.

   if (s1.IsNull()) return s2.IsNull();
   if (s1.fExtent != s2.fExtent) return kFALSE;
   return !memcmp(s1.fStr.Data()+s1.fBegin, s2.fStr.Data()+s2.fBegin,
                  s1.fExtent);
}

//______________________________________________________________________________
void TSubString::ToLower()
{
   // Convert sub-string to lower-case.

   if (!IsNull()) {                             // Ignore null substrings
      char *p = fStr.GetPointer() + fBegin;
      Ssiz_t n = fExtent;
      while (n--) { *p = tolower((unsigned char)*p); p++;}
   }
}

//______________________________________________________________________________
void TSubString::ToUpper()
{
   // Convert sub-string to upper-case.
   if (!IsNull()) {                             // Ignore null substrings
      char *p = fStr.GetPointer() + fBegin;
      Ssiz_t n = fExtent;
      while (n--) { *p = toupper((unsigned char)*p); p++;}
   }
}

//______________________________________________________________________________
void TSubString::SubStringError(Ssiz_t sr, Ssiz_t start, Ssiz_t n) const
{
   // Output error message.

   Error("TSubString::SubStringError",
         "out of bounds: start = %d, n = %d, sr = %d", start, n, sr);
}

//______________________________________________________________________________
void TSubString::AssertElement(Ssiz_t i) const
{
   // Check to make sure a sub-string index is in range.

   if (i == kNPOS || i >= Length())
      Error("TSubString::AssertElement",
            "out of bounds: i = %d, Length = %d", i, Length());
}

//______________________________________________________________________________
Bool_t TString::IsAscii() const
{
   // Returns true if all characters in string are ascii.

   const char *cp = Data();
   for (Ssiz_t i = 0; i < Length(); ++i)
      if (cp[i] & ~0x7F)
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsAlpha() const
{
   // Returns true if all characters in string are alphabetic.
   // Returns false in case string length is 0.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (!isalpha(cp[i]))
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsAlnum() const
{
   // Returns true if all characters in string are alphanumeric.
   // Returns false in case string length is 0.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (!isalnum(cp[i]))
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsDigit() const
{
   // Returns true if all characters in string are digits (0-9) or whitespaces,
   // i.e. "123456" and "123 456" are both valid integer strings.
   // Returns false in case string length is 0 or string contains other
   // characters or only whitespace.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   Int_t b = 0, d = 0;
   for (Ssiz_t i = 0; i < len; ++i) {
      if (cp[i] != ' ' && !isdigit(cp[i])) return kFALSE;
      if (cp[i] == ' ') b++;
      if (isdigit(cp[i])) d++;
   }
   if (b && !d)
      return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsFloat() const
{
   // Returns kTRUE if string contains a floating point or integer number.
   // Examples of valid formats are:
   //    64320
   //    64 320
   //    6 4 3 2 0
   //    6.4320     6,4320
   //    6.43e20   6.43E20    6,43e20
   //    6.43e-20  6.43E-20   6,43e-20, -6.43e+20

   //we first check if we have an integer, in this case, IsDigit() will be true straight away
   if (IsDigit()) return kTRUE;

   TString tmp = *this;
   //now we look for occurrences of '.', ',', e', 'E', '+', '-' and replace each
   //with ' ', if it is a floating point, IsDigit() will then return kTRUE

   tmp.ToLower();
   Ssiz_t pos = tmp.First('.');
   if (pos != kNPOS) tmp.Replace(pos, 1, " ", 1);
   pos = tmp.First(',');
   if (pos != kNPOS) tmp.Replace(pos, 1, " ", 1);
   pos = tmp.Index("e-");
   if (pos >= 1) tmp.Replace(pos, 2, " ", 1);
   pos = tmp.Index("e+");
   if (pos >= 1) tmp.Replace(pos, 2, " ", 1);
   pos = tmp.Index("e");
   if (pos >= 1) tmp.Replace(pos, 1, " ", 1);
   pos = tmp.First('-');
   if (pos == 0) tmp.Replace(pos, 1, " ", 1);
   pos = tmp.First('+');
   if (pos == 0) tmp.Replace(pos, 1, " ", 1);

   //test if it is now uniquely composed of numbers
   return tmp.IsDigit();
}

//______________________________________________________________________________
Bool_t TString::IsHex() const
{
   // Returns true if all characters in string are hexidecimal digits
   // (0-9,a-f,A-F). Returns false in case string length is 0 or string
   // contains other characters.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (!isxdigit(cp[i]))
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsBin() const
{
   // Returns true if all characters in string are binary digits (0,1).
   // Returns false in case string length is 0 or string contains other
   // characters.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (cp[i] != '0' && cp[i] != '1')
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsOct() const
{
   // Returns true if all characters in string are octal digits (0-7).
   // Returns false in case string length is 0 or string contains other
   // characters.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (!isdigit(cp[i]) || cp[i]=='8' || cp[i]=='9')
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsDec() const
{
   // Returns true if all characters in string are decimal digits (0-9).
   // Returns false in case string length is 0 or string contains other
   // characters.

   const char *cp = Data();
   Ssiz_t len = Length();
   if (len == 0) return kFALSE;
   for (Ssiz_t i = 0; i < len; ++i)
      if (!isdigit(cp[i]))
         return kFALSE;
   return kTRUE;
}

//______________________________________________________________________________
Bool_t TString::IsInBaseN(Int_t base) const
{
   // Returns true if all characters in string are expressed in the base
   // specified (range=2-36), i.e. {0,1} for base 2, {0-9,a-f,A-F} for base 16,
   // {0-9,a-z,A-Z} for base 36. Returns false in case string length is 0 or
   // string contains other characters.

   if (base < 2 || base > 36) {
      Error("TString::IsInBaseN", "base %d is not supported. Supported bases are {2,3,...,36}.", base);
      return kFALSE;
   }
   if (Length() == 0) {
      Error("TString::IsInBaseN", "input string is empty.") ;
      return kFALSE;
   }
   TString str = TString(Data()) ;
   str.ToUpper() ;
   TString str_ref0 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" ;
   TString str_ref = str_ref0 ;
   str_ref.Remove(base) ;
   Bool_t isInBase = kTRUE ;
   for (Int_t k = 0; k < str.Length(); k++) {
      if (! str_ref.Contains(str[k])) {
         isInBase = kFALSE ;
         break ;
      }
   }
   return (isInBase);
}

//______________________________________________________________________________
Int_t TString::Atoi() const
{
   // Return integer value of string.
   // Valid strings include only digits and whitespace (see IsDigit()),
   // i.e. "123456", "123 456" and "1 2 3 4        56" are all valid
   // integer strings whose Atoi() value is 123456.

   //any whitespace ?
   Int_t end = Index(" ");
   //if no whitespaces in string, just use atoi()
   if (end == -1) return atoi(Data());
   //make temporary string, removing whitespace
   Int_t start = 0;
   TString tmp;
   //loop over all whitespace
   while (end > -1) {
      tmp += (*this)(start, end-start);
      start = end+1; end = Index(" ", start);
   }
   //finally add part from last whitespace to end of string
   end = Length();
   tmp += (*this)(start, end-start);
   return atoi(tmp.Data());
}

//______________________________________________________________________________
Long64_t TString::Atoll() const
{
   // Return long long value of string.
   // Valid strings include only digits and whitespace (see IsDigit()),
   // i.e. "123456", "123 456" and "1 2 3 4        56" are all valid
   // integer strings whose Atoll() value is 123456.

   //any whitespace ?
   Int_t end = Index(" ");
   //if no whitespaces in string, just use atoi()
#ifndef R__WIN32
   if (end == -1) return atoll(Data());
#else
   if (end == -1) return _atoi64(Data());
#endif
   //make temporary string, removing whitespace
   Int_t start = 0;
   TString tmp;
   //loop over all whitespace
   while (end > -1) {
      tmp += (*this)(start, end-start);
      start = end+1; end = Index(" ", start);
   }
   //finally add part from last whitespace to end of string
   end = Length();
   tmp += (*this)(start, end-start);
#ifndef R__WIN32
   return atoll(tmp.Data());
#else
   return _atoi64(tmp.Data());
#endif
}

//______________________________________________________________________________
Double_t TString::Atof() const
{
   // Return floating-point value contained in string.
   // Examples of valid strings are:
   //    64320
   //    64 320
   //    6 4 3 2 0
   //    6.4320     6,4320
   //    6.43e20   6.43E20    6,43e20
   //    6.43e-20  6.43E-20   6,43e-20

   //look for a comma and some whitespace
   Int_t comma = Index(",");
   Int_t end = Index(" ");
   //if no commas & no whitespace in string, just use atof()
   if (comma == -1 && end == -1) return atof(Data());
   TString tmp = *this;
   if (comma > -1) {
      //replace comma with decimal point
      tmp.Replace(comma, 1, ".");
   }
   //no whitespace ?
   if (end == -1) return atof(tmp.Data());
   //remove whitespace
   Int_t start = 0;
   TString tmp2;
   while (end > -1) {
      tmp2 += tmp(start, end-start);
      start = end+1; end = tmp.Index(" ", start);
   }
   end = tmp.Length();
   tmp2 += tmp(start, end-start);
   return atof(tmp2.Data());
}

//______________________________________________________________________________
TString TString::Itoa(Int_t value, Int_t base)
{
   // Converts an Int_t to a TString with respect to the base specified (2-36).
   // Thus it is an enhanced version of sprintf (adapted from versions 0.4 of
   // http://www.jb.man.ac.uk/~slowe/cpp/itoa.html).
   // Usage: the following statement produce the same output, namely "1111"
   //   std::cout << TString::Itoa(15,2) ;
   //   std::cout << TString::Itoa(0xF,2) ; /// 0x prefix to handle hex
   //   std::cout << TString::Itoa(017,2) ; /// 0  prefix to handle oct
   // In case of error returns the "!" string.

   std::string buf;
   // check that the base if valid
   if (base < 2 || base > 36) {
      Error("TString::Itoa", "base %d is not supported. Supported bases are {2,3,...,36}.",base) ;
      return (TString("!"));
   }
   buf.reserve(35); // Pre-allocate enough space (35=kMaxDigits)
   Int_t quotient = value;
   // Translating number to string with base:
   do {
      buf += "0123456789abcdefghijklmnopqrstuvwxyz"[ TMath::Abs(quotient % base) ];
      quotient /= base;
   } while (quotient);
   // Append the negative sign
   if (value < 0) buf += '-';
   std::reverse(buf.begin(), buf.end());
   return (TString(buf.data()));
}

//______________________________________________________________________________
TString TString::UItoa(UInt_t value, Int_t base)
{
   // Converts a UInt_t (twice the range of an Int_t) to a TString with respect
   // to the base specified (2-36). Thus it is an enhanced version of sprintf
   // (adapted from versions 0.4 of http://www.jb.man.ac.uk/~slowe/cpp/itoa.html).
   // In case of error returns the "!" string.

   std::string buf;
   // check that the base if valid
   if (base < 2 || base > 36) {
      Error("TString::UItoa", "base %d is not supported. Supported bases are {2,3,...,36}.",base);
      return (TString("!"));
   }
   buf.reserve(35); // Pre-allocate enough space (35=kMaxDigits)
   UInt_t quotient = value;
   // Translating number to string with base:
   do {
      buf += "0123456789abcdefghijklmnopqrstuvwxyz"[ quotient % base ];
      quotient /= base;
   } while (quotient);
   std::reverse(buf.begin(), buf.end());
   return (TString(buf.data()));
}

//______________________________________________________________________________
TString TString::LLtoa(Long64_t value, Int_t base)
{
   // Converts a Long64_t to a TString with respect to the base specified (2-36).
   // Thus it is an enhanced version of sprintf (adapted from versions 0.4 of
   // http://www.jb.man.ac.uk/~slowe/cpp/itoa.html).
   // In case of error returns the "!" string.

   std::string buf;
   // check that the base if valid
   if (base < 2 || base > 36) {
      Error("TString::LLtoa", "base %d is not supported. Supported bases are {2,3,...,36}.",base);
      return (TString("!"));
   }
   buf.reserve(35); // Pre-allocate enough space (35=kMaxDigits)
   Long64_t quotient = value;
   // Translating number to string with base:
   do {
      buf += "0123456789abcdefghijklmnopqrstuvwxyz"[ TMath::Abs(quotient % base) ];
      quotient /= base;
   } while (quotient);
   // Append the negative sign
   if (value < 0) buf += '-';
   std::reverse(buf.begin(), buf.end());
   return (TString(buf.data()));
}

//______________________________________________________________________________
TString TString::ULLtoa(ULong64_t value, Int_t base)
{
   // Converts a ULong64_t (twice the range of an Long64_t) to a TString with
   // respect to the base specified (2-36). Thus it is an enhanced version of
   // sprintf (adapted from versions 0.4 of http://www.jb.man.ac.uk/~slowe/cpp/itoa.html).
   // In case of error returns the "!" string.

   std::string buf;
   // check that the base if valid
   if (base < 2 || base > 36) {
      Error("TString::ULLtoa", "base %d is not supported. Supported bases are {2,3,...,36}.",base);
      return (TString("!"));
   }
   buf.reserve(35); // Pre-allocate enough space (35=kMaxDigits)
   ULong64_t quotient = value;
   // Translating number to string with base:
   do {
      buf += "0123456789abcdefghijklmnopqrstuvwxyz"[ quotient % base ];
      quotient /= base;
   } while (quotient);
   std::reverse(buf.begin(), buf.end());
   return (TString(buf.data()));
}

//______________________________________________________________________________
TString TString::BaseConvert(const TString& s_in, Int_t base_in, Int_t base_out)
{
   // Converts string from base base_in to base base_out. Supported bases
   // are 2-36. At most 64 bit data can be converted.

   TString s_out = "!" ;  // return value in case of issue
   // checking base range
   if (base_in < 2 || base_in > 36 || base_out < 2 || base_out > 36) {
      Error("TString::BaseConvert", "only bases 2-36 are supported (base_in=%d, base_out=%d).", base_in, base_out);
      return (s_out);
   }
   // cleaning s_in
   TString s_in_ = s_in;
   Bool_t isSigned = kFALSE;
   if (s_in_[0] == '-') {
      isSigned = kTRUE;
      s_in_.Remove(0, 1);
   }
   if (!isSigned && s_in_[0] == '+') s_in_.Remove(0, 1);  // !isSigned to avoid strings beginning with "-+"
   if (base_in == 16 && s_in_.BeginsWith("0x")) s_in_.Remove(0, 2);  // removing hex prefix if any
   s_in_ = TString(s_in_.Strip(TString::kLeading, '0'));  // removing leading zeros (necessary for length comparison below)
   if (!s_in_.Length()) s_in_ += '0';
   // checking s_in_ is expressed in the mentioned base
   if (!s_in_.IsInBaseN(base_in)) {
      Error("TString::BaseConvert", "s_in=\"%s\" is not in base %d", s_in.Data(), base_in);
      return (s_out);
   }
   // checking s_in <= 64 bits
   TString s_max = TString::ULLtoa(18446744073709551615ULL, base_in);
   if (s_in_.Length() > s_max.Length()) {
      // string comparison (s_in_>s_max) does not take care of length
      Error("TString::BaseConvert", "s_in=\"%s\" > %s = 2^64-1 in base %d.", s_in.Data(), s_max.Data(), base_in);
      return (s_out);
   } else if (s_in_.Length() == s_max.Length()) {
      // if ( s_in_.Length() < s_max.Length() ) everything's fine
      s_in_.ToLower();  // s_max is lower case
      if (s_in_ > s_max) {
         // string comparison
         Error("TString::BaseConvert", "s_in=\"%s\" > %s = 2^64-1 in base %d.", s_in.Data(), s_max.Data(), base_in);
         return (s_out);
      }
   }

   // computing s_out
   ULong64_t i = ULong64_t(strtoull(s_in.Data(), 0, base_in));
   s_out = TString::ULLtoa(i, base_out);
   if (isSigned) s_out.Prepend("-");
   return (s_out);
}

//______________________________________________________________________________
Bool_t TString::EndsWith(const char *s, ECaseCompare cmp) const
{
   // Return true if string ends with the specified string.

   if (!s) return kTRUE;

   Ssiz_t l = strlen(s);
   if (l > Length()) return kFALSE;
   const char *s2 = Data() + Length() - l;

   if (cmp == kExact)
      return strcmp(s, s2) == 0;
   return strcasecmp(s, s2) == 0;
}

//__________________________________________________________________________________
TObjArray *TString::Tokenize(const TString &delim) const
{
   // This function is used to isolate sequential tokens in a TString.
   // These tokens are separated in the string by at least one of the
   // characters in delim. The returned array contains the tokens
   // as TObjString's. The returned array is the owner of the objects,
   // and must be deleted by the user.

   std::list<Int_t> splitIndex;

   Int_t i, start, nrDiff = 0;
   for (i = 0; i < delim.Length(); i++) {
      start = 0;
      while (start < Length()) {
         Int_t pos = Index(delim(i), start);
         if (pos == kNPOS) break;
         splitIndex.push_back(pos);
         start = pos + 1;
      }
      if (start > 0) nrDiff++;
   }
   splitIndex.push_back(Length());

   if (nrDiff > 1)
      splitIndex.sort();

   TObjArray *arr = new TObjArray();
   arr->SetOwner();

   start = -1;
   std::list<Int_t>::const_iterator it;
#ifndef R__HPUX
   for (it = splitIndex.begin(); it != splitIndex.end(); it++) {
#else
   for (it = splitIndex.begin(); it != (std::list<Int_t>::const_iterator) splitIndex.end(); it++) {
#endif
      Int_t stop = *it;
      if (stop - 1 >= start + 1) {
         TString tok = (*this)(start+1, stop-start-1);
         TObjString *objstr = new TObjString(tok);
         arr->Add(objstr);
      }
      start = stop;
   }

   return arr;
}

//______________________________________________________________________________
void TString::FormImp(const char *fmt, va_list ap)
{
   // Formats a string using a printf style format descriptor.
   // Existing string contents will be overwritten.

   Ssiz_t buflen = 20 + 20 * strlen(fmt);    // pick a number, any strictly positive number
   Clobber(buflen);

   va_list sap;
   R__VA_COPY(sap, ap);

   int n, vc = 0;
again:
   n = vsnprintf(GetPointer(), buflen, fmt, ap);
   // old vsnprintf's return -1 if string is truncated new ones return
   // total number of characters that would have been written
   if (n == -1 || n >= buflen) {
      if (n == -1)
         buflen *= 2;
      else
         buflen = n+1;
      Clobber(buflen);
      va_end(ap);
      R__VA_COPY(ap, sap);
      vc = 1;
      goto again;
   }
   va_end(sap);
   if (vc)
      va_end(ap);

   SetSize(strlen(Data()));
}

//______________________________________________________________________________
void TString::Form(const char *va_(fmt), ...)
{
   // Formats a string using a printf style format descriptor.
   // Existing string contents will be overwritten.

   va_list ap;
   va_start(ap, va_(fmt));
   FormImp(va_(fmt), ap);
   va_end(ap);
}

//______________________________________________________________________________
TString TString::Format(const char *va_(fmt), ...)
{
   // Static method which formats a string using a printf style format
   // descriptor and return a TString. Same as TString::Form() but it is
   // not needed to first create a TString.

   va_list ap;
   va_start(ap, va_(fmt));
   TString str;
   str.FormImp(va_(fmt), ap);
   va_end(ap);
   return str;
}

//---- Global String Handling Functions ----------------------------------------

//______________________________________________________________________________
static char *SlowFormat(const char *format, va_list ap, int hint)
{
   // Format a string in a formatting buffer (using a printf style
   // format descriptor).

   static const int fld_size = 2048;
   TTHREAD_TLS(char*) slowBuffer(0);
   TTHREAD_TLS(int) slowBufferSize(0);

   if (hint == -1) hint = fld_size;
   if (hint > slowBufferSize) {
      delete [] slowBuffer;
      slowBufferSize = 2 * hint;
      if (hint < 0 || slowBufferSize < 0) {
         slowBufferSize = 0;
         slowBuffer = 0;
         return 0;
      }
      slowBuffer = new char[slowBufferSize];
   }

   va_list sap;
   R__VA_COPY(sap, ap);

   int n = vsnprintf(slowBuffer, slowBufferSize, format, ap);
   // old vsnprintf's return -1 if string is truncated new ones return
   // total number of characters that would have been written
   if (n == -1 || n >= slowBufferSize) {
      if (n == -1) n = 2 * slowBufferSize;
      if (n == slowBufferSize) n++;
      if (n <= 0) {
         va_end(sap);
         return 0; // int overflow!
      }
      va_end(ap);
      R__VA_COPY(ap, sap);
      char *buf = SlowFormat(format, ap, n);
      va_end(sap);
      va_end(ap);
      return buf;
   }

   va_end(sap);

   return slowBuffer;
}

//______________________________________________________________________________
static char *Format(const char *format, va_list ap)
{
   // Format a string in a circular formatting buffer (using a printf style
   // format descriptor).

   static const int cb_size  = 4096;
   static const int fld_size = 2048;

   // a circular formating buffer
   TTHREAD_TLS_ARRAY(char,cb_size,gFormbuf); // gFormbuf[cb_size]; // some slob for form overflow
   TTHREAD_TLS(char*) gBfree(0);
   TTHREAD_TLS(char*) gEndbuf(0);

   if (gBfree == 0) {
      gBfree = gFormbuf;
      gEndbuf = &gFormbuf[cb_size-1];
   }
   char *buf = gBfree;

   if (buf+fld_size > gEndbuf)
      buf = gFormbuf;

   va_list sap;
   R__VA_COPY(sap, ap);

   int n = vsnprintf(buf, fld_size, format, ap);
   // old vsnprintf's return -1 if string is truncated new ones return
   // total number of characters that would have been written
   if (n == -1 || n >= fld_size) {
      va_end(ap);
      R__VA_COPY(ap, sap);
      buf = SlowFormat(format, ap, n);
      va_end(sap);
      va_end(ap);
      return buf;
   }

   va_end(sap);

   gBfree = buf+n+1;
   return buf;
}

//______________________________________________________________________________
char *Form(const char *va_(fmt), ...)
{
   // Formats a string in a circular formatting buffer. Removes the need to
   // create and delete short lived strings. Don't pass Form() pointers
   // from user code down to ROOT functions as the circular buffer may
   // be overwritten downstream. Use Form() results immediately or use
   // TString::Format() instead.

   va_list ap;
   va_start(ap,va_(fmt));
   char *b = Format(va_(fmt), ap);
   va_end(ap);
   return b;
}

//______________________________________________________________________________
void Printf(const char *va_(fmt), ...)
{
   // Formats a string in a circular formatting buffer and prints the string.
   // Appends a newline. If gPrintViaErrorHandler is true it will print via the
   // currently active ROOT error handler.

   va_list ap;
   va_start(ap,va_(fmt));
   if (gPrintViaErrorHandler)
      ErrorHandler(kPrint, 0, va_(fmt), ap);
   else {
      char *b = Format(va_(fmt), ap);
      printf("%s\n", b);
      fflush(stdout);
   }
   va_end(ap);
}

//______________________________________________________________________________
char *Strip(const char *s, char c)
{
   // Strip leading and trailing c (blanks by default) from a string.
   // The returned string has to be deleted by the user.

   if (!s) return 0;

   int l = strlen(s);
   char *buf = new char[l+1];

   if (l == 0) {
      *buf = '\0';
      return buf;
   }

   // get rid of leading c's
   const char *t1 = s;
   while (*t1 == c)
      t1++;

   // get rid of trailing c's
   const char *t2 = s + l - 1;
   while (*t2 == c && t2 > s)
      t2--;

   if (t1 > t2) {
      *buf = '\0';
      return buf;
   }
   strncpy(buf, t1, (Ssiz_t) (t2-t1+1));
   *(buf+(t2-t1+1)) = '\0';

   return buf;
}

//______________________________________________________________________________
char *StrDup(const char *str)
{
   // Duplicate the string str. The returned string has to be deleted by
   // the user.

   if (!str) return 0;

   char *s = new char[strlen(str)+1];
   if (s) strcpy(s, str);

   return s;
}

//______________________________________________________________________________
char *Compress(const char *str)
{
   // Remove all blanks from the string str. The returned string has to be
   // deleted by the user.

   if (!str) return 0;

   const char *p = str;
   char *s, *s1 = new char[strlen(str)+1];
   s = s1;

   while (*p) {
      if (*p != ' ')
         *s++ = *p;
      p++;
   }
   *s = '\0';

   return s1;
}

//______________________________________________________________________________
int EscChar(const char *src, char *dst, int dstlen, char *specchars,
            char escchar)
{
   // Escape specchars in src with escchar and copy to dst.

   const char *p;
   char *q, *end = dst+dstlen-1;

   for (p = src, q = dst; *p && q < end; ) {
      if (strchr(specchars, *p)) {
         *q++ = escchar;
         if (q < end)
            *q++ = *p++;
      } else
         *q++ = *p++;
   }
   *q = '\0';

   if (*p != 0)
      return -1;
   return q-dst;
}

//______________________________________________________________________________
int UnEscChar(const char *src, char *dst, int dstlen, char *specchars, char)
{
   // Un-escape specchars in src from escchar and copy to dst.

   const char *p;
   char *q, *end = dst+dstlen-1;

   for (p = src, q = dst; *p && q < end; ) {
      if (strchr(specchars, *p))
         p++;
      else
         *q++ = *p++;
   }
   *q = '\0';

   if (*p != 0)
      return -1;
   return q-dst;
}

#ifdef NEED_STRCASECMP
//______________________________________________________________________________
int strcasecmp(const char *str1, const char *str2)
{
   // Case insensitive string compare.

   return strncasecmp(str1, str2, str2 ? strlen(str2)+1 : 0);
}

//______________________________________________________________________________
int strncasecmp(const char *str1, const char *str2, Ssiz_t n)
{
   // Case insensitive string compare of n characters.

   while (n > 0) {
      int c1 = *str1;
      int c2 = *str2;

      if (isupper(c1))
         c1 = tolower(c1);

      if (isupper(c2))
         c2 = tolower(c2);

      if (c1 != c2)
         return c1 - c2;

      str1++;
      str2++;
      n--;
   }
   return 0;
}
#endif

//______________________________________________________________________________
std::string cling::printValue(const TString* const /*p*/, const TString* const u,
                              const cling::Value& /*VPI*/) {
   // Print a TString in the cling interpreter:
   TString s = TString::Format("\"%s\"[%d]", u->Data(), (int)u->Length());
   return s.Data();
}
