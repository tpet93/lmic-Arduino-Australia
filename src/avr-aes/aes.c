/*
*	Encryption and decryption library for 8-bit Atmel AVR
*	Copyright (C) 2011-2012  D. Kilian
*	Copyright (C) 2003,2006  B. Poettering
*
*	This program is free software: you can redistribute it and/or modify
*	it under the terms of the GNU General Public License as published by
*	the Free Software Foundation, either version 3 of the License, or
*	(at your option) any later version.
*
*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.
*
*	You should have received a copy of the GNU General Public License
*	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*	The first implementation (SMALL) was written by D. Kilian. The other
*	three implementations (FANTASTIC, FURIOUS, FAST) are translated and
*	slightly modified assembler files that wrote B. Poettering.
*	Library is published under the terms of the GNU General Public
*	License. If you need AES code, but this license is unsuitable for
*	your project, feel free to contact authors.
*	D. Kilian: kontakt AT dominik.cc
*	B. Poettering: avraes AT point-at-infinity.org
*/

#include <avr/pgmspace.h>

#include "aes.h"

#define SBOX_DATA_INIT \
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76, \
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0, \
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15, \
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75, \
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84, \
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf, \
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8, \
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2, \
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73, \
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb, \
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79, \
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08, \
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a, \
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e, \
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf, \
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,

#define ISBOX_DATA_INIT \
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb, \
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb, \
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e, \
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25, \
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92, \
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84, \
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06, \
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b, \
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73, \
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e, \
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b, \
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4, \
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f, \
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef, \
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61, \
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,


#if AES_IMPLEMENTATION == 0



/************************************************************************/
/*   SMALL                                                 by D. Kilian */
/************************************************************************/




typedef unsigned char byte;

static byte Rcon;

#ifdef AES_USEASM
	#define GF28_MUL2(a) { asm ("lsl %0 \n brcc .+2 \n eor %0, %1 \n" : "=r" (a) : "r" (c0x1b), "0" (a)); }
	#define GF28_DIV2(a) { asm ("lsr %0 \n brcc .+2 \n eor %0, %1 \n" : "=r" (a) : "r" (c0x8d), "0" (a)); }
#else
	#define GF28_MUL2(a) { if (a&0x80) { a = (a<<1) ^ 0x1b; } else { a <<= 1; } }
	#define GF28_DIV2(a) { if (a&0x01) { a = (a>>1) ^ 0x8d; } else { a >>= 1; } }
#endif


#if AES_SHORTSBOX
	#define SBOXTYPE 2  // funkcja
#else
	#define SBOXTYPE 1  // tablica
#endif


#if AES_INVCIPHER
	#if AES_SHORTINVSBOX
		#define INVSBOXTYPE 2  // funkcja
	#else
		#define INVSBOXTYPE 1  // tablica
	#endif
#else
	#define INVSBOXTYPE 0      // brak
#endif


#if SBOXTYPE==2 && INVSBOXTYPE!=2 
#if AES_SHORTSBOXSIZE > 192
#undef SBOXTYPE
#define SBOXTYPE 1
#endif
#endif

#if SBOXTYPE!=2 && INVSBOXTYPE==2
#if AES_SHORTSBOXSIZE > 192
#undef INVSBOXTYPE
#define INVSBOXTYPE 1
#endif
#endif


#if SBOXTYPE==1
	static const byte Sbox[] PROGMEM = { SBOX_DATA_INIT };
	#define SBOX(x) (pgm_read_byte(Sbox+(x)))
#endif


#if INVSBOXTYPE==1
	static const byte InvSbox[] PROGMEM = { ISBOX_DATA_INIT };
	#define INVSBOX(x) (pgm_read_byte(InvSbox+(x)))
#endif


#if SBOXTYPE==2 && INVSBOXTYPE==2
	#define SBOX(x) (aesCalcSbox((x),0))
	#define INVSBOX(x) (aesCalcSbox((x),1))
#else
	#if SBOXTYPE==2
		#define SBOX(x) (aesCalcSbox(x))
	#endif
	#if INVSBOXTYPE==2
		#define INVSBOX(x) (aesCalcSbox(x))
	#endif
#endif


#if SBOXTYPE==2 || INVSBOXTYPE==2

#if AES_SHORTSBOXSIZE < 10
#error AES_SHORTSBOXSIZE too small
#endif

#if AES_SHORTSBOXSIZE > 256
#undef AES_SHORTSBOXSIZE
#define AES_SHORTSBOXSIZE 256
#endif

static const byte invGf28[AES_SHORTSBOXSIZE] PROGMEM = {
	0x00,0x01,0x8d,0xf6,
	0xcb,0x52,0x7b,0xd1,
	0xe8,0x4f,
	#if AES_SHORTSBOXSIZE > 10
	0x29,0xc0,
	#endif
	#if AES_SHORTSBOXSIZE > 12
	0xb0,0xe1,0xe5,0xc7,
	#endif
	#if AES_SHORTSBOXSIZE > 16
	0x74,0xb4,0xaa,0x4b,
	#endif
	#if AES_SHORTSBOXSIZE > 20
	0x99,0x2b,0x60,0x5f,
	#endif
	#if AES_SHORTSBOXSIZE > 24
	0x58,0x3f,0xfd,0xcc,
	#endif
	#if AES_SHORTSBOXSIZE > 28
	0xff,0x40,0xee,0xb2,
	#endif
	#if AES_SHORTSBOXSIZE > 32
	0x3a,0x6e,0x5a,0xf1,
	#endif
	#if AES_SHORTSBOXSIZE > 36
	0x55,0x4d,0xa8,0xc9,
	#endif
	#if AES_SHORTSBOXSIZE > 40
	0xc1,0x0a,0x98,0x15,
	#endif
	#if AES_SHORTSBOXSIZE > 44
	0x30,0x44,0xa2,0xc2,
	#endif
	#if AES_SHORTSBOXSIZE > 48
	0x2c,0x45,0x92,0x6c,
	#endif
	#if AES_SHORTSBOXSIZE > 52
	0xf3,0x39,0x66,0x42,
	#endif
	#if AES_SHORTSBOXSIZE > 56
	0xf2,0x35,0x20,0x6f,
	#endif
	#if AES_SHORTSBOXSIZE > 60
	0x77,0xbb,0x59,0x19,
	#endif
	#if AES_SHORTSBOXSIZE > 64
	0x1d,0xfe,0x37,0x67,
	#endif
	#if AES_SHORTSBOXSIZE > 68
	0x2d,0x31,0xf5,0x69,
	#endif
	#if AES_SHORTSBOXSIZE > 72
	0xa7,0x64,0xab,0x13,
	#endif
	#if AES_SHORTSBOXSIZE > 76
	0x54,0x25,0xe9,0x09,
	#endif
	#if AES_SHORTSBOXSIZE > 80
	0xed,0x5c,0x05,0xca,
	#endif
	#if AES_SHORTSBOXSIZE > 84
	0x4c,0x24,0x87,0xbf,
	#endif
	#if AES_SHORTSBOXSIZE > 88
	0x18,0x3e,0x22,0xf0,
	#endif
	#if AES_SHORTSBOXSIZE > 92
	0x51,0xec,0x61,0x17,
	#endif
	#if AES_SHORTSBOXSIZE > 96
	0x16,0x5e,0xaf,0xd3,
	#endif
	#if AES_SHORTSBOXSIZE > 100
	0x49,0xa6,0x36,0x43,
	#endif
	#if AES_SHORTSBOXSIZE > 104
	0xf4,0x47,0x91,0xdf,
	#endif
	#if AES_SHORTSBOXSIZE > 108
	0x33,0x93,0x21,0x3b,
	#endif
	#if AES_SHORTSBOXSIZE > 112
	0x79,0xb7,0x97,0x85,
	#endif
	#if AES_SHORTSBOXSIZE > 116
	0x10,0xb5,0xba,0x3c,
	#endif
	#if AES_SHORTSBOXSIZE > 120
	0xb6,0x70,0xd0,0x06,
	#endif
	#if AES_SHORTSBOXSIZE > 124
	0xa1,0xfa,0x81,0x82,
	#endif
	#if AES_SHORTSBOXSIZE > 128
	0x83,0x7e,0x7f,0x80,
	#endif
	#if AES_SHORTSBOXSIZE > 132
	0x96,0x73,0xbe,0x56,
	#endif
	#if AES_SHORTSBOXSIZE > 136
	0x9b,0x9e,0x95,0xd9,
	#endif
	#if AES_SHORTSBOXSIZE > 140
	0xf7,0x02,0xb9,0xa4,
	#endif
	#if AES_SHORTSBOXSIZE > 144
	0xde,0x6a,0x32,0x6d,
	#endif
	#if AES_SHORTSBOXSIZE > 148
	0xd8,0x8a,0x84,0x72,
	#endif
	#if AES_SHORTSBOXSIZE > 152
	0x2a,0x14,0x9f,0x88,
	#endif
	#if AES_SHORTSBOXSIZE > 156
	0xf9,0xdc,0x89,0x9a,
	#endif
	#if AES_SHORTSBOXSIZE > 160
	0xfb,0x7c,0x2e,0xc3,
	#endif
	#if AES_SHORTSBOXSIZE > 164
	0x8f,0xb8,0x65,0x48,
	#endif
	#if AES_SHORTSBOXSIZE > 168
	0x26,0xc8,0x12,0x4a,
	#endif
	#if AES_SHORTSBOXSIZE > 172
	0xce,0xe7,0xd2,0x62,
	#endif
	#if AES_SHORTSBOXSIZE > 176
	0x0c,0xe0,0x1f,0xef,
	#endif
	#if AES_SHORTSBOXSIZE > 180
	0x11,0x75,0x78,0x71,
	#endif
	#if AES_SHORTSBOXSIZE > 184
	0xa5,0x8e,0x76,0x3d,
	#endif
	#if AES_SHORTSBOXSIZE > 188
	0xbd,0xbc,0x86,0x57,
	#endif
	#if AES_SHORTSBOXSIZE > 192
	0x0b,0x28,0x2f,0xa3,
	#endif
	#if AES_SHORTSBOXSIZE > 196
	0xda,0xd4,0xe4,0x0f,
	#endif
	#if AES_SHORTSBOXSIZE > 200
	0xa9,0x27,0x53,0x04,
	#endif
	#if AES_SHORTSBOXSIZE > 204
	0x1b,0xfc,0xac,0xe6,
	#endif
	#if AES_SHORTSBOXSIZE > 208
	0x7a,0x07,0xae,0x63,
	#endif
	#if AES_SHORTSBOXSIZE > 212
	0xc5,0xdb,0xe2,0xea,
	#endif
	#if AES_SHORTSBOXSIZE > 216
	0x94,0x8b,0xc4,0xd5,
	#endif
	#if AES_SHORTSBOXSIZE > 220
	0x9d,0xf8,0x90,0x6b,
	#endif
	#if AES_SHORTSBOXSIZE > 224
	0xb1,0x0d,0xd6,0xeb,
	#endif
	#if AES_SHORTSBOXSIZE > 228
	0xc6,0x0e,0xcf,0xad,
	#endif
	#if AES_SHORTSBOXSIZE > 232
	0x08,0x4e,0xd7,0xe3,
	#endif
	#if AES_SHORTSBOXSIZE > 236
	0x5d,0x50,0x1e,0xb3,
	#endif
	#if AES_SHORTSBOXSIZE > 240
	0x5b,0x23,0x38,0x34,
	#endif
	#if AES_SHORTSBOXSIZE > 244
	0x68,0x46,0x03,0x8c,
	#endif
	#if AES_SHORTSBOXSIZE > 248
	0xdd,0x9c,0x7d,0xa0,
	#endif
	#if AES_SHORTSBOXSIZE > 252
	0xcd,0x1a,0x41,0x1c,
	#endif
};

#if SBOXTYPE==2 && INVSBOXTYPE==2

static byte aesCalcSbox(byte x, byte inv)
{
	byte c0x1b = 0x1b;
	byte a, b;

	if (inv) {
		x ^= 0x63;
		a = 0;
		b = 0x4a;
matxor:
		while (x) {
			if (x&1) a ^= b;
			#ifdef AES_USEASM
			asm ("lsl %0 \n brcc .+2 \n ori %0, 1" : "=d" (b) : "0" (b));
			#else
			b = (b<<1) | (b>>7);
			#endif
			x >>= 1;
		}
		if (!inv) return a;
		x = a;
	}
	
	#if AES_SHORTSBOXSIZE < 256
		a = 0;
		while (x >= AES_SHORTSBOXSIZE) {
			GF28_MUL2(x);
			a++;
		}
		x = pgm_read_byte(invGf28 + x);
		while (a--) GF28_MUL2(x);
	#else
		x = pgm_read_byte(invGf28 + x);
	#endif

	if (!inv) {
		a = 0x63;
		b = 0x1f;
		goto matxor;
	}
	return x;
}

#elif SBOXTYPE==2

static byte aesCalcSbox(byte x)
{
	byte c0x1b = 0x1b;
	byte a, b;
	
	a = 0;
	while (x >= AES_SHORTSBOXSIZE) {
		GF28_MUL2(x);
		a++;
	}
	x = pgm_read_byte(invGf28 + x);
	while (a--) GF28_MUL2(x);
	// x^-1 = a2

	a = 0x63;
	b = 0x1f;
	while (x) {
		if (x&1) a ^= b;
		#ifdef AES_USEASM
		asm ("lsl %0 \n brcc .+2 \n ori %0, 1" : "=d" (b) : "0" (b));
		#else
		b = (b<<1) | (b>>7);
		#endif
		x >>= 1;
	}
	return a;
}

#elif INVSBOXTYPE==2

static byte aesCalcSbox(byte x)
{
	byte c0x1b = 0x1b;
	byte a, b;

	x ^= 0x63;
	a = 0;
	b = 0x4a;
	while (x) {
		if (x&1) a ^= b;
		#ifdef AES_USEASM
		asm ("lsl %0 \n brcc .+2 \n ori %0, 1" : "=d" (b) : "0" (b));
		#else
		b = (b<<1) | (b>>7);
		#endif
		x >>= 1;
	}

	b = 0;
	while (a >= AES_SHORTSBOXSIZE) {
		GF28_MUL2(a);
		b++;
	}
	a = pgm_read_byte(invGf28 + a);
	while (b--) GF28_MUL2(a);

	return a;
}

#endif

#endif


#if AES_CIPHER || AES_KEYPATCH

static void aesAddRoundKey(byte* state, byte* key)
{
	byte c0x1b = 0x1b;
	byte *ptr;
	byte a, b, c, d, t, i;
	for (i = 0; i < 16; i+=4) {
		ptr = key + ((i-4)&12);
		a = ptr[0];
		b = ptr[1];
		c = ptr[2];
		d = ptr[3];
		if (i == 0) {
			t = b;
			b = SBOX(c);
			c = SBOX(d);
			d = SBOX(a);
			a = SBOX(t) ^ Rcon;
			GF28_MUL2(Rcon);
		}
		ptr = key + i;
		t = ptr[0]; ptr[0] = a ^ t; a = t;
		t = ptr[1]; ptr[1] = b ^ t; b = t;
		t = ptr[2]; ptr[2] = c ^ t; c = t;
		t = ptr[3]; ptr[3] = d ^ t; d = t;
		if (state) {
			*state++ ^= a;
			*state++ ^= b;
			*state++ ^= c;
			*state++ ^= d;
		}
	}
}

#endif

#if AES_INVCIPHER || AES_KEYREWIND

static void aesInvAddRoundKey(byte* state, byte* key)
{
	byte c0x8d = 0x8d;
	byte *ptr;
	byte a, b, c, d, t, i;
	for (i = 12; !(i&0x80); i-=4) {
		ptr = key + ((i-4)&12);
		a = ptr[0];
		b = ptr[1];
		c = ptr[2];
		d = ptr[3];
		if (i == 0) {
			GF28_DIV2(Rcon);
			t = a;
			a = SBOX(b) ^ Rcon;
			b = SBOX(c);
			c = SBOX(d);
			d = SBOX(t);
		}
		ptr = key + i;
		a ^= ptr[0]; ptr[0] = a;
		b ^= ptr[1]; ptr[1] = b;
		c ^= ptr[2]; ptr[2] = c;
		d ^= ptr[3]; ptr[3] = d;
		if (state) {
			ptr = state + i;
			ptr[0] ^= a;
			ptr[1] ^= b;
			ptr[2] ^= c;
			ptr[3] ^= d;
		}			
	}
	
}

#endif


#if AES_CIPHER
static void aesSubBytes(byte* state)
{
	byte i;
	for (i=0; i<16; i++) {
		*state = SBOX(*state);
		state++;
	}
}
#endif

#if AES_INVCIPHER
static void aesInvSubBytes(byte* state)
{
	byte i;
	for (i=0; i<16; i++) {
		*state = INVSBOX(*state);
		state++;
	}
}
#endif


#if AES_FASTSHROWS

#if AES_CIPHER
static void aesShiftRows(byte* state)
{
	byte t;
	t = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = t;
	t = state[10];
	state[10] = state[2];
	state[2] = t;
	t = state[14];
	state[14] = state[6];
	state[6] = t;
	t = state[3];
	state[3] = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = t;
}
#endif


#if AES_INVCIPHER
static void aesInvShiftRows(byte* state)
{
	byte t;
	t = state[1];
	state[1] = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = t;
	t = state[10];
	state[10] = state[2];
	state[2] = t;
	t = state[14];
	state[14] = state[6];
	state[6] = t;
	t = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = t;
}
#endif

#else 

#if AES_CIPHER && AES_INVCIPHER

#define aesShiftRows(s) aesShiftRows_B((s),0)
#define aesInvShiftRows(s) aesShiftRows_B((s),1)

static void aesShiftRows_B(byte* state, byte inv)

#elif AES_CIPHER

static void aesShiftRows(byte* state)

#else

static void aesInvShiftRows(byte* state)

#endif
{
	#if !AES_CIPHER || !AES_INVCIPHER
		#if AES_CIPHER
			byte inv = 0;
		#else
			byte inv = 1;
		#endif
	#endif
	byte *ptr;
	byte i, j, k, t;
	for (i=1; i<4; i++) {
		for (j=i; j<4; j++) {
			ptr = state + j;
			if (inv) ptr += 8;
			for (k=j; k<12; k+=4) {
				t = ptr[0];
				ptr[0] = ptr[4];
				ptr[4] = t;
				if (inv) {
					ptr -= 4;
				} else {
					ptr += 4;
				}
			}
		}
	}
}

#endif

#if !AES_CIPHER || !AES_INVCIPHER
#undef AES_FASTMIXCOL
#define AES_FASTMIXCOL 1
#endif

#if AES_FASTMIXCOL

#if AES_CIPHER
static void aesMixColumns(byte* state)
{
	byte c0x1b = 0x1b;
	byte i, a0, a1, a2, a3, sum, b;
	byte* ptr = state;
	for (i = 0; i < 16; i+=4) {
		a0 = ptr[0];
		a1 = ptr[1];
		a2 = ptr[2];
		a3 = ptr[3];
		sum = a0 ^ a1 ^ a2 ^ a3;
		b = a0^a1; GF28_MUL2(b);
		*ptr++ = sum ^ a0 ^ b;
		b = a1^a2; GF28_MUL2(b);
		*ptr++ = sum ^ a1 ^ b;
		b = a2^a3; GF28_MUL2(b);
		*ptr++ = sum ^ a2 ^ b;
		b = a3^a0; GF28_MUL2(b);
		*ptr++ = sum ^ a3 ^ b;
	}
}
#endif


#if AES_INVCIPHER
void aesInvMixColumns(byte* state)
{
	byte c0x1b = 0x1b;
	byte i, a0, a1, a2, a3, sum, b, c, d, e;
	byte* ptr = state;
	for(i = 0; i < 16; i+=4)
	{
		a0 = ptr[0];
		a1 = ptr[1];
		a2 = ptr[2];
		a3 = ptr[3];
		sum = a0 ^ a1 ^ a2 ^ a3;
		c = sum; GF28_MUL2(c);
		d = c ^ a0 ^ a2; GF28_MUL2(d); GF28_MUL2(d);
		d ^= sum;
		e = c ^ a1 ^ a3; GF28_MUL2(e); GF28_MUL2(e);
		e ^= sum;
		b = a0^a1; GF28_MUL2(b);
		*ptr++ = d ^ a0 ^ b;
		b = a1^a2; GF28_MUL2(b);
		*ptr++ = e ^ a1 ^ b;
		b = a2^a3; GF28_MUL2(b);
		*ptr++ = d ^ a2 ^ b;
		b = a3^a0; GF28_MUL2(b);
		*ptr++ = e ^ a3 ^ b;
	}
}
#endif

#else

#define aesMixColumns(state) aesMixColumns_B(state, 0)
#define aesInvMixColumns(state) aesMixColumns_B(state, 1)

void aesMixColumns_B(byte* state, byte inv) 
{
	byte c0x1b = 0x1b;
	byte i, a0, a1, a2, a3, sum, b, c, d, e;
	byte* ptr = state;
	for(i = 0; i < 16; i+=4)
	{
		a0 = ptr[0];
		a1 = ptr[1];
		a2 = ptr[2];
		a3 = ptr[3];
		sum = a0 ^ a1 ^ a2 ^ a3;
		if (inv) {
			c = sum; GF28_MUL2(c);
			d = c ^ a0 ^ a2; GF28_MUL2(d); GF28_MUL2(d);
			d ^= sum;
			e = c ^ a1 ^ a3; GF28_MUL2(e); GF28_MUL2(e);
			e ^= sum;
		} else {
			d = e = sum;
		}			
		b = a0^a1; GF28_MUL2(b);
		*ptr++ = d ^ a0 ^ b;
		b = a1^a2; GF28_MUL2(b);
		*ptr++ = e ^ a1 ^ b;
		b = a2^a3; GF28_MUL2(b);
		*ptr++ = d ^ a2 ^ b;
		b = a3^a0; GF28_MUL2(b);
		*ptr++ = e ^ a3 ^ b;
	}
}


#endif


#if AES_CIPHER
void aesCipher(unsigned char* key, unsigned char* state)
{
	byte r;

	Rcon = 1;

	for (r = 0; r < 11; r++) {
		if (r) {
			aesSubBytes(state);
			aesShiftRows(state);
			if (r != 10) aesMixColumns(state);
		}
		aesAddRoundKey(state, key);
	}

}
#endif


#if AES_INVCIPHER
void aesInvCipher(unsigned char* patched, unsigned char* state)
{
	byte r;

	Rcon = 0xD8;

	for (r = 10; !(r&0x80); r--) {
		aesInvAddRoundKey(state, patched);
		if (r) {
			if (r != 10) aesInvMixColumns(state);
			aesInvShiftRows(state);
			aesInvSubBytes(state);
		}
	}

}
#endif


#if AES_KEYREWIND
void aesKeyRewind(unsigned char* patched)
{
	byte r;
	Rcon = 0xD8;
	for (r = 0; r < 11; r++) {
		aesInvAddRoundKey(0, patched);
	}		
}
#endif


#if AES_KEYPATCH
void aesKeyPatch(unsigned char* key)
{
	byte r;
	Rcon = 1;
	for (r = 0; r < 11; r++) {
		aesAddRoundKey(0, key);
	}
}
#endif




#elif AES_IMPLEMENTATION == 4 && AES_CIPHER


/************************************************************************/
/*   MINI                                                  by D. Kilian */
/************************************************************************/


#define A "r16"
#define t3 "r17"
#define t4 "r18"
#define B "r20"
#define Rcon "r21"
#define t1 "r24"
#define t2 "r25"
#define Xlo "r26"
#define Xhi "r27"
#define Ylo "r28"
#define Yhi "r29"
#define Zlo "r30"
#define Zhi "r31"

#if AES_SHORTSBOX
#if AES_SHORTSBOXSIZE > 216
#undef AES_SHORTSBOX
#define AES_SHORTSBOX 0
#endif
#endif


#if AES_SHORTSBOX

const unsigned char aes_tab_invGf28[AES_SHORTSBOXSIZE] PROGMEM = {
	0x00,0x01,0x8d,0xf6,
	0xcb,0x52,0x7b,0xd1,
	0xe8,0x4f,
	#if AES_SHORTSBOXSIZE > 10
	0x29,0xc0,
	#endif
	#if AES_SHORTSBOXSIZE > 12
	0xb0,0xe1,0xe5,0xc7,
	#endif
	#if AES_SHORTSBOXSIZE > 16
	0x74,0xb4,0xaa,0x4b,
	#endif
	#if AES_SHORTSBOXSIZE > 20
	0x99,0x2b,0x60,0x5f,
	#endif
	#if AES_SHORTSBOXSIZE > 24
	0x58,0x3f,0xfd,0xcc,
	#endif
	#if AES_SHORTSBOXSIZE > 28
	0xff,0x40,0xee,0xb2,
	#endif
	#if AES_SHORTSBOXSIZE > 32
	0x3a,0x6e,0x5a,0xf1,
	#endif
	#if AES_SHORTSBOXSIZE > 36
	0x55,0x4d,0xa8,0xc9,
	#endif
	#if AES_SHORTSBOXSIZE > 40
	0xc1,0x0a,0x98,0x15,
	#endif
	#if AES_SHORTSBOXSIZE > 44
	0x30,0x44,0xa2,0xc2,
	#endif
	#if AES_SHORTSBOXSIZE > 48
	0x2c,0x45,0x92,0x6c,
	#endif
	#if AES_SHORTSBOXSIZE > 52
	0xf3,0x39,0x66,0x42,
	#endif
	#if AES_SHORTSBOXSIZE > 56
	0xf2,0x35,0x20,0x6f,
	#endif
	#if AES_SHORTSBOXSIZE > 60
	0x77,0xbb,0x59,0x19,
	#endif
	#if AES_SHORTSBOXSIZE > 64
	0x1d,0xfe,0x37,0x67,
	#endif
	#if AES_SHORTSBOXSIZE > 68
	0x2d,0x31,0xf5,0x69,
	#endif
	#if AES_SHORTSBOXSIZE > 72
	0xa7,0x64,0xab,0x13,
	#endif
	#if AES_SHORTSBOXSIZE > 76
	0x54,0x25,0xe9,0x09,
	#endif
	#if AES_SHORTSBOXSIZE > 80
	0xed,0x5c,0x05,0xca,
	#endif
	#if AES_SHORTSBOXSIZE > 84
	0x4c,0x24,0x87,0xbf,
	#endif
	#if AES_SHORTSBOXSIZE > 88
	0x18,0x3e,0x22,0xf0,
	#endif
	#if AES_SHORTSBOXSIZE > 92
	0x51,0xec,0x61,0x17,
	#endif
	#if AES_SHORTSBOXSIZE > 96
	0x16,0x5e,0xaf,0xd3,
	#endif
	#if AES_SHORTSBOXSIZE > 100
	0x49,0xa6,0x36,0x43,
	#endif
	#if AES_SHORTSBOXSIZE > 104
	0xf4,0x47,0x91,0xdf,
	#endif
	#if AES_SHORTSBOXSIZE > 108
	0x33,0x93,0x21,0x3b,
	#endif
	#if AES_SHORTSBOXSIZE > 112
	0x79,0xb7,0x97,0x85,
	#endif
	#if AES_SHORTSBOXSIZE > 116
	0x10,0xb5,0xba,0x3c,
	#endif
	#if AES_SHORTSBOXSIZE > 120
	0xb6,0x70,0xd0,0x06,
	#endif
	#if AES_SHORTSBOXSIZE > 124
	0xa1,0xfa,0x81,0x82,
	#endif
	#if AES_SHORTSBOXSIZE > 128
	0x83,0x7e,0x7f,0x80,
	#endif
	#if AES_SHORTSBOXSIZE > 132
	0x96,0x73,0xbe,0x56,
	#endif
	#if AES_SHORTSBOXSIZE > 136
	0x9b,0x9e,0x95,0xd9,
	#endif
	#if AES_SHORTSBOXSIZE > 140
	0xf7,0x02,0xb9,0xa4,
	#endif
	#if AES_SHORTSBOXSIZE > 144
	0xde,0x6a,0x32,0x6d,
	#endif
	#if AES_SHORTSBOXSIZE > 148
	0xd8,0x8a,0x84,0x72,
	#endif
	#if AES_SHORTSBOXSIZE > 152
	0x2a,0x14,0x9f,0x88,
	#endif
	#if AES_SHORTSBOXSIZE > 156
	0xf9,0xdc,0x89,0x9a,
	#endif
	#if AES_SHORTSBOXSIZE > 160
	0xfb,0x7c,0x2e,0xc3,
	#endif
	#if AES_SHORTSBOXSIZE > 164
	0x8f,0xb8,0x65,0x48,
	#endif
	#if AES_SHORTSBOXSIZE > 168
	0x26,0xc8,0x12,0x4a,
	#endif
	#if AES_SHORTSBOXSIZE > 172
	0xce,0xe7,0xd2,0x62,
	#endif
	#if AES_SHORTSBOXSIZE > 176
	0x0c,0xe0,0x1f,0xef,
	#endif
	#if AES_SHORTSBOXSIZE > 180
	0x11,0x75,0x78,0x71,
	#endif
	#if AES_SHORTSBOXSIZE > 184
	0xa5,0x8e,0x76,0x3d,
	#endif
	#if AES_SHORTSBOXSIZE > 188
	0xbd,0xbc,0x86,0x57,
	#endif
	#if AES_SHORTSBOXSIZE > 192
	0x0b,0x28,0x2f,0xa3,
	#endif
	#if AES_SHORTSBOXSIZE > 196
	0xda,0xd4,0xe4,0x0f,
	#endif
	#if AES_SHORTSBOXSIZE > 200
	0xa9,0x27,0x53,0x04,
	#endif
	#if AES_SHORTSBOXSIZE > 204
	0x1b,0xfc,0xac,0xe6,
	#endif
	#if AES_SHORTSBOXSIZE > 208
	0x7a,0x07,0xae,0x63,
	#endif
	#if AES_SHORTSBOXSIZE > 212
	0xc5,0xdb,0xe2,0xea,
	#endif
};

#else

const unsigned char aes_tab_sbox[] PROGMEM = { SBOX_DATA_INIT };
	
#ifdef AES_SHORTSBOXSIZE
#undef AES_SHORTSBOXSIZE
#endif
#define AES_SHORTSBOXSIZE 10

#endif

char aesTempBuffer[21];

void aesCipher(const unsigned char* key, unsigned char* data)
{
	asm volatile (
		"	rcall swapState			\n"
		"	push "Xlo"			\n"
		"	push "Xhi"			\n"
		"	ldi "Ylo", lo8(aesTempBuffer+5)			\n"
		"	ldi "Yhi", hi8(aesTempBuffer+5)			\n"
		"loadkeyloop:			\n"
		"		ld "t1", Z+			\n"
		"		st Y+, "t1"			\n"
		"		cpi "Ylo", lo8(aesTempBuffer+21)			\n"
		"		brne loadkeyloop			\n"
		"	ldi "Rcon", 1			\n"
		"mainloop:			\n"
		"		ldi "Ylo", lo8(aesTempBuffer+4)			\n"
		"		ldi "Yhi", hi8(aesTempBuffer+4)			\n"
		"inckeyloop1:			\n"
		"			ldd "t1", Y+16			\n"
		"			rcall sbox			\n"
		"			st -Y, "t1"			\n"
		"			cpi "Ylo", lo8(aesTempBuffer)			\n"
		"			brne inckeyloop1			\n"
		"		adiw "Ylo", 1			\n"
		"		std Y+3, "t1"			\n"
		"		ld "t1", Y			\n"
		"		eor "t1", "Rcon"			\n"
		"		st Y, "t1"			\n"
		"		mov "t1", "Rcon"			\n"
		"		rcall gf28mul2			\n"
		"		mov "Rcon", "t1"			\n"
		"		clr "Xlo"			\n"
		"		clr "Xhi"			\n"
		"addkeyloop1:			\n"
		"			ldd "t4", Y+4			\n"
		"			ld "t1", X			\n"
		"			eor "t1", "t4"			\n"
		"			cpi "Rcon", 0xD8			\n"
		"			breq .+2			\n"
		"			rcall sbox			\n"
		"			st X+, "t1"			\n"
		"			ld "t1", Y+			\n"
		"			eor "t1", "t4"			\n"
		"			std Y+3, "t1"			\n"
		"			cpi "Xlo", 16			\n"
		"			brne addkeyloop1			\n"
		"		cpi "Rcon", 0xD8			\n"
		"		breq endofmainloop			\n"
		"		mov r17, r1			\n"
		"		movw r18, r2			\n"
		"		movw r22, r6			\n"
		"		mov r27, r11			\n"
		"		clr "Zhi"			\n"
		//"		clr "Zlo"			\n" <-- Zlo == 0 after sbox
		"mixloop1:			\n"
		"			clr "Xlo"			\n"
		"			rcall shiftload			\n"
		"			mov "A", "Yhi"			\n"
		"			rcall shiftload			\n"
		"			mov "B", "Yhi"			\n"
		"			rcall shiftload			\n"
		"			mov "Ylo", "Yhi"			\n"
		"			rcall shiftload			\n"
		"			sbiw "Zlo", 20			\n"
		"mixloop2:			\n"
		"				mov "t1", "A"			\n"
		"				eor "t1", "B"			\n"
		"				rcall gf28mul2			\n"
		"				eor "t1", "A"			\n"
		"				eor "t1", "Xlo"			\n"
		"				cpi "Rcon", 0x6C			\n"
		"				brne .+2			\n"
		"					mov "t1", "A"			\n"
		"				st Z+, "t1"			\n"
		"				mov "t1", "A"			\n"
		"				mov "A", "B"			\n"
		"				mov "B", "Ylo"			\n"
		"				mov "Ylo", "Yhi"			\n"
		"				mov "Yhi", "t1"			\n"
		"				mov "t1", "Zlo"			\n"
		"				andi "t1", 0x03			\n"
		"				brne mixloop2			\n"
		"			cpi "Zlo", 16			\n"
		"			brne mixloop1			\n"
		"		rjmp mainloop			\n"
		"endofmainloop:			\n"
		"	pop "Xhi"			\n"
		"	pop "Xlo"			\n"
		"	rcall swapState			\n"
		"	rjmp endoffunc			\n"
		"shiftload:			\n"
		"	ld "Yhi", Z			\n"
		"	eor "Xlo", "Yhi"			\n"
		"	adiw "Zlo", 5			\n"
		"	ret			\n"
		"gf28mul2:			\n"
		"	ldi "t2", 0x1B			\n"
		"	lsl "t1"			\n"
		"	brcc .+2			\n"
		"	eor "t1", "t2"			\n"
		"	ret			\n"
		
#if AES_SHORTSBOX
		"sbox:			\n"
		"	clr "t3"			\n"
		"sboxloop1:			\n"
		"		rcall gf28mul2			\n"
		"		inc "t3"			\n"
		"		cpi "t1", %2			\n"
		"		brcc sboxloop1			\n"
		"	mov "Zlo", "t1"			\n"
		"	clr "Zhi"			\n"
		"	subi "Zlo",lo8(-(aes_tab_invGf28))			\n"
		"	sbci "Zhi",hi8(-(aes_tab_invGf28))			\n"
		"	lpm "t1", Z			\n"
		"sboxloop2:			\n"
		"		rcall gf28mul2			\n"
		"		dec "t3"			\n"
		"		brne sboxloop2			\n"
		"	mov "Zlo", "t1"			\n"
		"	ldi "t1", 0x63			\n"
		"	ldi "t3", 0x1f			\n"
		"sboxloop3:			\n"
		"		sbrc "Zlo", 0			\n"
		"		eor "t1", "t3"			\n"
		"		lsl "t3"			\n"
		"		brcc .+2			\n"
		"		ori "t3", 1			\n"
		"		lsr "Zlo"			\n"
		"		brne sboxloop3			\n"
		"	ret			\n"
#else
		"sbox:			\n"
		"	mov "Zlo", "t1"			\n"
		"	clr "Zhi"			\n"
		"	subi "Zlo",lo8(-(aes_tab_sbox))			\n"
		"	sbci "Zhi",hi8(-(aes_tab_sbox))			\n"
		"	lpm "t1", Z			\n"
		"	clr "Zlo"			\n"
		"	ret			\n"
#endif

		"swapState:			\n"
		"	clr "Ylo"			\n"
		"	clr "Yhi"			\n"
		"swaploop1:			\n"
		"		ld "t1", X			\n"
		"		ld "t2", Y			\n"
		"		st X+, "t2"			\n"
		"		st Y+, "t1"			\n"
		"		cpi "Ylo", 16			\n"
		"		brne swaploop1			\n"
		"	sbiw "Xlo", 16			\n"
		"	ret			\n"
		
		"endoffunc:			\n"
		
		: "+x" (data), "+z" (key)
		: "M" (AES_SHORTSBOXSIZE)
		: "memory",
		"r16", "r17", "r18", "r19", "r20", "r21",
		"r22", "r23", "r24", "r25", "r28", "r29"
	);
}





#elif AES_IMPLEMENTATION == 1


/************************************************************************/
/*   FANTASTIC                                         by B. Poettering */
/************************************************************************/




#if AES_CIPHER || AES_INVCIPHER
const char aes_tab_sbox[256] PROGMEM __attribute__ ((aligned(256))) = { SBOX_DATA_INIT };
#endif


#if AES_INVCIPHER
const char aes_tab_isbox[256] PROGMEM __attribute__ ((aligned(256))) = { ISBOX_DATA_INIT };
#endif


#define _H1 "r23"
#define _H2 "r0"
#define _H3 "r24"
#define _Rcon "r25"
#define _ST11 "r7"
#define _ST21 "r8"
#define _ST31 "r9"
#define _ST41 "r10"
#define _ST12 "r11"
#define _ST22 "r12"
#define _ST32 "r13"
#define _ST42 "r14"
#define _ST13 "r15"
#define _ST23 "r16"
#define _ST33 "r17"
#define _ST43 "r18"
#define _ST14 "r19"
#define _ST24 "r20"
#define _ST34 "r21"
#define _ST44 "r22"
#define _X "X"
#define _XH "r27"
#define _XL "r26"
#define _Y "Y"
#define _YH "r29"
#define _YL "r28"
#define _Z "Z"
#define _ZH "r31"
#define _ZL "r30"
#define _ST_START "7"
#define _ST_END "23"

	
#define COMMON	\
	"MixColumns:		\n"	\
	"mov "_H1", "_ST11"		\n"	\
	"eor "_H1", "_ST21"		\n"	\
	"mov "_ZL", "_H1"		\n"	\
	"eor "_H1", "_ST31"		\n"	\
	"eor "_H1", "_ST41"		\n"	\
	"mov "_H2", "_ST11"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST11", "_ZL"		\n"	\
	"eor "_ST11", "_H1"		\n"	\
	"mov "_ZL", "_ST21"		\n"	\
	"eor "_ZL", "_ST31"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST21", "_ZL"		\n"	\
	"eor "_ST21", "_H1"		\n"	\
	"mov "_ZL", "_ST31"		\n"	\
	"eor "_ZL", "_ST41"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST31", "_ZL"		\n"	\
	"eor "_ST31", "_H1"		\n"	\
	"mov "_ZL", "_ST41"		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST41", "_ZL"		\n"	\
	"eor "_ST41", "_H1"		\n"	\
	"mov "_H1", "_ST12"		\n"	\
	"eor "_H1", "_ST22"		\n"	\
	"mov "_ZL", "_H1"		\n"	\
	"eor "_H1", "_ST32"		\n"	\
	"eor "_H1", "_ST42"		\n"	\
	"mov "_H2", "_ST12"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST12", "_ZL"		\n"	\
	"eor "_ST12", "_H1"		\n"	\
	"mov "_ZL", "_ST22"		\n"	\
	"eor "_ZL", "_ST32"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST22", "_ZL"		\n"	\
	"eor "_ST22", "_H1"		\n"	\
	"mov "_ZL", "_ST32"		\n"	\
	"eor "_ZL", "_ST42"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST32", "_ZL"		\n"	\
	"eor "_ST32", "_H1"		\n"	\
	"mov "_ZL", "_ST42"		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST42", "_ZL"		\n"	\
	"eor "_ST42", "_H1"		\n"	\
	"mov "_H1", "_ST13"		\n"	\
	"eor "_H1", "_ST23"		\n"	\
	"mov "_ZL", "_H1"		\n"	\
	"eor "_H1", "_ST33"		\n"	\
	"eor "_H1", "_ST43"		\n"	\
	"mov "_H2", "_ST13"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST13", "_ZL"		\n"	\
	"eor "_ST13", "_H1"		\n"	\
	"mov "_ZL", "_ST23"		\n"	\
	"eor "_ZL", "_ST33"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST23", "_ZL"		\n"	\
	"eor "_ST23", "_H1"		\n"	\
	"mov "_ZL", "_ST33"		\n"	\
	"eor "_ZL", "_ST43"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST33", "_ZL"		\n"	\
	"eor "_ST33", "_H1"		\n"	\
	"mov "_ZL", "_ST43"		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST43", "_ZL"		\n"	\
	"eor "_ST43", "_H1"		\n"	\
	"mov "_H1", "_ST14"		\n"	\
	"eor "_H1", "_ST24"		\n"	\
	"mov "_ZL", "_H1"		\n"	\
	"eor "_H1", "_ST34"		\n"	\
	"eor "_H1", "_ST44"		\n"	\
	"mov "_H2", "_ST14"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST14", "_ZL"		\n"	\
	"eor "_ST14", "_H1"		\n"	\
	"mov "_ZL", "_ST24"		\n"	\
	"eor "_ZL", "_ST34"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST24", "_ZL"		\n"	\
	"eor "_ST24", "_H1"		\n"	\
	"mov "_ZL", "_ST34"		\n"	\
	"eor "_ZL", "_ST44"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST34", "_ZL"		\n"	\
	"eor "_ST34", "_H1"		\n"	\
	"mov "_ZL", "_ST44"		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"lsl "_ZL"		\n"	\
	"brcc .+2		\n"	\
	"eor "_ZL", "_H3"		\n"	\
	"eor "_ST44", "_ZL"		\n"	\
	"eor "_ST44", "_H1"		\n"	\
	"ret	\n"	\
	"AddRoundKey:		\n"	\
	"ld "_H1", "_Y"		\n"	\
	"eor "_ST11", "_H1"		\n"	\
	"ldd "_H1", "_Y"+1		\n"	\
	"eor "_ST21", "_H1"		\n"	\
	"ldd "_H1", "_Y"+2		\n"	\
	"eor "_ST31", "_H1"		\n"	\
	"ldd "_H1", "_Y"+3		\n"	\
	"eor "_ST41", "_H1"		\n"	\
	"ldd "_H1", "_Y"+4		\n"	\
	"eor "_ST12", "_H1"		\n"	\
	"ldd "_H1", "_Y"+5		\n"	\
	"eor "_ST22", "_H1"		\n"	\
	"ldd "_H1", "_Y"+6		\n"	\
	"eor "_ST32", "_H1"		\n"	\
	"ldd "_H1", "_Y"+7		\n"	\
	"eor "_ST42", "_H1"		\n"	\
	"ldd "_H1", "_Y"+8		\n"	\
	"eor "_ST13", "_H1"		\n"	\
	"ldd "_H1", "_Y"+9		\n"	\
	"eor "_ST23", "_H1"		\n"	\
	"ldd "_H1", "_Y"+10		\n"	\
	"eor "_ST33", "_H1"		\n"	\
	"ldd "_H1", "_Y"+11		\n"	\
	"eor "_ST43", "_H1"		\n"	\
	"ldd "_H1", "_Y"+12		\n"	\
	"eor "_ST14", "_H1"		\n"	\
	"ldd "_H1", "_Y"+13		\n"	\
	"eor "_ST24", "_H1"		\n"	\
	"ldd "_H1", "_Y"+14		\n"	\
	"eor "_ST34", "_H1"		\n"	\
	"ldd "_H1", "_Y"+15		\n"	\
	"eor "_ST44", "_H1"		\n"	\
	"ret		\n"
	
#define COMMON_INCKEY	\
	"RAMIncKey128:		\n"	\
	"ldd "_H2", "_Y"+12		\n"	\
	"ldd "_ZL", "_Y"+13		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"eor "_ZL", "_Rcon"		\n"	\
	"lsl "_Rcon"		\n"	\
	"brcc .+2		\n"	\
	"ldi "_Rcon", 0x1b		\n"	\
	"rcall RAMInc1		\n"	\
	"ldd "_ZL", "_Y"+13		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"rcall RAMInc1		\n"	\
	"ldd "_ZL", "_Y"+13		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"rcall RAMInc1		\n"	\
	"mov "_ZL", "_H2"		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"rcall RAMInc1		\n"	\
	"sbiw "_YL", 4		\n"	\
	"ret		\n"	\
	"RAMInc1:ld "_H1", "_Y"		\n"	\
	"eor "_ZL", "_H1"		\n"	\
	"st "_Y"+, "_ZL"		\n"	\
	"ldd "_H1", "_Y"+3		\n"	\
	"eor "_ZL", "_H1"		\n"	\
	"std "_Y"+3, "_ZL"		\n"	\
	"ldd "_H1", "_Y"+7		\n"	\
	"eor "_ZL", "_H1"		\n"	\
	"std "_Y"+7, "_ZL"		\n"	\
	"ldd "_H1", "_Y"+11		\n"	\
	"eor "_ZL", "_H1"		\n"	\
	"std "_Y"+11, "_ZL"		\n"	\
	"ret		\n"

#define COMMON_DECKEY	\
	"RAMDecKey128:		\n"	\
	"ldi "_ZH", hi8(aes_tab_sbox)		\n"	\
	"ldi "_H1", 4		\n"	\
	"RAMDec1:ldd "_ZL", "_Y"+12		\n"	\
	"ldd "_H2", "_Y"+8		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"std "_Y"+12, "_ZL"		\n"	\
	"ldd "_ZL", "_Y"+4		\n"	\
	"eor "_H2", "_ZL"		\n"	\
	"std "_Y"+8, "_H2"		\n"	\
	"ld "_H2", "_Y"+		\n"	\
	"eor "_ZL", "_H2"		\n"	\
	"std "_Y"+3, "_ZL"		\n"	\
	"dec "_H1"		\n"	\
	"brne RAMDec1		\n"	\
	"ldd "_ZL", "_Y"+8		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"ld "_H1", -"_Y"		\n"	\
	"eor "_H1", "_ZL"		\n"	\
	"st "_Y", "_H1"		\n"	\
	"ldd "_ZL", "_Y"+12		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"ld "_H1", -"_Y"		\n"	\
	"eor "_H1", "_ZL"		\n"	\
	"st "_Y", "_H1"		\n"	\
	"ldd "_ZL", "_Y"+12		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"ld "_H1", -"_Y"		\n"	\
	"eor "_H1", "_ZL"		\n"	\
	"st "_Y", "_H1"		\n"	\
	"ldd "_ZL", "_Y"+12		\n"	\
	"lpm "_ZL", "_Z"		\n"	\
	"ld "_H1", -"_Y"		\n"	\
	"eor "_H1", "_ZL"		\n"	\
	"eor "_H1", "_Rcon"		\n"	\
	"st "_Y", "_H1"		\n"	\
	"lsr "_Rcon"		\n"	\
	"cpi "_Rcon", 0x0d		\n"	\
	"brne .+2		\n"	\
	"ldi "_Rcon", 0x80		\n"	\
	"ret		\n"


#define COMMON_LOAD	\
	"ldi "_ZL", "_ST_START"		\n"	\
	"eor "_ZH","_ZH"		\n"	\
	"encloop1:		\n"	\
	"ld "_H1", X+		\n"	\
	"st Z+, "_H1"		\n"	\
	"cpi "_ZL", "_ST_END"		\n"	\
	"brne encloop1		\n"	\
	"sbiw "_XL", 16		\n"	\
	"ldi "_H3", 0x1b		\n"
	
#define COMMON_STORE \
	"ldi "_ZL", "_ST_START"		\n"	\
	"eor "_ZH","_ZH"		\n"	\
	"encloop2:		\n"	\
	"ld "_H1", Z+		\n"	\
	"st X+, "_H1"		\n"	\
	"cpi "_ZL", "_ST_END"		\n"	\
	"brne encloop2		\n"


#if AES_CIPHER
void aesCipher(unsigned char* key, unsigned char* data)
{
	
	asm volatile (
	
		#if AES_INVCIPHER
		"rcall encdecload		\n"
		#else
		COMMON_LOAD
		#endif
		
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		
		"ldi "_Rcon", 1		\n"
		"AESEnc1:rcall AddRoundKey		\n"
		"rcall RAMIncKey128		\n"
		"rcall ShiftRowsSubBytes		\n"
		"cpi "_Rcon", 0x6c		\n"
		#if AES_INVCIPHER
		"breq encendoffunc		\n"
		#else
		"breq encendofloop1		\n"
		#endif
		"rcall MixColumns		\n"
		"rjmp AESEnc1		\n"

		#if !AES_INVCIPHER
		"encendofloop1:"
		"rjmp encendoffunc		\n"
		COMMON
		COMMON_INCKEY
		#if AES_KEYREWIND
		COMMON_DECKEY
		#endif
		#endif
				
		"ShiftRowsSubBytes:		\n"		// Touched registers: ST11-ST44, H1, Z
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST21"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_H1", "_ST31"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_H1", "_ST32"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H1", "_ST44"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST44", "_Z"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST43", "_Z"		\n"
		"mov "_ZL", "_ST41"		\n"
		"lpm "_ST42", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST41", "_Z"		\n"
		"ret		\n"
				
		"encendoffunc:		\n"
		"rcall AddRoundKey		\n"
		
		#if AES_INVCIPHER
		"rcall encdecstore		\n"
		#else
		COMMON_STORE
		#endif
		
		: "+y" (key), "+x" (data)
		:
		: "memory", _H1, _H2, _H3, _Rcon,
		 _ST11, _ST12, _ST13, _ST14, 
		 _ST21, _ST22, _ST23, _ST24, 
		 _ST31, _ST32, _ST33, _ST34, 
		 _ST41, _ST42, _ST43, _ST44, 
		 _ZH, _ZL
	);

}
#endif


#if AES_INVCIPHER
void aesInvCipher(unsigned char* key, unsigned char* data)
{
	
	asm volatile (
	
		#if AES_CIPHER
		"rcall encdecload		\n"
		#else
		COMMON_LOAD
		#endif

		"ldi "_Rcon", 0x36		\n"
		"rcall AddRoundKey		\n"
		"rcall RAMDecKey128		\n"
		"rcall ShiftRowsSubBytesInverse		\n"
		"AESDec1:rcall AddRoundKey		\n"
		"rcall RAMDecKey128		\n"
		"rcall MixColumnsInverse		\n"
		"rcall ShiftRowsSubBytesInverse		\n"
		"cpi "_Rcon", 0		\n"
		"brne AESDec1		\n"
		"rcall AddRoundKey		\n"
		
		"rjmp decendoffunc		\n"
		
		"ShiftRowsSubBytesInverse:		\n"		// Touched registers: ST11-ST44, H1, Z
		"ldi "_ZH", hi8(aes_tab_isbox)		\n"
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST21"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_H1", "_ST31"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_H1", "_ST32"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H1", "_ST44"		\n"
		"mov "_ZL", "_ST41"		\n"
		"lpm "_ST44", "_Z"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST41", "_Z"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST42", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST43", "_Z"		\n"
		"ret		\n"
		
		"MixColumnsZLMul4:		\n"
		"lsl "_ZL"		\n"
		"brcc .+2		\n"
		"eor "_ZL", "_H3"		\n"		// Tm = xtime(a[0] ^ a[1])
		"lsl "_ZL"		\n"
		"brcc .+2		\n"
		"eor "_ZL", "_H3"		\n"		// Tm = xtime(a[0] ^ a[1])
		"ret		\n"
		
		"MixColumnsInverse:		\n"		// Touched registers: ST11-ST44, H1, H2, Z
		"mov "_ZL", "_ST11"		\n"		// u = xtime(xtime(a[0] ^ a[2]))
		"eor "_ZL", "_ST31"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST11", "_ZL"		\n"		// a[0] ^= u
		"eor "_ST31", "_ZL"		\n"		// a[2] ^= u
		"mov "_ZL", "_ST21"		\n"		// v = xtime(xtime(a[1] ^ a[3]))
		"eor "_ZL", "_ST41"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST21", "_ZL"		\n"		// a[1] ^= v
		"eor "_ST41", "_ZL"		\n"		// a[3] ^= v
		"mov "_ZL", "_ST12"		\n"
		"eor "_ZL", "_ST32"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST12", "_ZL"		\n"
		"eor "_ST32", "_ZL"		\n"
		"mov "_ZL", "_ST22"		\n"
		"eor "_ZL", "_ST42"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST22", "_ZL"		\n"
		"eor "_ST42", "_ZL"		\n"
		"mov "_ZL", "_ST13"		\n"
		"eor "_ZL", "_ST33"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST13", "_ZL"		\n"
		"eor "_ST33", "_ZL"		\n"
		"mov "_ZL", "_ST23"		\n"
		"eor "_ZL", "_ST43"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST23", "_ZL"		\n"
		"eor "_ST43", "_ZL"		\n"
		"mov "_ZL", "_ST14"		\n"
		"eor "_ZL", "_ST34"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST14", "_ZL"		\n"
		"eor "_ST34", "_ZL"		\n"
		"mov "_ZL", "_ST24"		\n"
		"eor "_ZL", "_ST44"		\n"
		"rcall MixColumnsZLMul4		\n"
		"eor "_ST24", "_ZL"		\n"
		"eor "_ST44", "_ZL"		\n"
		
		COMMON
		COMMON_DECKEY
		#if AES_CIPHER | AES_KEYPATCH
		COMMON_INCKEY
		#endif
		
		#if AES_CIPHER
		"encdecload:		\n"
		COMMON_LOAD
		"ret		\n"
		"encdecstore:		\n"
		COMMON_STORE
		"ret		\n"
		#endif
		
		"decendoffunc:		\n"
		
		#if AES_CIPHER
		"rcall encdecstore		\n"
		#else
		COMMON_STORE
		#endif
		
		: "+y" (key), "+x" (data)
		:
		: "memory", _H1, _H2, _H3, _Rcon,
		 _ST11, _ST12, _ST13, _ST14, 
		 _ST21, _ST22, _ST23, _ST24, 
		 _ST31, _ST32, _ST33, _ST34, 
		 _ST41, _ST42, _ST43, _ST44, 
		 _ZH, _ZL
	);
		
}
#endif


#if (AES_CIPHER || AES_INVCIPHER) & AES_KEYREWIND
void aesKeyRewind(unsigned char* patched)
{
	
	asm volatile (
		"ldi "_Rcon", 0x36		\n"
		"AESKeyR:rcall RAMDecKey128		\n"
		"cpi "_Rcon", 0		\n"
		"brne AESKeyR		\n"
		: "+y" (patched)
		:
		: "memory", _H1, _H2, _Rcon, _ZH, _ZL
	);
}
#endif


#if (AES_CIPHER || AES_INVCIPHER) & AES_KEYPATCH
void aesKeyPatch(unsigned char* key)
{
	asm volatile (
		"ldi "_Rcon", 1		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"AESKeyF:rcall RAMIncKey128		\n"
		"cpi "_Rcon", 0x6c		\n"
		"brne AESKeyF		\n"
		: "+y" (key)
		:
		: "memory", _H1, _H2, _Rcon, _ZH, _ZL
	);
}
#endif



#elif AES_IMPLEMENTATION == 2


/************************************************************************/
/*   FURIOUS                                           by B. Poettering */
/************************************************************************/




#if AES_CIPHER || AES_KEYEXPAND
const char aes_tab_sbox[256] PROGMEM __attribute__ ((aligned(256))) = { SBOX_DATA_INIT };
#endif


#if AES_INVCIPHER
const char aes_tab_isbox[256] PROGMEM __attribute__ ((aligned(256))) = { ISBOX_DATA_INIT };
#endif


#define _H1 "r6"
#define _H2 "r7"
#define _H3 "r0"
#define _H4 "r24"
#define _I "r25"
#define _ST11 "r8"
#define _ST12 "r9"
#define _ST13 "r10"
#define _ST14 "r11"
#define _ST21 "r12"
#define _ST22 "r13"
#define _ST23 "r14"
#define _ST24 "r15"
#define _ST31 "r16"
#define _ST32 "r17"
#define _ST33 "r18"
#define _ST34 "r19"
#define _ST41 "r20"
#define _ST42 "r21"
#define _ST43 "r22"
#define _ST44 "r23"
#define _X "X"
#define _XH "r27"
#define _XL "r26"
#define _Y "Y"
#define _YH "r29"
#define _YL "r28"
#define _Z "Z"
#define _ZH "r31"
#define _ZL "r30"


#define COMMON \
	"addroundkey:		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST11", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST21", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST31", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST41", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST12", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST22", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST32", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST42", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST13", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST23", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST33", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST43", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST14", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST24", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST34", "_H1"		\n"	\
	"ld "_H1", "_Y"+		\n"	\
	"eor "_ST44", "_H1"		\n"	\
	"ret		\n"	\
	"mixcolumns:		\n"	\
	"mov "_H1", "_ST11"		\n"	\
	"eor "_H1", "_ST21"		\n"	\
	"eor "_H1", "_ST31"		\n"	\
	"eor "_H1", "_ST41"		\n"	\
	"mov "_H2", "_ST11"		\n"	\
	"mov "_H3", "_ST11"		\n"	\
	"eor "_H3", "_ST21"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST11", "_H3"		\n"	\
	"eor "_ST11", "_H1"		\n"	\
	"mov "_H3", "_ST21"		\n"	\
	"eor "_H3", "_ST31"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST21", "_H3"		\n"	\
	"eor "_ST21", "_H1"		\n"	\
	"mov "_H3", "_ST31"		\n"	\
	"eor "_H3", "_ST41"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST31", "_H3"		\n"	\
	"eor "_ST31", "_H1"		\n"	\
	"mov "_H3", "_ST41"		\n"	\
	"eor "_H3", "_H2"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST41", "_H3"		\n"	\
	"eor "_ST41", "_H1"		\n"	\
	"mov "_H1", "_ST12"		\n"	\
	"eor "_H1", "_ST22"		\n"	\
	"eor "_H1", "_ST32"		\n"	\
	"eor "_H1", "_ST42"		\n"	\
	"mov "_H2", "_ST12"		\n"	\
	"mov "_H3", "_ST12"		\n"	\
	"eor "_H3", "_ST22"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST12", "_H3"		\n"	\
	"eor "_ST12", "_H1"		\n"	\
	"mov "_H3", "_ST22"		\n"	\
	"eor "_H3", "_ST32"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST22", "_H3"		\n"	\
	"eor "_ST22", "_H1"		\n"	\
	"mov "_H3", "_ST32"		\n"	\
	"eor "_H3", "_ST42"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST32", "_H3"		\n"	\
	"eor "_ST32", "_H1"		\n"	\
	"mov "_H3", "_ST42"		\n"	\
	"eor "_H3", "_H2"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST42", "_H3"		\n"	\
	"eor "_ST42", "_H1"		\n"	\
	"mov "_H1", "_ST13"		\n"	\
	"eor "_H1", "_ST23"		\n"	\
	"eor "_H1", "_ST33"		\n"	\
	"eor "_H1", "_ST43"		\n"	\
	"mov "_H2", "_ST13"		\n"	\
	"mov "_H3", "_ST13"		\n"	\
	"eor "_H3", "_ST23"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST13", "_H3"		\n"	\
	"eor "_ST13", "_H1"		\n"	\
	"mov "_H3", "_ST23"		\n"	\
	"eor "_H3", "_ST33"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST23", "_H3"		\n"	\
	"eor "_ST23", "_H1"		\n"	\
	"mov "_H3", "_ST33"		\n"	\
	"eor "_H3", "_ST43"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST33", "_H3"		\n"	\
	"eor "_ST33", "_H1"		\n"	\
	"mov "_H3", "_ST43"		\n"	\
	"eor "_H3", "_H2"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST43", "_H3"		\n"	\
	"eor "_ST43", "_H1"		\n"	\
	"mov "_H1", "_ST14"		\n"	\
	"eor "_H1", "_ST24"		\n"	\
	"eor "_H1", "_ST34"		\n"	\
	"eor "_H1", "_ST44"		\n"	\
	"mov "_H2", "_ST14"		\n"	\
	"mov "_H3", "_ST14"		\n"	\
	"eor "_H3", "_ST24"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST14", "_H3"		\n"	\
	"eor "_ST14", "_H1"		\n"	\
	"mov "_H3", "_ST24"		\n"	\
	"eor "_H3", "_ST34"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST24", "_H3"		\n"	\
	"eor "_ST24", "_H1"		\n"	\
	"mov "_H3", "_ST34"		\n"	\
	"eor "_H3", "_ST44"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST34", "_H3"		\n"	\
	"eor "_ST34", "_H1"		\n"	\
	"mov "_H3", "_ST44"		\n"	\
	"eor "_H3", "_H2"		\n"	\
	"lsl "_H3"		\n"	\
	"brcc .+2		\n"	\
	"eor "_H3", "_H4"		\n"	\
	"eor "_ST44", "_H3"		\n"	\
	"eor "_ST44", "_H1"		\n"	\
	"ret	\n"

#define COMMON_LOAD \
	"ld "_ST11", "_X"+		\n"	\
	"ld "_ST21", "_X"+		\n"	\
	"ld "_ST31", "_X"+		\n"	\
	"ld "_ST41", "_X"+		\n"	\
	"ld "_ST12", "_X"+		\n"	\
	"ld "_ST22", "_X"+		\n"	\
	"ld "_ST32", "_X"+		\n"	\
	"ld "_ST42", "_X"+		\n"	\
	"ld "_ST13", "_X"+		\n"	\
	"ld "_ST23", "_X"+		\n"	\
	"ld "_ST33", "_X"+		\n"	\
	"ld "_ST43", "_X"+		\n"	\
	"ld "_ST14", "_X"+		\n"	\
	"ld "_ST24", "_X"+		\n"	\
	"ld "_ST34", "_X"+		\n"	\
	"ld "_ST44", "_X"+		\n"	\
	"sbiw "_XL", 16		\n"

#define COMMON_STORE \
	"st "_X"+, "_ST11"		\n"	\
	"st "_X"+, "_ST21"		\n"	\
	"st "_X"+, "_ST31"		\n"	\
	"st "_X"+, "_ST41"		\n"	\
	"st "_X"+, "_ST12"		\n"	\
	"st "_X"+, "_ST22"		\n"	\
	"st "_X"+, "_ST32"		\n"	\
	"st "_X"+, "_ST42"		\n"	\
	"st "_X"+, "_ST13"		\n"	\
	"st "_X"+, "_ST23"		\n"	\
	"st "_X"+, "_ST33"		\n"	\
	"st "_X"+, "_ST43"		\n"	\
	"st "_X"+, "_ST14"		\n"	\
	"st "_X"+, "_ST24"		\n"	\
	"st "_X"+, "_ST34"		\n"	\
	"st "_X"+, "_ST44"		\n"


#if AES_KEYEXPAND
void aesKeyExpand(const unsigned char* key, unsigned char* expanded)
{
	asm volatile (
	
		"rcall encdecload		\n"
		"movw	"_XL", "_YL"		\n"
		
		"ldi "_H4", 1		\n"
		"ldi "_I", 0x1b		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"rjmp keyexp1		\n"
		"keyexp0:mov "_ZL", "_ST24"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST11", "_H3"		\n"
		"eor "_ST11", "_H4"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST21", "_H3"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST31", "_H3"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST41", "_H3"		\n"
		"eor "_ST12", "_ST11"		\n"
		"eor "_ST22", "_ST21"		\n"
		"eor "_ST32", "_ST31"		\n"
		"eor "_ST42", "_ST41"		\n"
		"eor "_ST13", "_ST12"		\n"
		"eor "_ST23", "_ST22"		\n"
		"eor "_ST33", "_ST32"		\n"
		"eor "_ST43", "_ST42"		\n"
		"eor "_ST14", "_ST13"		\n"
		"eor "_ST24", "_ST23"		\n"
		"eor "_ST34", "_ST33"		\n"
		"eor "_ST44", "_ST43"		\n"
		"lsl "_H4"		\n"
		"brcc keyexp1		\n"
		"eor "_H4", "_I"		\n"
		"keyexp1:		\n"
		"rcall encdecstore		\n"
		"cpi "_H4", 0x6c		\n"
		"brne keyexp0		\n"
		
		: "+y" (expanded), "+x" (key)
		:
		: "memory", _H3, _H4, _I,
		_ST11, _ST12, _ST13, _ST14,
		_ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34,
		_ST41, _ST42, _ST43, _ST44,
		_ZH, _ZL
	);
	
}
#endif


#if AES_CIPHER
void aesCipher(const unsigned char* expanded, unsigned char* data)
{
	asm volatile (
	
		#if AES_INVCIPHER || AES_KEYEXPAND
		"rcall encdecload		\n"
		#else
		COMMON_LOAD
		#endif
	
		"ldi "_H4", 0x1b		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"ldi "_I", 10		\n"
		"encryp1:rcall addroundkey		\n"		// AddRoundKey
		"mov "_ZL", "_ST11"		\n"		// SubBytes + ShiftRows
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST21"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_H1", "_ST31"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_H1", "_ST32"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H1", "_ST44"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST44", "_Z"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST43", "_Z"		\n"
		"mov "_ZL", "_ST41"		\n"
		"lpm "_ST42", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST41", "_Z"		\n"
		"dec "_I"		\n"
		"breq endofencloop		\n"
		"rcall mixcolumns		\n"		// MixColumns
		"rjmp encryp1		\n"
	
		"endofencloop:		\n"
		"rcall addroundkey		\n"
	
		#if !AES_INVCIPHER
		"rjmp endofencfunc		\n"
		COMMON
		#if AES_KEYEXPAND
		"encdecload:		\n"
		COMMON_LOAD
		"ret		\n"
		"encdecstore:		\n"
		COMMON_STORE
		"ret		\n"
		#endif
		#endif

		"endofencfunc:		\n"
	
		#if AES_INVCIPHER || AES_KEYEXPAND
		"rcall encdecstore		\n"
		#else
		COMMON_STORE
		#endif

		: "+y" (expanded), "+x" (data)
		:
		: "memory", _H1, _H2, _H3, _H4, _I,
		_ST11, _ST12, _ST13, _ST14,
		_ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34,
		_ST41, _ST42, _ST43, _ST44,
		_ZH, _ZL
	
	);
}
#endif

#if AES_INVCIPHER
void aesInvCipher(const unsigned char* expanded, unsigned char* data)
{
	asm volatile (
	
		#if AES_CIPHER || AES_KEYEXPAND
		"rcall encdecload		\n"
		#else
		COMMON_LOAD
		#endif
	
		"subi "_YL", 0x60		\n"
		"sbci "_YH", 0xFF		\n"

		"ldi "_H4", 0x1b		\n"
		"ldi "_I", 10		\n"
		"rcall addroundkey		\n"		// AddRoundKey
		"sbiw "_YL",32		\n"
		"ldi "_ZH", hi8(aes_tab_isbox)		\n"		// SubBytes + ShiftRows
		"decryp1:		\n"
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST21"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_H1", "_ST33"		\n"
		"mov "_ZL", "_ST31"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_H1", "_ST34"		\n"
		"mov "_ZL", "_ST32"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_H1", "_ST41"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST41", "_Z"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST42", "_Z"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_ST43", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST44", "_Z"		\n"
		"rcall addroundkey		\n"		// AddRoundKey
		"sbiw "_YL",32		\n"
		"dec "_I"		\n"
		"brne .+2		\n"
		"rjmp endofdecfunc		\n"
		"mov "_H1", "_ST11"		\n"
		"eor "_H1", "_ST31"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"mov "_H2", "_ST21"		\n"
		"eor "_H2", "_ST41"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"eor "_ST11", "_H1"		\n"
		"eor "_ST21", "_H2"		\n"
		"eor "_ST31", "_H1"		\n"
		"eor "_ST41", "_H2"		\n"
		"mov "_H1", "_ST12"		\n"
		"eor "_H1", "_ST32"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"mov "_H2", "_ST22"		\n"
		"eor "_H2", "_ST42"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"eor "_ST12", "_H1"		\n"
		"eor "_ST22", "_H2"		\n"
		"eor "_ST32", "_H1"		\n"
		"eor "_ST42", "_H2"		\n"
		"mov "_H1", "_ST13"		\n"
		"eor "_H1", "_ST33"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"mov "_H2", "_ST23"		\n"
		"eor "_H2", "_ST43"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"eor "_ST13", "_H1"		\n"
		"eor "_ST23", "_H2"		\n"
		"eor "_ST33", "_H1"		\n"
		"eor "_ST43", "_H2"		\n"
		"mov "_H1", "_ST14"		\n"
		"eor "_H1", "_ST34"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"lsl "_H1"		\n"
		"brcc .+2		\n"
		"eor "_H1", "_H4"		\n"
		"mov "_H2", "_ST24"		\n"
		"eor "_H2", "_ST44"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"lsl "_H2"		\n"
		"brcc .+2		\n"
		"eor "_H2", "_H4"		\n"
		"eor "_ST14", "_H1"		\n"
		"eor "_ST24", "_H2"		\n"
		"eor "_ST34", "_H1"		\n"
		"eor "_ST44", "_H2"		\n"
		"rcall mixcolumns		\n"		// MixColumns
		"rjmp decryp1		\n"
	
		COMMON
	
		#if AES_CIPHER || AES_KEYEXPAND
		"encdecload:		\n"
		COMMON_LOAD
		"ret		\n"
		"encdecstore:		\n"
		COMMON_STORE
		"ret		\n"
		#endif
	
		"endofdecfunc:		\n"
	
		#if AES_CIPHER || AES_KEYEXPAND
		"rcall encdecstore		\n"
		#else
		COMMON_STORE
		#endif
	
		: "+y" (expanded), "+x" (data)
		:
		: "memory", _H1, _H2, _H3, _H4, _I,
		_ST11, _ST12, _ST13, _ST14,
		_ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34,
		_ST41, _ST42, _ST43, _ST44,
		_ZH, _ZL
	);
}
#endif



#elif AES_IMPLEMENTATION == 3


/************************************************************************/
/*   FAST                                              by B. Poettering */
/************************************************************************/




#if AES_KEYEXPAND || AES_KEYPATCH || AES_CIPHER
const char aes_tab_sbox[256] PROGMEM __attribute__ ((aligned(256))) = { SBOX_DATA_INIT };
#endif

#if AES_CIPHER
const char aes_tab_sbox02[256] PROGMEM __attribute__ ((aligned(256))) = {
	0xc6,0xf8,0xee,0xf6,0xff,0xd6,0xde,0x91,0x60,0x02,0xce,0x56,0xe7,0xb5,0x4d,0xec,
	0x8f,0x1f,0x89,0xfa,0xef,0xb2,0x8e,0xfb,0x41,0xb3,0x5f,0x45,0x23,0x53,0xe4,0x9b,
	0x75,0xe1,0x3d,0x4c,0x6c,0x7e,0xf5,0x83,0x68,0x51,0xd1,0xf9,0xe2,0xab,0x62,0x2a,
	0x08,0x95,0x46,0x9d,0x30,0x37,0x0a,0x2f,0x0e,0x24,0x1b,0xdf,0xcd,0x4e,0x7f,0xea,
	0x12,0x1d,0x58,0x34,0x36,0xdc,0xb4,0x5b,0xa4,0x76,0xb7,0x7d,0x52,0xdd,0x5e,0x13,
	0xa6,0xb9,0x00,0xc1,0x40,0xe3,0x79,0xb6,0xd4,0x8d,0x67,0x72,0x94,0x98,0xb0,0x85,
	0xbb,0xc5,0x4f,0xed,0x86,0x9a,0x66,0x11,0x8a,0xe9,0x04,0xfe,0xa0,0x78,0x25,0x4b,
	0xa2,0x5d,0x80,0x05,0x3f,0x21,0x70,0xf1,0x63,0x77,0xaf,0x42,0x20,0xe5,0xfd,0xbf,
	0x81,0x18,0x26,0xc3,0xbe,0x35,0x88,0x2e,0x93,0x55,0xfc,0x7a,0xc8,0xba,0x32,0xe6,
	0xc0,0x19,0x9e,0xa3,0x44,0x54,0x3b,0x0b,0x8c,0xc7,0x6b,0x28,0xa7,0xbc,0x16,0xad,
	0xdb,0x64,0x74,0x14,0x92,0x0c,0x48,0xb8,0x9f,0xbd,0x43,0xc4,0x39,0x31,0xd3,0xf2,
	0xd5,0x8b,0x6e,0xda,0x01,0xb1,0x9c,0x49,0xd8,0xac,0xf3,0xcf,0xca,0xf4,0x47,0x10,
	0x6f,0xf0,0x4a,0x5c,0x38,0x57,0x73,0x97,0xcb,0xa1,0xe8,0x3e,0x96,0x61,0x0d,0x0f,
	0xe0,0x7c,0x71,0xcc,0x90,0x06,0xf7,0x1c,0xc2,0x6a,0xae,0x69,0x17,0x99,0x3a,0x27,
	0xd9,0xeb,0x2b,0x22,0xd2,0xa9,0x07,0x33,0x2d,0x3c,0x15,0xc9,0x87,0xaa,0x50,0xa5,
	0x03,0x59,0x09,0x1a,0x65,0xd7,0x84,0xd0,0x82,0x29,0x5a,0x1e,0x7b,0xa8,0x6d,0x2c,
};
#endif

#if AES_INVCIPHER
const char aes_tab_isbox[256] PROGMEM __attribute__ ((aligned(256))) = { ISBOX_DATA_INIT };
#endif

#if AES_INVCIPHER || AES_KEYPATCH
const char aes_tab_isbox0e[256] PROGMEM __attribute__ ((aligned(256))) = {
	0x51,0x7e,0x1a,0x3a,0x3b,0x1f,0xac,0x4b,0x20,0xad,0x88,0xf5,0x4f,0xc5,0x26,0xb5,
	0xde,0x25,0x45,0x5d,0xc3,0x81,0x8d,0x6b,0x03,0x15,0xbf,0x95,0xd4,0x58,0x49,0x8e,
	0x75,0xf4,0x99,0x27,0xbe,0xf0,0xc9,0x7d,0x63,0xe5,0x97,0x62,0xb1,0xbb,0xfe,0xf9,
	0x70,0x8f,0x94,0x52,0xab,0x72,0xe3,0x66,0xb2,0x2f,0x86,0xd3,0x30,0x23,0x02,0xed,
	0x8a,0xa7,0xf3,0x4e,0x65,0x06,0xd1,0xc4,0x34,0xa2,0x05,0xa4,0x0b,0x40,0x5e,0xbd,
	0x3e,0x96,0xdd,0x4d,0x91,0x71,0x04,0x60,0x19,0xd6,0x89,0x67,0xb0,0x07,0xe7,0x79,
	0xa1,0x7c,0xf8,0x00,0x09,0x32,0x1e,0x6c,0xfd,0x0f,0x3d,0x36,0x0a,0x68,0x9b,0x24,
	0x0c,0x93,0xb4,0x1b,0x80,0x61,0x5a,0x1c,0xe2,0xc0,0x3c,0x12,0x0e,0xf2,0x2d,0x14,
	0x57,0xaf,0xee,0xa3,0xf7,0x5c,0x44,0x5b,0x8b,0xcb,0xb6,0xb8,0xd7,0x42,0x13,0x84,
	0x85,0xd2,0xae,0xc7,0x1d,0xdc,0x0d,0x77,0x2b,0xa9,0x11,0x47,0xa8,0xa0,0x56,0x22,
	0x87,0xd9,0x8c,0x98,0xa6,0xa5,0xda,0x3f,0x2c,0x50,0x6a,0x54,0xf6,0x90,0x2e,0x82,
	0x9f,0x69,0x6f,0xcf,0xc8,0x10,0xe8,0xdb,0xcd,0x6e,0xec,0x83,0xe6,0xaa,0x21,0xef,
	0xba,0x4a,0xea,0x29,0x31,0x2a,0xc6,0x35,0x74,0xfc,0xe0,0x33,0xf1,0x41,0x7f,0x17,
	0x76,0x43,0xcc,0xe4,0x9e,0x4c,0xc1,0x46,0x9d,0x01,0xfa,0xfb,0xb3,0x92,0xe9,0x6d,
	0x9a,0x37,0x59,0xeb,0xce,0xb7,0xe1,0x7a,0x9c,0x55,0x18,0x73,0x53,0x5f,0xdf,0x78,
	0xca,0xb9,0x38,0xc2,0x16,0xbc,0x28,0xff,0x39,0x08,0xd8,0x64,0x7b,0xd5,0x48,0xd0,
};
#endif

#if AES_INVCIPHER || AES_KEYPATCH
const char aes_tab_isbox09[256] PROGMEM __attribute__ ((aligned(256))) = {
	0xf4,0x41,0x17,0x27,0xab,0x9d,0xfa,0xe3,0x30,0x76,0xcc,0x02,0xe5,0x2a,0x35,0x62,
	0xb1,0xba,0xea,0xfe,0x2f,0x4c,0x46,0xd3,0x8f,0x92,0x6d,0x52,0xbe,0x74,0xe0,0xc9,
	0xc2,0x8e,0x58,0xb9,0xe1,0x88,0x20,0xce,0xdf,0x1a,0x51,0x53,0x64,0x6b,0x81,0x08,
	0x48,0x45,0xde,0x7b,0x73,0x4b,0x1f,0x55,0xeb,0xb5,0xc5,0x37,0x28,0xbf,0x03,0x16,
	0xcf,0x79,0x07,0x69,0xda,0x05,0x34,0xa6,0x2e,0xf3,0x8a,0xf6,0x83,0x60,0x71,0x6e,
	0x21,0xdd,0x3e,0xe6,0x54,0xc4,0x06,0x50,0x98,0xbd,0x40,0xd9,0xe8,0x89,0x19,0xc8,
	0x7c,0x42,0x84,0x00,0x80,0x2b,0x11,0x5a,0x0e,0x85,0xae,0x2d,0x0f,0x5c,0x5b,0x36,
	0x0a,0x57,0xee,0x9b,0xc0,0xdc,0x77,0x12,0x93,0xa0,0x22,0x1b,0x09,0x8b,0xb6,0x1e,
	0xf1,0x75,0x99,0x7f,0x01,0x72,0x66,0xfb,0x43,0x23,0xed,0xe4,0x31,0x63,0x97,0xc6,
	0x4a,0xbb,0xf9,0x29,0x9e,0xb2,0x86,0xc1,0xb3,0x70,0x94,0xe9,0xfc,0xf0,0x7d,0x33,
	0x49,0x38,0xca,0xd4,0xf5,0x7a,0xb7,0xad,0x3a,0x78,0x5f,0x7e,0x8d,0xd8,0x39,0xc3,
	0x5d,0xd0,0xd5,0x25,0xac,0x18,0x9c,0x3b,0x26,0x59,0x9a,0x4f,0x95,0xff,0xbc,0x15,
	0xe7,0x6f,0x9f,0xb0,0xa4,0x3f,0xa5,0xa2,0x4e,0x82,0x90,0xa7,0x04,0xec,0xcd,0x91,
	0x4d,0xef,0xaa,0x96,0xd1,0x6a,0x2c,0x65,0x5e,0x8c,0x87,0x0b,0x67,0xdb,0x10,0xd6,
	0xd7,0xa1,0xf8,0x13,0xa9,0x61,0x1c,0x47,0xd2,0xf2,0x14,0xc7,0xf7,0xfd,0x3d,0x44,
	0xaf,0x68,0x24,0xa3,0x1d,0xe2,0x3c,0x0d,0xa8,0x0c,0xb4,0x56,0xcb,0x32,0x6c,0xb8,
};
#endif

#if AES_INVCIPHER || AES_KEYPATCH
const char aes_tab_isbox0d[256] PROGMEM __attribute__ ((aligned(256))) = {
	0xa7,0x65,0xa4,0x5e,0x6b,0x45,0x58,0x03,0xfa,0x6d,0x76,0x4c,0xd7,0xcb,0x44,0xa3,
	0x5a,0x1b,0x0e,0xc0,0x75,0xf0,0x97,0xf9,0x5f,0x9c,0x7a,0x59,0x83,0x21,0x69,0xc8,
	0x89,0x79,0x3e,0x71,0x4f,0xad,0xac,0x3a,0x4a,0x31,0x33,0x7f,0x77,0xae,0xa0,0x2b,
	0x68,0xfd,0x6c,0xf8,0xd3,0x02,0x8f,0xab,0x28,0xc2,0x7b,0x08,0x87,0xa5,0x6a,0x82,
	0x1c,0xb4,0xf2,0xe2,0xf4,0xbe,0x62,0xfe,0x53,0x55,0xe1,0xeb,0xec,0xef,0x9f,0x10,
	0x8a,0x06,0x05,0xbd,0x8d,0x5d,0xd4,0x15,0xfb,0xe9,0x43,0x9e,0x42,0x8b,0x5b,0xee,
	0x0a,0x0f,0x1e,0x00,0x86,0xed,0x70,0x72,0xff,0x38,0xd5,0x39,0xd9,0xa6,0x54,0x2e,
	0x67,0xe7,0x96,0x91,0xc5,0x20,0x4b,0x1a,0xba,0x2a,0xe0,0x17,0x0d,0xc7,0xa8,0xa9,
	0x19,0x07,0xdd,0x60,0x26,0xf5,0x3b,0x7e,0x29,0xc6,0xfc,0xf1,0xdc,0x85,0x22,0x11,
	0x24,0x3d,0x32,0xa1,0x2f,0x30,0x52,0xe3,0x16,0xb9,0x48,0x64,0x8c,0x3f,0x2c,0x90,
	0x4e,0xd1,0xa2,0x0b,0x81,0xde,0x8e,0xbf,0x9d,0x92,0xcc,0x46,0x13,0xb8,0xf7,0xaf,
	0x80,0x93,0x2d,0x12,0x99,0x7d,0x63,0xbb,0x78,0x18,0xb7,0x9a,0x6e,0xe6,0xcf,0xe8,
	0x9b,0x36,0x09,0x7c,0xb2,0x23,0x94,0x66,0xbc,0xca,0xd0,0xd8,0x98,0xda,0x50,0xf6,
	0xd6,0xb0,0x4d,0x04,0xb5,0x88,0x1f,0x51,0xea,0x35,0x74,0x41,0x1d,0xd2,0x56,0x47,
	0x61,0x0c,0x14,0x3c,0x27,0xc9,0xe5,0xb1,0xdf,0x73,0xce,0x37,0xcd,0xaa,0x6f,0xdb,
	0xf3,0xc4,0x34,0x40,0xc3,0x25,0x49,0x95,0x01,0xb3,0xe4,0xc1,0x84,0xb6,0x5c,0x57,
};
#endif

#if AES_INVCIPHER || AES_KEYPATCH
const char aes_tab_isbox0b[256] PROGMEM __attribute__ ((aligned(256))) = {
	0x50,0x53,0xc3,0x96,0xcb,0xf1,0xab,0x93,0x55,0xf6,0x91,0x25,0xfc,0xd7,0x80,0x8f,
	0x49,0x67,0x98,0xe1,0x02,0x12,0xa3,0xc6,0xe7,0x95,0xeb,0xda,0x2d,0xd3,0x29,0x44,
	0x6a,0x78,0x6b,0xdd,0xb6,0x17,0x66,0xb4,0x18,0x82,0x60,0x45,0xe0,0x84,0x1c,0x94,
	0x58,0x19,0x87,0xb7,0x23,0xe2,0x57,0x2a,0x07,0x03,0x9a,0xa5,0xf2,0xb2,0xba,0x5c,
	0x2b,0x92,0xf0,0xa1,0xcd,0xd5,0x1f,0x8a,0x9d,0xa0,0x32,0x75,0x39,0xaa,0x06,0x51,
	0xf9,0x3d,0xae,0x46,0xb5,0x05,0x6f,0xff,0x24,0x97,0xcc,0x77,0xbd,0x88,0x38,0xdb,
	0x47,0xe9,0xc9,0x00,0x83,0x48,0xac,0x4e,0xfb,0x56,0x1e,0x27,0x64,0x21,0xd1,0x3a,
	0xb1,0x0f,0xd2,0x9e,0x4f,0xa2,0x69,0x16,0x0a,0xe5,0x43,0x1d,0x0b,0xad,0xb9,0xc8,
	0x85,0x4c,0xbb,0xfd,0x9f,0xbc,0xc5,0x34,0x76,0xdc,0x68,0x63,0xca,0x10,0x40,0x20,
	0x7d,0xf8,0x11,0x6d,0x4b,0xf3,0xec,0xd0,0x6c,0x99,0xfa,0x22,0xc4,0x1a,0xd8,0xef,
	0xc7,0xc1,0xfe,0x36,0xcf,0x28,0x26,0xa4,0xe4,0x0d,0x9b,0x62,0xc2,0xe8,0x5e,0xf5,
	0xbe,0x7c,0xa9,0xb3,0x3b,0xa7,0x6e,0x7b,0x09,0xf4,0x01,0xa8,0x65,0x7e,0x08,0xe6,
	0xd9,0xce,0xd4,0xd6,0xaf,0x31,0x30,0xc0,0x37,0xa6,0xb0,0x15,0x4a,0xf7,0x0e,0x2f,
	0x8d,0x4d,0x54,0xdf,0xe3,0x1b,0xb8,0x7f,0x04,0x5d,0x73,0x2e,0x5a,0x52,0x33,0x13,
	0x8c,0x7a,0x8e,0x89,0xee,0x35,0xed,0x3c,0x59,0x3f,0x79,0xbf,0xea,0x5b,0x14,0x86,
	0x81,0x3e,0x2c,0x5f,0x72,0x0c,0x8b,0x41,0x71,0xde,0x9c,0x90,0x61,0x70,0x74,0x42,
};
#endif


#if AES_KEYEXPAND
void aesKeyExpand(const unsigned char* key, unsigned char* expanded)
{
	asm volatile (
		#define _H1 "r24"
		#define _H2 "r25"
		#define _H3 "r0"
		#define _ST11 "r8"
		#define _ST12 "r9"
		#define _ST13 "r10"
		#define _ST14 "r11"
		#define _ST21 "r12"
		#define _ST22 "r13"
		#define _ST23 "r14"
		#define _ST24 "r15"
		#define _ST31 "r16"
		#define _ST32 "r17"
		#define _ST33 "r18"
		#define _ST34 "r19"
		#define _ST41 "r20"
		#define _ST42 "r21"
		#define _ST43 "r22"
		#define _ST44 "r23"
		#define _X "X"
		#define _XH "r27"
		#define _XL "r26"
		#define _Y "Y"
		#define _YH "r29"
		#define _YL "r28"
		#define _Z "Z"
		#define _ZH "r31"
		#define _ZL "r30"
		
		"ld "_ST11", "_X"+		\n"
		"ld "_ST21", "_X"+		\n"
		"ld "_ST31", "_X"+		\n"
		"ld "_ST41", "_X"+		\n"
		"ld "_ST12", "_X"+		\n"
		"ld "_ST22", "_X"+		\n"
		"ld "_ST32", "_X"+		\n"
		"ld "_ST42", "_X"+		\n"
		"ld "_ST13", "_X"+		\n"
		"ld "_ST23", "_X"+		\n"
		"ld "_ST33", "_X"+		\n"
		"ld "_ST43", "_X"+		\n"
		"ld "_ST14", "_X"+		\n"
		"ld "_ST24", "_X"+		\n"
		"ld "_ST34", "_X"+		\n"
		"ld "_ST44", "_X"+		\n"
		"ldi "_H1", 1		\n"
		"ldi "_H2", 0x1b		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"rjmp keyexp1		\n"
		"keyexp0:mov "_ZL", "_ST24"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST11", "_H3"		\n"
		"eor "_ST11", "_H1"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST21", "_H3"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST31", "_H3"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST41", "_H3"		\n"
		"eor "_ST12", "_ST11"		\n"
		"eor "_ST22", "_ST21"		\n"
		"eor "_ST32", "_ST31"		\n"
		"eor "_ST42", "_ST41"		\n"
		"eor "_ST13", "_ST12"		\n"
		"eor "_ST23", "_ST22"		\n"
		"eor "_ST33", "_ST32"		\n"
		"eor "_ST43", "_ST42"		\n"
		"eor "_ST14", "_ST13"		\n"
		"eor "_ST24", "_ST23"		\n"
		"eor "_ST34", "_ST33"		\n"
		"eor "_ST44", "_ST43"		\n"
		"lsl "_H1"		\n"
		"brcc keyexp1		\n"
		"eor "_H1", "_H2"		\n"
		"keyexp1:st "_Y"+, "_ST11"		\n"
		"st "_Y"+, "_ST21"		\n"
		"st "_Y"+, "_ST31"		\n"
		"st "_Y"+, "_ST41"		\n"
		"st "_Y"+, "_ST12"		\n"
		"st "_Y"+, "_ST22"		\n"
		"st "_Y"+, "_ST32"		\n"
		"st "_Y"+, "_ST42"		\n"
		"st "_Y"+, "_ST13"		\n"
		"st "_Y"+, "_ST23"		\n"
		"st "_Y"+, "_ST33"		\n"
		"st "_Y"+, "_ST43"		\n"
		"st "_Y"+, "_ST14"		\n"
		"st "_Y"+, "_ST24"		\n"
		"st "_Y"+, "_ST34"		\n"
		"st "_Y"+, "_ST44"		\n"
		"cpi "_H1", 0x6c		\n"
		"brne keyexp0		\n"
		: "+x" (key), "+y" (expanded)
		:
		: "memory",_H1, _H2, _H3, _ST11,
		_ST12, _ST13, _ST14, _ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34, _ST41, _ST42, _ST43,
		_ST44, _ZH, _ZL
		
		#undef _H1
		#undef _H2
		#undef _H3
		#undef _ST11
		#undef _ST12
		#undef _ST13
		#undef _ST14
		#undef _ST21
		#undef _ST22
		#undef _ST23
		#undef _ST24
		#undef _ST31
		#undef _ST32
		#undef _ST33
		#undef _ST34
		#undef _ST41
		#undef _ST42
		#undef _ST43
		#undef _ST44
		#undef _X
		#undef _XH
		#undef _XL
		#undef _Y
		#undef _YH
		#undef _YL
		#undef _Z
		#undef _ZH
		#undef _ZL
	);
	
}
#endif

#if AES_KEYPATCH
void aesKeyPatch(unsigned char* expanded)
{
	asm volatile (
		#define _H1 "r19"
		#define _H2 "r20"
		#define _H3 "r21"
		#define _H4 "r22"
		#define _H5 "r23"
		#define _I "r24"
		#define _ST11 "r0"
		#define _ST21 "r25"
		#define _ST31 "r26"
		#define _ST41 "r27"
		#define _Y "Y"
		#define _YH "r29"
		#define _YL "r28"
		#define _Z "Z"
		#define _ZH "r31"
		#define _ZL "r30"
		"adiw "_YL", 16		\n"
		"ldi "_I", 35		\n"
		"patchd0:ldd "_ST11", "_Y"+0		\n"
		"ldd "_ST21", "_Y"+1		\n"
		"ldd "_ST31", "_Y"+2		\n"
		"ldd "_ST41", "_Y"+3		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ZL", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H1", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H2", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H3", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H4", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"mov "_ZL", "_ST21"		\n"
		"lpm "_ZL", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"mov "_ZL", "_ST31"		\n"
		"lpm "_ZL", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"mov "_ZL", "_ST41"		\n"
		"lpm "_ZL", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"st "_Y"+, "_H1"		\n"
		"st "_Y"+, "_H2"		\n"
		"st "_Y"+, "_H3"		\n"
		"st "_Y"+, "_H4"		\n"
		"dec "_I"		\n"
		"sbrs "_I", 7		\n"
		"jmp patchd0		\n"
		: "+y" (expanded)
		:
		: "memory", _H1, _H2, _H3, _H4, _H5, _I, _ST11, _ST21, _ST31, _ST41, _ZH, _ZL
		#undef _H1
		#undef _H2
		#undef _H3
		#undef _H4
		#undef _H5
		#undef _I
		#undef _ST11
		#undef _ST21
		#undef _ST31
		#undef _ST41
		#undef _Y
		#undef _YL
		#undef _YH
		#undef _Z
		#undef _ZH
		#undef _ZL
	);
}
#endif

#define _H1 "r18"
#define _H2 "r19"
#define _H3 "r20"
#define _H4 "r21"
#define _H5 "r22"
#define _I "r23"
#define _ST11 "r24"
#define _ST12 "r25"
#define _ST13 "r0"
#define _ST14 "r4"
#define _ST21 "r5"
#define _ST22 "r6"
#define _ST23 "r7"
#define _ST24 "r8"
#define _ST31 "r9"
#define _ST32 "r10"
#define _ST33 "r11"
#define _ST34 "r12"
#define _ST41 "r13"
#define _ST42 "r14"
#define _ST43 "r15"
#define _ST44 "r16"
#define _X "X"
#define _XH "r27"
#define _XL "r26"
#define _Y "Y"
#define _YH "r29"
#define _YL "r28"
#define _Z "Z"
#define _ZH "r31"
#define _ZL "r30"

#if AES_CIPHER
void aesCipher(const unsigned char* expanded, unsigned char* data)
{

	asm volatile (
	
		"ld "_ST11", "_X"+		\n"
		"ld "_ST21", "_X"+		\n"
		"ld "_ST31", "_X"+		\n"
		"ld "_ST41", "_X"+		\n"
		"ld "_ST12", "_X"+		\n"
		"ld "_ST22", "_X"+		\n"
		"ld "_ST32", "_X"+		\n"
		"ld "_ST42", "_X"+		\n"
		"ld "_ST13", "_X"+		\n"
		"ld "_ST23", "_X"+		\n"
		"ld "_ST33", "_X"+		\n"
		"ld "_ST43", "_X"+		\n"
		"ld "_ST14", "_X"+		\n"
		"ld "_ST24", "_X"+		\n"
		"ld "_ST34", "_X"+		\n"
		"ld "_ST44", "_X"+		\n"
		"sbiw "_XL", 16		\n"
		
		"rcall encryp1		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"ldi "_I", 8		\n"
		"encryp0:mov "_ZL", "_ST11"		\n"		// 1
		"lpm "_H2", "_Z"		\n"
		"mov "_H3", "_H2"		\n"
		"mov "_H4", "_H2"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H1", "_Z"		\n"
		"eor "_H4", "_H1"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H2", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H2", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"ldd "_ST11", "_Y"+0		\n"
		"eor "_ST11", "_H1"		\n"
		"mov "_ZL", "_ST41"		\n"		// 2
		"ldd "_ST41", "_Y"+3		\n"
		"eor "_ST41", "_H4"		\n"
		"lpm "_H1", "_Z"		\n"
		"mov "_H4", "_H1"		\n"
		"mov "_ST33", "_H1"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_ST44", "_Z"		\n"
		"eor "_ST33", "_ST44"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_ST44", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_ST33", "_H5"		\n"
		"eor "_ST44", "_H5"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_ST33", "_H5"		\n"
		"eor "_ST44", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_ST44", "_H5"		\n"
		"ldd "_ST12", "_Y"+4		\n"
		"eor "_ST12", "_H1"		\n"
		"ldd "_ST22", "_Y"+5		\n"
		"eor "_ST22", "_H4"		\n"
		"mov "_ZL", "_ST31"		\n"		// 3
		"ldd "_ST31", "_Y"+2		\n"
		"eor "_ST31", "_H3"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H3", "_ST34"		\n"
		"mov "_H1", "_ST34"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H4", "_Z"		\n"
		"eor "_H3", "_H4"		\n"
		"mov "_ZL", "_ST42"		\n"
		"ldd "_ST42", "_Y"+7		\n"
		"eor "_ST42", "_ST44"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"eor "_H1", "_H5"		\n"
		"ldd "_ST13", "_Y"+8		\n"
		"eor "_ST13", "_ST34"		\n"
		"ldd "_ST23", "_Y"+9		\n"
		"eor "_ST23", "_H3"		\n"
		"mov "_ZL", "_ST32"		\n"		// 4
		"ldd "_ST32", "_Y"+6		\n"
		"eor "_ST32", "_ST33"		\n"
		"ldd "_ST33", "_Y"+10		\n"
		"eor "_ST33", "_H4"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_ST34", "_ST24"		\n"
		"mov "_H4", "_ST24"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H3", "_Z"		\n"
		"eor "_ST34", "_H3"		\n"
		"mov "_ZL", "_ST43"		\n"
		"ldd "_ST43", "_Y"+11		\n"
		"eor "_ST43", "_H1"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox02)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"mov "_ZL", "_ST21"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"eor "_ST34", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_sbox)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"eor "_H3", "_H5"		\n"
		"eor "_H4", "_H5"		\n"
		"ldd "_ST21", "_Y"+1		\n"
		"eor "_ST21", "_H2"		\n"
		"ldd "_ST14", "_Y"+12		\n"
		"eor "_ST14", "_ST24"		\n"
		"ldd "_ST24", "_Y"+13		\n"
		"eor "_ST24", "_ST34"		\n"
		"ldd "_ST34", "_Y"+14		\n"
		"eor "_ST34", "_H3"		\n"
		"ldd "_ST44", "_Y"+15		\n"
		"eor "_ST44", "_H4"		\n"
		"adiw "_YL", 16		\n"
		"dec "_I"		\n"
		"sbrs "_I",7		\n"
		"jmp encryp0		\n"
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST21"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_H1", "_ST31"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_H1", "_ST32"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H1", "_ST41"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_ST41", "_Z"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST44", "_Z"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST43", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST42", "_Z"		\n"
		"rjmp encryp2		\n"
	
		"encryp1:ld "_H1", "_Y"+		\n"
		"eor "_ST11", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST21", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST31", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST41", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST12", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST22", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST32", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST42", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST13", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST23", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST33", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST43", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST14", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST24", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST34", "_H1"		\n"
		"ld "_H1", "_Y"+		\n"
		"eor "_ST44", "_H1"		\n"
		"ret		\n"
	
		"encryp2:		\n"
		"rcall encryp1		\n"
	
		"st "_X"+, "_ST11"		\n"
		"st "_X"+, "_ST21"		\n"
		"st "_X"+, "_ST31"		\n"
		"st "_X"+, "_ST41"		\n"
		"st "_X"+, "_ST12"		\n"
		"st "_X"+, "_ST22"		\n"
		"st "_X"+, "_ST32"		\n"
		"st "_X"+, "_ST42"		\n"
		"st "_X"+, "_ST13"		\n"
		"st "_X"+, "_ST23"		\n"
		"st "_X"+, "_ST33"		\n"
		"st "_X"+, "_ST43"		\n"
		"st "_X"+, "_ST14"		\n"
		"st "_X"+, "_ST24"		\n"
		"st "_X"+, "_ST34"		\n"
		"st "_X"+, "_ST44"		\n"
	
		: "+y" (expanded), "+x" (data)
		:
		: "memory",_H1, _H2, _H3, _H4, _H5, _I, _ST11,
		_ST12, _ST13, _ST14, _ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34, _ST41, _ST42, _ST43,
		_ST44, _ZH, _ZL
	);
}
#endif

#if AES_INVCIPHER
void aesInvCipher(const unsigned char* patched, unsigned char* data)
{

	asm volatile (
	
		"ld "_ST11", "_X"+		\n"
		"ld "_ST21", "_X"+		\n"
		"ld "_ST31", "_X"+		\n"
		"ld "_ST41", "_X"+		\n"
		"ld "_ST12", "_X"+		\n"
		"ld "_ST22", "_X"+		\n"
		"ld "_ST32", "_X"+		\n"
		"ld "_ST42", "_X"+		\n"
		"ld "_ST13", "_X"+		\n"
		"ld "_ST23", "_X"+		\n"
		"ld "_ST33", "_X"+		\n"
		"ld "_ST43", "_X"+		\n"
		"ld "_ST14", "_X"+		\n"
		"ld "_ST24", "_X"+		\n"
		"ld "_ST34", "_X"+		\n"
		"ld "_ST44", "_X"+		\n"
		"sbiw "_XL", 16		\n"
	
		"subi "_YL", 0x50		\n"
		"sbci "_YH", 0xFF		\n"

		"rcall decryp1		\n"
		"ldi "_I", 8		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"decryp0:sbiw "_YL", 16		\n"
		"mov "_ZL", "_ST11"		\n"		// 1
		"lpm "_H1", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H2", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H3", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H4", "_Z"		\n"
		"mov "_ZL", "_ST24"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldd "_ST11", "_Y"+0		\n"
		"eor "_ST11", "_H1"		\n"
		"mov "_ZL", "_ST21"		\n"		// 2
		"ldd "_ST21", "_Y"+1		\n"
		"eor "_ST21", "_H2"		\n"
		"lpm "_H2", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_ST24", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_ST33", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H1", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST24", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldd "_ST12", "_Y"+4		\n"
		"eor "_ST12", "_H1"		\n"
		"ldd "_ST42", "_Y"+7		\n"
		"eor "_ST42", "_ST33"		\n"
		"mov "_ZL", "_ST31"		\n"		// 3
		"ldd "_ST31", "_Y"+2		\n"
		"eor "_ST31", "_H3"		\n"
		"lpm "_ST34", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H3", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H1", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST34", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_ST33", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldd "_ST13", "_Y"+8		\n"
		"eor "_ST13", "_H1"		\n"
		"ldd "_ST43", "_Y"+11		\n"
		"eor "_ST43", "_H3"		\n"
		"ldd "_ST22", "_Y"+5		\n"
		"eor "_ST22", "_H2"		\n"
		"mov "_ZL", "_ST41"		\n"		// 4
		"ldd "_ST41", "_Y"+3		\n"
		"eor "_ST41", "_H4"		\n"
		"lpm "_H4", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H1", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H2", "_Z"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H3", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0b)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"mov "_ZL", "_ST32"		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H2", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0d)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H1", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox09)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H4", "_H5"		\n"
		"ldi "_ZH", hi8(aes_tab_isbox0e)		\n"
		"lpm "_H5", "_Z"		\n"
		"eor "_H3", "_H5"		\n"
		"ldd "_ST14", "_Y"+12		\n"
		"eor "_ST14", "_H1"		\n"
		"ldd "_ST23", "_Y"+9		\n"
		"eor "_ST23", "_ST33"		\n"
		"ldd "_ST32", "_Y"+6		\n"
		"eor "_ST32", "_ST24"		\n"
		"ldd "_ST33", "_Y"+10		\n"
		"eor "_ST33", "_ST34"		\n"
		"ldd "_ST34", "_Y"+14		\n"
		"eor "_ST34", "_H3"		\n"
		"ldd "_ST44", "_Y"+15		\n"
		"eor "_ST44", "_H4"		\n"
		"ldd "_ST24", "_Y"+13		\n"
		"eor "_ST24", "_H2"		\n"
		"dec "_I"		\n"
		"sbrs "_I",7		\n"
		"jmp decryp0		\n"
		"ldi "_ZH", hi8(aes_tab_isbox)		\n"
		"mov "_ZL", "_ST11"		\n"
		"lpm "_ST11", "_Z"		\n"
		"mov "_ZL", "_ST12"		\n"
		"lpm "_ST12", "_Z"		\n"
		"mov "_ZL", "_ST13"		\n"
		"lpm "_ST13", "_Z"		\n"
		"mov "_ZL", "_ST14"		\n"
		"lpm "_ST14", "_Z"		\n"
		"mov "_H1", "_ST24"		\n"
		"mov "_ZL", "_ST23"		\n"
		"lpm "_ST24", "_Z"		\n"
		"mov "_ZL", "_ST22"		\n"
		"lpm "_ST23", "_Z"		\n"
		"mov "_ZL", "_ST21"		\n"
		"lpm "_ST22", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST21", "_Z"		\n"
		"mov "_H1", "_ST31"		\n"
		"mov "_ZL", "_ST33"		\n"
		"lpm "_ST31", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST33", "_Z"		\n"
		"mov "_H1", "_ST32"		\n"
		"mov "_ZL", "_ST34"		\n"
		"lpm "_ST32", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST34", "_Z"		\n"
		"mov "_H1", "_ST41"		\n"
		"mov "_ZL", "_ST42"		\n"
		"lpm "_ST41", "_Z"		\n"
		"mov "_ZL", "_ST43"		\n"
		"lpm "_ST42", "_Z"		\n"
		"mov "_ZL", "_ST44"		\n"
		"lpm "_ST43", "_Z"		\n"
		"mov "_ZL", "_H1"		\n"
		"lpm "_ST44", "_Z"		\n"
		"rjmp decryp2		\n"
		"decryp1:ld "_H1", -"_Y"		\n"
		"eor "_ST44", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST34", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST24", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST14", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST43", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST33", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST23", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST13", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST42", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST32", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST22", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST12", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST41", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST31", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST21", "_H1"		\n"
		"ld "_H1", -"_Y"		\n"
		"eor "_ST11", "_H1"		\n"
		"ret		\n"
		"decryp2:		\n"
		"rcall decryp1		\n"

		"st "_X"+, "_ST11"		\n"
		"st "_X"+, "_ST21"		\n"
		"st "_X"+, "_ST31"		\n"
		"st "_X"+, "_ST41"		\n"
		"st "_X"+, "_ST12"		\n"
		"st "_X"+, "_ST22"		\n"
		"st "_X"+, "_ST32"		\n"
		"st "_X"+, "_ST42"		\n"
		"st "_X"+, "_ST13"		\n"
		"st "_X"+, "_ST23"		\n"
		"st "_X"+, "_ST33"		\n"
		"st "_X"+, "_ST43"		\n"
		"st "_X"+, "_ST14"		\n"
		"st "_X"+, "_ST24"		\n"
		"st "_X"+, "_ST34"		\n"
		"st "_X"+, "_ST44"		\n"

		: "+y" (patched), "+x" (data)
		:
		: "memory",_H1, _H2, _H3, _H4, _H5, _I, _ST11,
		_ST12, _ST13, _ST14, _ST21, _ST22, _ST23, _ST24,
		_ST31, _ST32, _ST33, _ST34, _ST41, _ST42, _ST43,
		_ST44, _ZH, _ZL
	);
}
#endif


#endif
