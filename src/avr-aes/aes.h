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

#ifndef aes_h
#define aes_h


/************************************************************************/
/*   COMFIGURATION                                                      */
/*                                                                      */
/*  Change following definitions to suit your needs.                    */
/************************************************************************/

/*
*	Select implementation:
*	0 - SMALL by D. Kiliam
*	1 - FANTASTIC by B. Poettering
*	2 - FURIOUS by B. Poettering
*	3 - FAST by B. Poettering
*	4 - MINI by D. Kilian
*/
#define AES_IMPLEMENTATION 3

/*
*	Add aesCipher to the library.
*/
#define AES_CIPHER 1

/*
*	Add aesInvCipher to the library.
*/
#define AES_INVCIPHER 1

/*
*	Add aesKeyRewind to the library, if available.
*/
#define AES_KEYREWIND 1

/*
*	Add aesKeyPatch to the library, if available.
*/
#define AES_KEYPATCH 1

/*
*	Add aesKeyExpand to the library, if available.
*/
#define AES_KEYEXPAND 1

/*
*	Use short array instead of SBOX.
*	Only significant in SMALL implementation.
*/
#define AES_SHORTSBOX 0

/*
*	Use short array instead of inverse of SBOX.
*	Only significant in SMALL implementation and when AES_INVCIPHER != 0.
*/
#define AES_SHORTINVSBOX 0

/*
*	Use faster function for ShiftRows and InvShiftRows transformations.
*	Only significant in SMALL implementation.
*/
#define AES_FASTSHROWS 1

/*
*	Use faster function for MixColumns and InvMixColumns transformations.
*	Only significant in SMALL implementation and when AES_CIPHER != 0 && AES_INVCIPHER != 0.
*/
#define AES_FASTMIXCOL 0

/*
*	Size of short array. Correct values: 10, 12, 16, 20, ..., 4*N, ..., 248, 252, 256
*	Only significant in SMALL implementation and when
*	AES_SHORTSBOX != 0 || AES_SHORTINVSBOX != 0.
*/
#define AES_SHORTSBOXSIZE 16

/*
*	Allow inline assembler.
*	Only significant in SMALL implementation.
*/
#define AES_USEASM 1




/************************************************************************/
/*   LIBRARY INTERFACE                                                  */
/*                                                                      */
/*  See documentation for details.                                      */
/************************************************************************/


#if AES_IMPLEMENTATION == 0 || AES_IMPLEMENTATION == 1

// Fantastic and Small

#if AES_CIPHER
void aesCipher(unsigned char* key, unsigned char* data);
#endif

#if AES_INVCIPHER
void aesInvCipher(unsigned char* patched, unsigned char* data);
#endif

#if AES_KEYREWIND
void aesKeyRewind(unsigned char* patched);
#endif

#if AES_KEYPATCH
void aesKeyPatch(unsigned char* key);
#endif

#elif AES_IMPLEMENTATION == 2 || AES_IMPLEMENTATION == 3

// Fast and Furious

#if AES_CIPHER
void aesCipher(const unsigned char* expanded, unsigned char* data);
#endif

#if AES_KEYEXPAND
void aesKeyExpand(const unsigned char* key, unsigned char* expanded);
#endif

#if AES_IMPLEMENTATION == 2

#if AES_INVCIPHER
void aesInvCipher(const unsigned char* expanded, unsigned char* data);
#endif

#else

#if AES_KEYPATCH
void aesKeyPatch(unsigned char* expanded);
#endif

#if AES_INVCIPHER
void aesInvCipher(const unsigned char* patched, unsigned char* data);
#endif

#endif

#elif AES_IMPLEMENTATION == 4

// Mini

#if AES_CIPHER
extern char aesTempBuffer[21];
void aesCipher(const unsigned char* key, unsigned char* data);
#endif


#endif


#endif
