#ifndef _lmic_config_h_
#define _lmic_config_h_

// In the original LMIC code, these config values were defined on the
// gcc commandline. Since Arduino does not allow easily modifying the
// compiler commandline, use this file instead.

#define CFG_eu868 1
//#define CFG_us915 1
#define CFG_sx1272_radio 1
//#define CFG_sx1276_radio 1

// 16 μs per tick
// LMIC requires ticks to be 15.5μs - 100 μs long
#define US_PER_OSTICK_EXPONENT 4
#define US_PER_OSTICK (1 << US_PER_OSTICK_EXPONENT)
#define OSTICKS_PER_SEC (1000000 / US_PER_OSTICK)

// Uncomment this to disable all code related to joining
//#define DISABLE_JOIN
// Uncomment this to disable all code related to ping
//#define DISABLE_PING
// Uncomment this to disable all code related to beacon tracking.
// Requires ping to be disabled too
//#define DISABLE_BEACONS

// Uncomment these to disable the corresponding MAC commands.
// Class A
//#define DISABLE_MCMD_DCAP_REQ // duty cycle cap
//#define DISABLE_MCMD_DN2P_SET // 2nd DN window param
//#define DISABLE_MCMD_SNCH_REQ // set new channel
// Class B
//#define DISABLE_MCMD_PING_SET // set ping freq, automatically disabled by DISABLE_PING
//#define DISABLE_MCMD_BCNI_ANS // next beacon start, automatical disabled by DISABLE_BEACON

// 0 is a no-op AES
// 1 is regular LMIC
// 2 is Ideetron AES
// 3 is tiny-AES128-C
// 4 is AESLib (that uses a license incompatible with the EPL!)
// 5 is aes-min (see ../aes-min/aes-sbox.h to enable small sbox)
// 6 is aes-min with precalculated key schedule (calculated on first
// use and kept in global memory afterwards). Note that this does not
// support key changes and currently, this implementation does not
// produce valid packets for some reason!
#define AES_IMPLEMENTATION 1

#endif // _lmic_config_h_
