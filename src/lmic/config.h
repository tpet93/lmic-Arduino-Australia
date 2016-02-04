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
#define US_PER_OSTICK 16
#define OSTICKS_PER_SEC (1000000 / US_PER_OSTICK)

// Uncomment this to disable all code related to joining
//#define DISABLE_JOIN
// Uncomment this to disable all code related to ping
//#define DISABLE_PING
// Uncomment this to disable all code related to beacon tracking.
// Requires ping to be disabled too
//#define DISABLE_BEACONS

#endif // _lmic_config_h_
