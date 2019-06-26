/*******************************************************************************
 * Copyright (c) 2015 Thomas Telkamp and Matthijs Kooijman
 * Copyright (c) 2018 Terry Moore, MCCI
 *
 * Permission is hereby granted, free of charge, to anyone
 * obtaining a copy of this document and accompanying files,
 * to do whatever they want with them without any restriction,
 * including, but not limited to, copying, modification and redistribution.
 * NO WARRANTY OF ANY KIND IS PROVIDED.
 *
 * This example sends a valid LoRaWAN packet with payload "Hello,
 * world!", using frequency and encryption settings matching those of
 * the The Things Network.
 *
 * This uses OTAA (Over-the-air activation), where where a DevEUI and
 * application key is configured, which are used in an over-the-air
 * activation procedure where a DevAddr and session keys are
 * assigned/generated for use with all further communication.
 *
 * Note: LoRaWAN per sub-band duty-cycle limitation is enforced (1% in
 * g1, 0.1% in g2), but not the TTN fair usage policy (which is probably
 * violated by this sketch when left running for longer)!

 * To use this sketch, first register your application and device with
 * the things network, to set or generate an AppEUI, DevEUI and AppKey.
 * Multiple devices can use the same AppEUI, but each device has its own
 * DevEUI and AppKey.
 *
 * Do not forget to define the radio type correctly in
 * arduino-lmic/project_config/lmic_project_config.h or from your BOARDS.txt.
 *
 *******************************************************************************/

#include <lmic.h>
#include <hal/hal.h>
#include <SPI.h>
#include <uECC.h>
//#include <MemoryFree.h>
//-------------------------
extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }

      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"


  //-----elliptic curve 256k1 ---------------
  const struct uECC_Curve_t * curve = uECC_secp256k1();

  char private1[32];
  //char private2[32];

  char public1[64]; //my pub
  char public2[64];  //net pub
  char public3[64];  //app pub

  char secret1[32];  //net secret
  char secret2[32];  //app ssecret

  char hash[32];// = "asdfghjklmnbvcxzasdfg";
  char sig[64];// = "asdfghjklmnbvcxzasdfgasdfghjklmnbvcxzas";//{0};
//-------------------------
//
// For normal use, we require that you edit the sketch to replace FILLMEIN
// with values assigned by the TTN console. However, for regression tests,
// we want to be able to compile these scripts. The regression tests define
// COMPILE_REGRESSION_TEST, and in that case we define FILLMEIN to a non-
// working but innocuous value.
//
#ifdef COMPILE_REGRESSION_TEST
# define FILLMEIN 0
#else
# warning "You must replace the values marked FILLMEIN with real values from the TTN control panel!"
# define FILLMEIN (#dont edit this, edit the lines that use FILLMEIN)
#endif

// This EUI must be in little-endian format, so least-significant-byte
// first. When copying an EUI from ttnctl output, this means to reverse
// the bytes. For TTN issued EUIs the last bytes should be 0xD5, 0xB3,
// 0x70.
static const u1_t PROGMEM APPEUI[8]={ 0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x01, 0x20, 0x94 };
void os_getArtEui (u1_t* buf) { memcpy_P(buf, APPEUI, 8);}

// This should also be in little endian format, see above.
static const u1_t PROGMEM DEVEUI[8]={ 0x00, 0xBA, 0xAC, 0xBB, 0xF3, 0x3A, 0x5F, 0xCE };
void os_getDevEui (u1_t* buf) { memcpy_P(buf, DEVEUI, 8);}

// This key should be in big endian format (or, since it is not really a
// number but a block of memory, endianness does not really apply). In
// practice, a key taken from ttnctl can be copied as-is.
static const u1_t PROGMEM APPKEY[16] = { 0x25, 0x7E, 0x95, 0xD9, 0xA3, 0x97, 0xFA, 0x46, 0x37, 0x4C, 0xDA, 0x25, 0xAA, 0xCC, 0xF2, 0x75 };
void os_getDevKey (u1_t* buf) {  memcpy_P(buf, APPKEY, 16);}

static uint8_t mydata[] = "Hello, world!";
static osjob_t sendjob;

// Schedule TX every this many seconds (might become longer due to duty
// cycle limitations).
const unsigned TX_INTERVAL = 60;

// Pin mapping
const lmic_pinmap lmic_pins = {
    .nss = 8, //6,
    .rxtx = LMIC_UNUSED_PIN,
    .rst = 4, //5,
    .dio = {7, 6, LMIC_UNUSED_PIN}, //{2, 3, 4},
};


void onEvent (ev_t ev) {
    //Serial.print(F("loop ---- - "));Serial.println(freeMemory());
//    Serial.print(os_getTime());
//    Serial.print(": ");
    switch(ev) {
        case EV_SCAN_TIMEOUT:
            //Serial.println(F("EV_SCAN_TIMEOUT"));
            break;
        case EV_BEACON_FOUND:
            //Serial.println(F("EV_BEACON_FOUND"));
            break;
        case EV_BEACON_MISSED:
            //Serial.println(F("EV_BEACON_MISSED"));
            break;
        case EV_BEACON_TRACKED:
            //Serial.println(F("EV_BEACON_TRACKED"));
            break;
        case EV_JOINING:
            //Serial.println(millis());
            LMIC_setDrTxpow(DR_SF9,14);
            LMIC_setAdrMode(1);
            //Serial.println(F("EV_JOINING"));
            //Serial.print(F("loop mem - "));Serial.println(freeMemory());
            //Serial.println(millis());

            break;
        case EV_JOINED:
            //Serial.println(F("EV_JOINED"));
            {
              //Serial.println(millis());
              //Serial.print(F("loop mem - "));Serial.println(freeMemory());
              u4_t netid = 0;
              devaddr_t devaddr = 0;
              u1_t nwkKey[16];
              u1_t artKey[16];
              LMIC_getSessionKeys(&netid, &devaddr, nwkKey, artKey);
//              Serial.print("netid: ");
//              Serial.println(netid, DEC);
//              Serial.print("devaddr: ");
//              Serial.println(devaddr, HEX);
//              Serial.print("artKey: ");
//              for (int i=0; i<sizeof(artKey); ++i) {
//                Serial.print(artKey[i], HEX);
//              }
//              Serial.println("");
//              Serial.print("nwkKey: ");
//              for (int i=0; i<sizeof(nwkKey); ++i) {
//                Serial.print(nwkKey[i], HEX);
//              }
//              Serial.println("");

              //Serial.println(millis());
              //Serial.print(F("loop mem - "));Serial.println(freeMemory());

            }
            // Disable link check validation (automatically enabled
            // during join, but because slow data rates change max TX
	    // size, we don't use it in this example.
            LMIC_setLinkCheckMode(0);
            break;
        /*
        || This event is defined but not used in the code. No
        || point in wasting codespace on it.
        ||
        || case EV_RFU1:
        ||     Serial.println(F("EV_RFU1"));
        ||     break;
        */
        case EV_JOIN_FAILED:
            //Serial.println(F("EV_JOIN_FAILED"));
            break;
        case EV_REJOIN_FAILED:
            //Serial.println(F("EV_REJOIN_FAILED"));
            break;
        case EV_TXCOMPLETE:
//            Serial.println(F("EV_TXCOMPLETE (includes waiting for RX windows)"));
//            if (LMIC.txrxFlags & TXRX_ACK)
//              Serial.println(F("Received ack"));
//            if (LMIC.dataLen) {
//              Serial.print(F("Received "));
//              Serial.print(LMIC.dataLen);
//              Serial.println(F(" bytes of payload"));
//            }
            // Schedule next transmission
            os_setTimedCallback(&sendjob, os_getTime()+sec2osticks(TX_INTERVAL), do_send);
            break;
        case EV_LOST_TSYNC:
            //Serial.println(F("EV_LOST_TSYNC"));
            break;
        case EV_RESET:
            //Serial.println(F("EV_RESET"));
            break;
        case EV_RXCOMPLETE:
            // data received in ping slot
            //Serial.println(F("EV_RXCOMPLETE"));
            break;
        case EV_LINK_DEAD:
            //Serial.println(F("EV_LINK_DEAD"));
            break;
        case EV_LINK_ALIVE:
            //Serial.println(F("EV_LINK_ALIVE"));
            break;
        /*
        || This event is defined but not used in the code. No
        || point in wasting codespace on it.
        ||
        || case EV_SCAN_FOUND:
        ||    Serial.println(F("EV_SCAN_FOUND"));
        ||    break;
        */
        case EV_TXSTART:
            //Serial.println(F("EV_TXSTART"));
            break;
        default:
            //Serial.print(F("Unknown event: "));
            //Serial.println((unsigned) ev);
            break;
    }
}

void do_send(osjob_t* j){
    // Check if there is not a current TX/RX job running
    if (LMIC.opmode & OP_TXRXPEND) {
        //Serial.println(F("OP_TXRXPEND, not sending"));
    } else {
        // Prepare upstream data transmission at the next possible time.
        LMIC_setTxData2(1, mydata, sizeof(mydata)-1, 0);
        //Serial.println(F("Packet queued"));
    }
    // Next TX is scheduled after TX_COMPLETE event.
}

void setup() {
    //delay(2000);
    //Serial.println("------------");
    //delay(2000);
    Serial.begin(9600);
    Serial.println(F("Starting"));

    #ifdef VCC_ENABLE
    // For Pinoccio Scout boards
    pinMode(VCC_ENABLE, OUTPUT);
    digitalWrite(VCC_ENABLE, HIGH);
    delay(1000);
    #endif

    // LMIC init
    os_init();
    // Reset the MAC state. Session and pending data transfers will be discarded.
    LMIC_reset();

    // Start job (sending automatically starts OTAA too)
    do_send(&sendjob);
}

void loop() {
    os_runloop_once();

    uECC_make_key(public1, private1, curve);

    uECC_make_key(public2, private2, curve);

    int r = uECC_shared_secret(public2, private1, secret1, curve);

    if (!r) {
      //Serial.print("shared_secret() failed (1)\n");
      return;
    }

    r = uECC_shared_secret(public1, private2, secret2, curve);
    if (!r) {
      //Serial.print("shared_secret() failed (2)\n");
      return;
    }

    if (memcmp(secret1, secret2, 20) != 0) {
      //Serial.print("Shared secrets are not identical!\n");
    } else {
      //Serial.print("Shared secrets are identical\n");
    }

    //---------------------------------------------------
    if (!uECC_sign(private1, hash, sizeof(hash), sig, curve)) {
        //Serial.println("uECC_sign() failed\n");
        return 1;
    }
    if (!uECC_verify(public1, hash, sizeof(hash), sig, curve)) {
        //Serial.println("uECC_verify() failed\n");
        return 1;
    }
  }
