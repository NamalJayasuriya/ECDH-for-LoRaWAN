#include <uECC.h> //https://www.arduinolibraries.info/libraries/micro-ecc
#include <MemoryFree.h> //https://github.com/maniacbug/MemoryFree

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


//  //-----elliptic curve 160r1 ---------------
//  const struct uECC_Curve_t * curve = uECC_secp160r1();
//
//  char private1[21];
//  char private2[21];
//
//  char public1[40];
//  char public2[40];
//
//  char secret1[20];
//
//  char hash[21] = "asdfghjklmnbvcxzasdfg";
//  char sig[40] = "asdfghjklmnbvcxzasdfgasdfghjklmnbvcxzas";//{0};
//-----------------------------------------------

//    //-----elliptic curve 192r1 ---------------
//  const struct uECC_Curve_t * curve = uECC_secp192r1();
//
//  char private1[24];
//  char private2[24];
//
//  char public1[48];
//  char public2[48];
//
//  char secret1[24];
//
//  char hash[24] = "asdfghjklmnbvcxzasdfg";
//  char sig[48] = "asdfghjklmnbvcxzasdfgasdfghjklmnbvcxzas";//{0};
//-----------------------------------------------

//  //-----elliptic curve 224r1 ---------------
//  const struct uECC_Curve_t * curve = uECC_secp224r1();
//
//  char private1[28];
//  char private2[28];
//
//  char public1[56];
//  char public2[56];
//
//  char secret1[28];
//
//  char hash[28] = "asdfghjklmnbvcxzasdfg";
//  char sig[56] = "asdfghjklmnbvcxzasdfgasdfghjklmnbvcxzas";//{0};
//-----------------------------------------------

//-----elliptic curve 256k1/ 256r1 ---------------
const struct uECC_Curve_t * curve = uECC_secp256k1();
//const struct uECC_Curve_t * curve = uECC_secp256r1();

char private1[32];
char private2[32];

char public1[64];
char public2[64];

char secret1[32];

char hash[32] = "asdfghjklmnbvcxzasdfg";
char sig[64] = "asdfghjklmnbvcxzasdfgasdfghjklmnbvcxzas";//{0};
//-----------------------------------------------

void ecdh_code_space() {

  //key exchange

 uECC_make_key(public1, private1, curve);
 uECC_make_key(public2, private2, curve);
 int r = uECC_shared_secret(public2, private1, secret1, curve);

}

void ecdsa_code_space() {

  // ecds and verification

  uECC_sign(private1, hash, sizeof(hash), sig, curve);
  uECC_verify(public1, hash, sizeof(hash), sig, curve);

}

void ecdh_ram() {

 //key exchange
 Serial.print(F("init ---- - ")); Serial.println(2560 - freeMemory());
 uECC_make_key(public1, private1, curve);
 Serial.print(F("key pair 1 ---- - ")); Serial.println(2560 - freeMemory());
 uECC_make_key(public2, private2, curve);
 Serial.print(F("key pair two ---- - ")); Serial.println(2560 - freeMemory());
 int r = uECC_shared_secret(public2, private1, secret1, curve);
 Serial.print(F("secret gen ---- - ")); Serial.println(2560 - freeMemory());

}

void ecdsa_ram() {

  //  // ecds and verification

  uECC_sign(private1, hash, sizeof(hash), sig, curve);
  Serial.print(F("sign ---- - "));Serial.println(2560-freeMemory());
  uECC_verify(public1, hash, sizeof(hash), sig, curve);
  Serial.print(F("verify ---- - "));Serial.println(2560-freeMemory());

}

void ecdh_time() {

  unsigned long a = millis();
  uECC_make_key(public1, private1, curve);
  unsigned long b = millis();
  Serial.print("Made key 1 in "); Serial.println(b - a);

  a = millis();
   uECC_make_key(public2, private2, curve);
   b = millis();
   Serial.print("Made key 2 in "); Serial.println(b - a);

   a = millis();
   int r = uECC_shared_secret(public2, private1, secret1, curve);
   b = millis();
   Serial.print("Shared secret 1 in "); Serial.println(b - a);

   if (!r) {
     Serial.print("shared_secret() failed (1)\n");
     return;
   }

}

void ecdsa_time() {

  unsigned long a = millis();
  if (!uECC_sign(private1, hash, sizeof(hash), sig, curve)) {
    Serial.println("uECC_sign() failed\n");
    return 1;
  }
  unsigned long b = millis();
  //print after sign
  Serial.print("222 hash : "); Serial.print((char)hash); Serial.print(", ssign : "); Serial.println((char)sig);
  Serial.print("digitally signe : "); Serial.println(b - a);

  a = millis();
  if (!uECC_verify(public1, hash, sizeof(hash), sig, curve)) {
    Serial.println("uECC_verify() failed\n");
    return 1;
  }
  b = millis();
  //signature verification
  Serial.print("333 hash : "); Serial.print((char)hash); Serial.print(", ssign : "); Serial.println((char)sig);
  Serial.print("ssignature verified : "); Serial.println(b - a);

}

void setup() {
  Serial.begin(115200);
  Serial.print("Testing ecc\n");
  //delay(2000);
  //Serial.println("----------------");
  uECC_set_rng(&RNG);
}

void loop() {

  //uncomment the variable declaration only for the relavant key size (at the top of this code)

  //uncomment to test code space and global data mem allocation
  ecdh_code_space();
  ecdsa_code_space();

  //uncomment to test free space of ram
  //ecdh_ram();
  //ecdsa_ram();

  //uncomment to test time consumptions and the execution results
  //ecdh_time();
  //ecdsa_time();

}
