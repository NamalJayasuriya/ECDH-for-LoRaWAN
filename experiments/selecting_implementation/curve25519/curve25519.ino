/*
   Copyright (C) 2015 Southern Storm Software, Pty Ltd.

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

/*
  This example runs tests on the Curve25519 algorithm.
*/

#include "Crypto.h"
#include "Curve25519.h"
#include "Ed25519.h"
#include "utility/ProgMemUtil.h"
#include "RNG.h"
#include "string.h"
#include <MemoryFree.h>

void printNumber(const char *name, const uint8_t *x)
{
  static const char hexchars[] = "0123456789ABCDEF";
  Serial.print(name);
  Serial.print(" = ");
  for (uint8_t posn = 0; posn < 32; ++posn) {
    Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
    Serial.print(hexchars[x[posn] & 0x0F]);
  }
  Serial.println();
}

void testDH_time()
{
  static uint8_t alice_k[32];
  static uint8_t alice_f[32];
  static uint8_t bob_k[32];
  static uint8_t bob_f[32];
  Serial.println("Diffie-Hellman key exchange:");
  Serial.print("Generate random k/f for Alice ... ");
  Serial.flush();
  unsigned long start = micros();
  Curve25519::dh1(alice_k, alice_f);
  unsigned long elapsed = micros() - start;
  Serial.print("elapsed ");
  Serial.print(elapsed);
  Serial.println(" us");

  Serial.print("Generate random k/f for Bob ... ");
  Serial.flush();
  start = micros();
  Curve25519::dh1(bob_k, bob_f);
  elapsed = micros() - start;
  Serial.print("elapsed ");
  Serial.print(elapsed);
  Serial.println(" us");

  Serial.print("Generate shared secret for Alice ... ");
  Serial.flush();
  start = micros();
  Curve25519::dh2(bob_k, alice_f);
  elapsed = micros() - start;
  Serial.print("elapsed ");
  Serial.print(elapsed);
  Serial.println(" us");

  Serial.print("Generate shared secret for Bob ... ");
  Serial.flush();
  start = micros();
  Curve25519::dh2(alice_k, bob_f);
  elapsed = micros() - start;
  Serial.print("elapsed ");
  Serial.print(elapsed);
  Serial.println(" us");

  Serial.print("Check that the shared secrets match ... ");
  if (memcmp(alice_k, bob_k, 32) == 0)
    Serial.println("ok");
  else
    Serial.println("failed");
}

void test_dsa_time() {
  // Sign using the test vector.

  static uint8_t alice_k[32];
  static uint8_t alice_f[32];
  uint8_t signature[64];
  uint8_t msg[4] = {0x01, 0x02, 0x03, 0x04};

  Serial.print("curve 25519 DSA test.....");
  Serial.print(" sign ... ");
  Serial.flush();
  unsigned long start = micros();
  Ed25519::sign(signature, alice_k, alice_f, msg, 2);
  unsigned long elapsed = micros() - start;

  Serial.print(" (elapsed ");
  Serial.print(elapsed);
  Serial.println(" us)");

  // Verify using the test vector.
  //Serial.print(test->name);
  Serial.print(" verify ... ");
  Serial.flush();
  start = micros();
  bool verified = Ed25519::verify(signature, alice_f, msg, 2);
  elapsed = micros() - start;
  if (verified) {
    Serial.print("ok");
  } else {
    Serial.println("failed");
  }
  Serial.print(" (elapsed ");
  Serial.print(elapsed);
  Serial.println(" us)");
}

void testDH_ram() {

  static uint8_t alice_k[32];
  static uint8_t alice_f[32];
  static uint8_t bob_k[32];
  static uint8_t bob_f[32];

  Serial.print(F("init ---- - ")); Serial.println(2560 - freeMemory());
  Curve25519::dh1(alice_k, alice_f);
  Serial.print(F("dh1 ---- - ")); Serial.println(2560 - freeMemory());
  Curve25519::dh2(alice_k, bob_f);
  Serial.print(F("dh2 ---- - ")); Serial.println(2560 - freeMemory());
}

void testDSA_ram() {
  static uint8_t alice_k[32];
  static uint8_t alice_f[32];

  uint8_t signature[64];
  uint8_t msg[4] = {0x01, 0x02, 0x03, 0x04};

  Serial.print(F("init ---- - ")); Serial.println(2560 - freeMemory());
  Ed25519::sign(signature, alice_k, alice_f, msg, 2);
  Serial.print(F("sign ---- - ")); Serial.println(2560 - freeMemory());
  bool verified = Ed25519::verify(signature, alice_f, msg, 2);
  Serial.print(F("init ---- - ")); Serial.println(2560 - freeMemory());
}

void testDH_code_space() {

  static uint8_t alice_k[32];
  static uint8_t alice_f[32];
  static uint8_t bob_k[32];
  static uint8_t bob_f[32];

  Curve25519::dh1(alice_k, alice_f);
  Curve25519::dh2(bob_k, alice_f);
}

void testDSA_code_space() {

  static uint8_t alice_k[32];
  static uint8_t alice_f[32];

  uint8_t signature[64];
  uint8_t msg[4] = {0x01, 0x02, 0x03, 0x04};

  Ed25519::sign(signature, alice_k, alice_f, msg, 2);
  bool verified = Ed25519::verify(signature, alice_f, msg, 2);
}

void setup()
{
  Serial.begin(9600);

  // Start the random number generator.  We don't initialise a noise
  // source here because we don't need one for testing purposes.
  // Real DH applications should of course use a proper noise source.
  RNG.begin("TestCurve25519 1.0");
  delay(5000);
  Serial.println();
  Serial.println("-------setup-------");
  Serial.println();
  Serial.println("finidhed");
}

void loop()
{
  // Perform the tests.
  //testEval();

  //uncomment to test time consumption
  //testDH_time();
  //test_dsa_time();

  //uncomment to test ram space consumption
  //testDH_ram();
  //testDSA_ram();

  //uncomment to test flash memory and global data consumption
  //testDH_code_space();
  //testDSA_code_space();
}
