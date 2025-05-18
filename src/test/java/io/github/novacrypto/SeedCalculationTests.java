/*
 *  BIP39 library, a Java implementation of BIP39
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Original source: https://github.com/NovaCrypto/BIP39
 *  You can contact the authors via github issues.
 */

package io.github.novacrypto;

import io.github.novacrypto.bip39.JavaxPBKDF2WithHmacSHA512;
import io.github.novacrypto.bip39.SeedCalculator;
import io.github.novacrypto.testjson.EnglishJson;
import org.junit.Test;

import static io.github.novacrypto.Hex.toHex;
import static org.junit.Assert.assertEquals;

public final class SeedCalculationTests {

    @Test
    public void bip39_english() {
        assertEquals("2eea1e4d099089606b7678809be6090ccba0fca171d4ed42c550194ca8e3600cd1e5989dcca38e5f903f5c358c92e0dcaffc9e71a48ad489bb868025c907d1e1",
                calculateSeedHex("solar puppy hawk oxygen trip brief erase slot fossil mechanic filter voice"));
    }

    @Test
    public void bip39_english_with_passphrase() {
        assertEquals("36732d826f4fa483b5fe8373ef8d6aa3cb9c8fb30463d6c0063ee248afca2f87d11ebe6e75c2fb2736435994b868f8e9d4f4474c65ee05ac47aad7ef8a497846",
                calculateSeedHex("solar puppy hawk oxygen trip brief erase slot fossil mechanic filter voice", "CryptoIsCool"));
    }

    @Test
    public void all_english_test_vectors() {
        final EnglishJson data = EnglishJson.load();
        for (final String[] testCase : data.english) {
            assertEquals(testCase[2], calculateSeedHex(testCase[1], "TREZOR"));
        }
    }

    private static String calculateSeedHex(final String mnemonic) {
        return calculateSeedHex(mnemonic, "");
    }

    private static String calculateSeedHex(String mnemonic, String passphrase) {
        final String seed1 = calculateSeed(mnemonic, passphrase, new SeedCalculator());
        final String seed2 = calculateSeed(mnemonic, passphrase, new SeedCalculator(JavaxPBKDF2WithHmacSHA512.INSTANCE));
        assertEquals(seed1, seed2);
        return seed1;
    }

    private static String calculateSeed(String mnemonic, String passphrase, SeedCalculator seedCalculator) {
        return toHex(seedCalculator.calculateSeed(mnemonic, passphrase));
    }
}
