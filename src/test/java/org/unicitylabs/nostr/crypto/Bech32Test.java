package org.unicitylabs.nostr.crypto;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Unit tests for Bech32 encoding/decoding (NIP-19).
 */
public class Bech32Test {

    // --- Encode/Decode Round-Trip ---

    @Test
    public void testEncodeDecodeNpubRoundTrip() {
        byte[] publicKey = new byte[32];
        new SecureRandom().nextBytes(publicKey);

        String encoded = Bech32.encode("npub", publicKey);
        Bech32.DecodedBech32 decoded = Bech32.decode(encoded);

        assertEquals("npub", decoded.hrp);
        assertArrayEquals(publicKey, decoded.data);
    }

    @Test
    public void testEncodeDecodeNsecRoundTrip() {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);

        String encoded = Bech32.encode("nsec", privateKey);
        Bech32.DecodedBech32 decoded = Bech32.decode(encoded);

        assertEquals("nsec", decoded.hrp);
        assertArrayEquals(privateKey, decoded.data);
    }

    @Test
    public void testEncodedStringStartsWithHrpAndSeparator() {
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        String npub = Bech32.encode("npub", data);
        assertTrue(npub.startsWith("npub1"));

        String nsec = Bech32.encode("nsec", data);
        assertTrue(nsec.startsWith("nsec1"));
    }

    @Test
    public void testEncodedStringUsesOnlyBech32Charset() {
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        String encoded = Bech32.encode("npub", data);
        // After the '1' separator, only bech32 charset characters
        String dataPart = encoded.substring(encoded.indexOf('1') + 1);
        String charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        for (char c : dataPart.toCharArray()) {
            assertTrue("Invalid character: " + c, charset.indexOf(c) >= 0);
        }
    }

    @Test
    public void testDeterministicEncoding() {
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        String enc1 = Bech32.encode("npub", data);
        String enc2 = Bech32.encode("npub", data);

        assertEquals(enc1, enc2);
    }

    // --- Decode Validation ---

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeStringWithoutSeparator() {
        Bech32.decode("noseparatorhere");
    }

    @Test
    public void testDecodeWithInvalidChecksumFails() {
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        String encoded = Bech32.encode("npub", data);
        // Corrupt last character
        char lastChar = encoded.charAt(encoded.length() - 1);
        char replacement = (lastChar == 'q') ? 'p' : 'q';
        String corrupted = encoded.substring(0, encoded.length() - 1) + replacement;

        try {
            Bech32.decode(corrupted);
            fail("Expected exception for invalid checksum");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("checksum") || e.getMessage().contains("Invalid"));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeEmptyString() {
        Bech32.decode("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeSeparatorAtPosition0() {
        Bech32.decode("1abcdef");
    }

    @Test
    public void testDecodeWithInvalidCharacter() {
        try {
            Bech32.decode("npub1!invalid");
            fail("Expected exception for invalid character");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Invalid") || e.getMessage().contains("character"));
        }
    }

    // --- Round-trip via NostrKeyManager ---

    @Test
    public void testNpubRoundTripViaKeyManager() {
        NostrKeyManager km = NostrKeyManager.generate();
        String npub = km.getNpub();
        assertTrue(npub.startsWith("npub1"));

        Bech32.DecodedBech32 decoded = Bech32.decode(npub);
        assertArrayEquals(km.getPublicKey(), decoded.data);
    }

    @Test
    public void testNsecRoundTripViaKeyManager() {
        NostrKeyManager km = NostrKeyManager.generate();
        String nsec = km.getNsec();
        assertTrue(nsec.startsWith("nsec1"));

        Bech32.DecodedBech32 decoded = Bech32.decode(nsec);
        assertArrayEquals(km.getPrivateKey(), decoded.data);
    }

    // --- Edge cases ---

    @Test
    public void testEncodeDecodeAllZeros() {
        byte[] data = new byte[32];
        String encoded = Bech32.encode("npub", data);
        Bech32.DecodedBech32 decoded = Bech32.decode(encoded);
        assertArrayEquals(data, decoded.data);
    }

    @Test
    public void testEncodeDecodeAllOnes() {
        byte[] data = new byte[32];
        Arrays.fill(data, (byte) 0xFF);
        String encoded = Bech32.encode("npub", data);
        Bech32.DecodedBech32 decoded = Bech32.decode(encoded);
        assertArrayEquals(data, decoded.data);
    }

    @Test
    public void testDecodedBech32Fields() {
        byte[] data = new byte[32];
        new SecureRandom().nextBytes(data);

        String encoded = Bech32.encode("test", data);
        Bech32.DecodedBech32 decoded = Bech32.decode(encoded);

        assertEquals("test", decoded.hrp);
        assertNotNull(decoded.data);
    }
}
