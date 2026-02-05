package org.unicitylabs.nostr.crypto;

import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Edge case tests for NIP-44 encryption.
 * Covers version byte validation, payload boundary conditions, and error handling.
 *
 * Techniques: [BVA] Boundary Value Analysis, [EG] Error Guessing
 */
public class NIP44EdgeCasesTest {

    // ==========================================================
    // Version Byte Validation
    // ==========================================================

    @Test
    public void testRejectVersionByte0x00() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        // Change version byte to 0x00
        decoded[0] = 0x00;
        String modified = Base64.getEncoder().encodeToString(decoded);

        try {
            NIP44Encryption.decrypt(modified, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for version 0x00");
        } catch (Exception e) {
            assertTrue("Should mention unsupported version",
                    e.getMessage().toLowerCase().contains("version") ||
                    e.getMessage().toLowerCase().contains("unsupported"));
        }
    }

    @Test
    public void testRejectVersionByte0x01() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        // Change version byte to 0x01
        decoded[0] = 0x01;
        String modified = Base64.getEncoder().encodeToString(decoded);

        try {
            NIP44Encryption.decrypt(modified, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for version 0x01");
        } catch (Exception e) {
            assertTrue("Should mention unsupported version",
                    e.getMessage().toLowerCase().contains("version") ||
                    e.getMessage().toLowerCase().contains("unsupported"));
        }
    }

    @Test
    public void testRejectVersionByte0xFF() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        // Change version byte to 0xFF
        decoded[0] = (byte) 0xFF;
        String modified = Base64.getEncoder().encodeToString(decoded);

        try {
            NIP44Encryption.decrypt(modified, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for version 0xFF");
        } catch (Exception e) {
            assertTrue("Should mention unsupported version",
                    e.getMessage().toLowerCase().contains("version") ||
                    e.getMessage().toLowerCase().contains("unsupported"));
        }
    }

    // ==========================================================
    // Payload Length Validation
    // ==========================================================

    @Test
    public void testRejectPayloadOf10Bytes() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] shortPayload = new byte[10];
        shortPayload[0] = 0x02; // Correct version
        String encoded = Base64.getEncoder().encodeToString(shortPayload);

        try {
            NIP44Encryption.decrypt(encoded, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for payload of only 10 bytes");
        } catch (Exception e) {
            assertTrue("Should mention too short",
                    e.getMessage().toLowerCase().contains("short") ||
                    e.getMessage().toLowerCase().contains("length") ||
                    e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testRejectPayloadOf72Bytes() throws Exception {
        // 72 bytes is 1 under minimum (1 + 24 + 32 + 16 = 73)
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] payload = new byte[72];
        payload[0] = 0x02;
        String encoded = Base64.getEncoder().encodeToString(payload);

        try {
            NIP44Encryption.decrypt(encoded, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for 72-byte payload");
        } catch (Exception e) {
            assertTrue("Should fail for 72-byte payload",
                    e.getMessage().toLowerCase().contains("short") ||
                    e.getMessage().toLowerCase().contains("length") ||
                    e.getMessage().toLowerCase().contains("invalid") ||
                    e instanceof SecurityException);
        }
    }

    @Test
    public void testMinimumLengthPayloadFailsOnCrypto() throws Exception {
        // Minimum valid length is 73 bytes (1 + 24 + 32 + 16)
        // This should NOT fail with "too short" but should fail on crypto validation
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] payload = new byte[73];
        payload[0] = 0x02; // Correct version
        // Rest is zeros - will fail on crypto, not on "too short"
        String encoded = Base64.getEncoder().encodeToString(payload);

        try {
            NIP44Encryption.decrypt(encoded, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for invalid crypto data");
        } catch (Exception e) {
            // Should NOT be "too short" error
            assertFalse("Should not throw 'too short' for 73-byte payload",
                    e.getMessage().toLowerCase().contains("too short"));
        }
    }

    @Test
    public void testRejectTruncatedNonce() throws Exception {
        // 1 (version) + 10 (partial nonce) = 11 bytes total
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] payload = new byte[11];
        payload[0] = 0x02;
        String encoded = Base64.getEncoder().encodeToString(payload);

        try {
            NIP44Encryption.decrypt(encoded, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for truncated nonce");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    // ==========================================================
    // Corrupted Data Tests
    // ==========================================================

    @Test
    public void testCorruptedNonceFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test data", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = Base64.getDecoder().decode(encrypted);

        // Corrupt nonce area (bytes 1-24)
        for (int i = 1; i <= 24 && i < decoded.length; i++) {
            decoded[i] = (byte) ((decoded[i] + 1) % 256);
        }
        String corrupted = Base64.getEncoder().encodeToString(decoded);

        try {
            NIP44Encryption.decrypt(corrupted, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for corrupted nonce");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testRejectEmptyBase64String() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        try {
            NIP44Encryption.decrypt("", bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for empty base64 string");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testRejectInvalidBase64() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        try {
            NIP44Encryption.decrypt("not-valid-base64!!!", bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for invalid base64");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    // ==========================================================
    // Unpad Error Handling
    // ==========================================================

    @Test
    public void testUnpadRejectsTooShortInput() {
        // Less than 2 + 32 = 34 bytes
        byte[] shortPadded = new byte[10];

        try {
            NIP44Encryption.unpad(shortPadded);
            fail("Expected exception for too-short padded data");
        } catch (Exception e) {
            assertTrue("Should mention too short or invalid",
                    e.getMessage().toLowerCase().contains("short") ||
                    e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testUnpadRejectsZeroLengthPrefix() {
        // Create a padded buffer with length prefix = 0
        byte[] padded = new byte[2 + 32]; // 34 bytes
        padded[0] = 0x00;
        padded[1] = 0x00; // length = 0

        try {
            NIP44Encryption.unpad(padded);
            fail("Expected exception for zero length prefix");
        } catch (Exception e) {
            assertTrue("Should reject zero length",
                    e.getMessage().toLowerCase().contains("length") ||
                    e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    @Test
    public void testUnpadRejectsWrongPaddingSize() {
        // Create a padded buffer with mismatched padding
        // Length prefix claims 5 bytes, but calcPaddedLen(5) = 32, not 64
        byte[] padded = new byte[2 + 64]; // 66 bytes total
        padded[0] = 0x00;
        padded[1] = 0x05; // claims 5 bytes

        try {
            NIP44Encryption.unpad(padded);
            fail("Expected exception for wrong padding size");
        } catch (Exception e) {
            assertTrue("Should reject invalid padding",
                    e.getMessage().toLowerCase().contains("padding") ||
                    e.getMessage().toLowerCase().contains("invalid"));
        }
    }

    // ==========================================================
    // Pad Error Handling
    // ==========================================================

    @Test
    public void testPadRejectsEmptyMessage() {
        try {
            NIP44Encryption.pad(new byte[0]);
            fail("Expected exception for empty message");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testPadRejectsMessageExceedingMaxLength() {
        try {
            NIP44Encryption.pad(new byte[65536]);
            fail("Expected exception for message exceeding max length");
        } catch (Exception e) {
            assertTrue("Should mention too long",
                    e.getMessage().toLowerCase().contains("long") ||
                    e.getMessage().toLowerCase().contains("max"));
        }
    }

    @Test
    public void testPadAcceptsMaxLengthMessage() {
        byte[] padded = NIP44Encryption.pad(new byte[65535]);
        assertTrue(padded.length >= 2 + 65535);
    }

    // ==========================================================
    // Padding Roundtrip Tests
    // ==========================================================

    @Test
    public void testPadUnpadRoundtripVariousLengths() {
        int[] testLengths = {1, 5, 16, 31, 32, 33, 50, 64, 65, 100, 256, 500, 1000};

        for (int len : testLengths) {
            byte[] message = new byte[len];
            for (int i = 0; i < len; i++) {
                message[i] = (byte) (i % 256);
            }

            byte[] padded = NIP44Encryption.pad(message);
            byte[] unpadded = NIP44Encryption.unpad(padded);

            assertArrayEquals("Failed for length " + len, message, unpadded);
        }
    }

    @Test
    public void testPaddedLengthIncludesTwoBytePrefix() {
        byte[] message = new byte[]{1, 2, 3, 4, 5}; // 5 bytes
        byte[] padded = NIP44Encryption.pad(message);

        // First 2 bytes are big-endian length
        int encodedLength = ((padded[0] & 0xFF) << 8) | (padded[1] & 0xFF);
        assertEquals(5, encodedLength);

        // Total length should be 2 + calcPaddedLen(5)
        assertEquals(2 + NIP44Encryption.calcPaddedLen(5), padded.length);
    }

    @Test
    public void testPaddedLengthForLargeMessage() {
        byte[] message = new byte[300]; // 0x012C
        byte[] padded = NIP44Encryption.pad(message);

        // Check big-endian length prefix
        assertEquals(0x01, padded[0] & 0xFF); // high byte
        assertEquals(0x2C, padded[1] & 0xFF); // low byte (300 & 0xFF = 44 = 0x2C)
    }
}
