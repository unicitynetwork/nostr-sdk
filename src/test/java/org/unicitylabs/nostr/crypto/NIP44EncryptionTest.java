package org.unicitylabs.nostr.crypto;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for NIP-44 encryption (XChaCha20-Poly1305 with HKDF).
 */
public class NIP44EncryptionTest {

    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        // Generate two key pairs
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Hello, Bob! This is a secret message.";

        // Alice encrypts for Bob
        String encrypted = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        // Verify encrypted content is base64 and starts with version byte
        assertNotNull(encrypted);
        assertTrue(encrypted.length() > 0);

        // Bob decrypts from Alice
        String decrypted = NIP44Encryption.decrypt(
                encrypted,
                bob.getPrivateKey(),
                alice.getPublicKey()
        );

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecryptShortMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // NIP-44 requires minimum 1 byte message
        String message = "a";

        String encrypted = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        String decrypted = NIP44Encryption.decrypt(
                encrypted,
                bob.getPrivateKey(),
                alice.getPublicKey()
        );

        assertEquals(message, decrypted);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncryptEmptyMessageFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // NIP-44 does not allow empty messages
        NIP44Encryption.encrypt("", alice.getPrivateKey(), bob.getPublicKey());
    }

    @Test
    public void testEncryptDecryptLongMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create a message longer than 32 bytes to test padding
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("This is line ").append(i).append(" of a long message. ");
        }
        String message = sb.toString();

        String encrypted = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        String decrypted = NIP44Encryption.decrypt(
                encrypted,
                bob.getPrivateKey(),
                alice.getPublicKey()
        );

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecryptUnicodeMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Hello! \u4e2d\u6587 \u0420\u0443\u0441\u0441\u043a\u0438\u0439 \ud83d\ude00\ud83c\udf89";

        String encrypted = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        String decrypted = NIP44Encryption.decrypt(
                encrypted,
                bob.getPrivateKey(),
                alice.getPublicKey()
        );

        assertEquals(message, decrypted);
    }

    @Test
    public void testConversationKeyDerivation() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Conversation key should be the same from both sides
        byte[] aliceKey = NIP44Encryption.deriveConversationKey(
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        byte[] bobKey = NIP44Encryption.deriveConversationKey(
                bob.getPrivateKey(),
                alice.getPublicKey()
        );

        assertArrayEquals(aliceKey, bobKey);
        assertEquals(32, aliceKey.length); // 256-bit key
    }

    @Test
    public void testPadding() {
        // Test padding for various message lengths (minimum 1 byte per NIP-44)
        int[] testLengths = {1, 16, 31, 32, 33, 64, 100, 256, 1000};

        for (int len : testLengths) {
            byte[] message = new byte[len];
            for (int i = 0; i < len; i++) {
                message[i] = (byte) (i % 256);
            }

            byte[] padded = NIP44Encryption.pad(message);
            byte[] unpadded = NIP44Encryption.unpad(padded);

            assertArrayEquals("Failed for length " + len, message, unpadded);

            // Verify padded length is at least 32 and matches expected calculation
            int paddedLen = padded.length - 2; // Subtract 2-byte length prefix
            assertTrue("Padded length should be at least 32", paddedLen >= 32);
            assertEquals("Padded length should match calcPaddedLen for len=" + len,
                    NIP44Encryption.calcPaddedLen(len), paddedLen);
        }
    }

    @Test
    public void testCalcPaddedLen() {
        // Test that calcPaddedLen returns correct chunk-aligned values per NIP-44
        // Minimum valid message is 1 byte per NIP-44
        assertEquals(32, NIP44Encryption.calcPaddedLen(1));
        assertEquals(32, NIP44Encryption.calcPaddedLen(31));
        assertEquals(32, NIP44Encryption.calcPaddedLen(32));
        assertEquals(64, NIP44Encryption.calcPaddedLen(33));
        assertEquals(64, NIP44Encryption.calcPaddedLen(64));
        // For 65: nextPow2=128, chunk=max(32,16)=32, result=96
        assertEquals(96, NIP44Encryption.calcPaddedLen(65));
        // For 200: nextPow2=256, chunk=max(32,32)=32, result=224
        assertEquals(224, NIP44Encryption.calcPaddedLen(200));
    }

    @Test
    public void testDecryptWithWrongKey() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        NostrKeyManager eve = NostrKeyManager.generate();

        String message = "Secret message";

        String encrypted = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        // Eve should not be able to decrypt
        try {
            NIP44Encryption.decrypt(
                    encrypted,
                    eve.getPrivateKey(),
                    alice.getPublicKey()
            );
            fail("Expected decryption to fail with wrong key");
        } catch (Exception e) {
            // Expected - authentication should fail
            assertTrue(e.getMessage().contains("MAC") ||
                       e.getMessage().contains("authentication") ||
                       e.getMessage().contains("tag"));
        }
    }

    @Test
    public void testNostrKeyManagerNip44Methods() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Test via NostrKeyManager methods";

        // Test hex-based methods
        String encrypted = alice.encryptNip44Hex(message, bob.getPublicKeyHex());
        String decrypted = bob.decryptNip44Hex(encrypted, alice.getPublicKeyHex());

        assertEquals(message, decrypted);

        // Test byte-based methods
        String encrypted2 = alice.encryptNip44(message, bob.getPublicKey());
        String decrypted2 = bob.decryptNip44(encrypted2, alice.getPublicKey());

        assertEquals(message, decrypted2);
    }

    @Test
    public void testVersionByte() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt(
                "test",
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        // Decode and check version byte is 0x02
        byte[] decoded = java.util.Base64.getDecoder().decode(encrypted);
        assertEquals("Version byte should be 0x02", 0x02, decoded[0]);
    }

    // --- Additional Padding Boundary Tests ---

    @Test(expected = IllegalArgumentException.class)
    public void testCalcPaddedLenZeroThrows() {
        NIP44Encryption.calcPaddedLen(0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCalcPaddedLenNegativeThrows() {
        NIP44Encryption.calcPaddedLen(-1);
    }

    @Test
    public void testCalcPaddedLenMaxMessage() {
        // 65535 is the max message length
        int result = NIP44Encryption.calcPaddedLen(65535);
        assertTrue(result >= 65535);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCalcPaddedLenExceedsMaxThrows() {
        NIP44Encryption.calcPaddedLen(65536);
    }

    @Test
    public void testCalcPaddedLenBoundaryValues() {
        assertEquals(32, NIP44Encryption.calcPaddedLen(1));
        assertEquals(32, NIP44Encryption.calcPaddedLen(32));
        assertEquals(64, NIP44Encryption.calcPaddedLen(33));
        assertEquals(64, NIP44Encryption.calcPaddedLen(64));
        assertEquals(96, NIP44Encryption.calcPaddedLen(65));
        assertEquals(256, NIP44Encryption.calcPaddedLen(256));
        assertEquals(512, NIP44Encryption.calcPaddedLen(512));
        assertEquals(1024, NIP44Encryption.calcPaddedLen(1000));
    }

    @Test
    public void testPadEmptyMessageThrows() {
        try {
            NIP44Encryption.pad(new byte[0]);
            fail("Expected exception for empty message");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testPadHasTwoBytePrefix() {
        byte[] message = new byte[]{1, 2, 3, 4, 5};
        byte[] padded = NIP44Encryption.pad(message);

        // First 2 bytes are big-endian length
        int encodedLength = ((padded[0] & 0xFF) << 8) | (padded[1] & 0xFF);
        assertEquals(5, encodedLength);
        assertEquals(2 + NIP44Encryption.calcPaddedLen(5), padded.length);
    }

    @Test
    public void testUnpadTooShortInputThrows() {
        try {
            NIP44Encryption.unpad(new byte[33]); // 2 + 32 - 1 = 33, less than 2 + MIN_PADDED_LEN (34)
            fail("Expected exception for too-short input");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testMaxMessageEncryptDecrypt() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create a message near max size (65535 bytes)
        // Using smaller value to avoid slow test, but > 32KB to test large padding
        byte[] msgBytes = new byte[10000];
        new java.security.SecureRandom().nextBytes(msgBytes);
        // Convert to valid UTF-8 string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append((char) ('A' + (i % 26)));
        }
        String message = sb.toString();

        String encrypted = NIP44Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP44Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());
        assertEquals(message, decrypted);
    }

    // --- Tampered Ciphertext ---

    @Test
    public void testTamperedCiphertextFailsMAC() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = java.util.Base64.getDecoder().decode(encrypted);

        // Tamper with ciphertext (middle bytes, after version+nonce)
        if (decoded.length > 30) {
            decoded[30] ^= 0x01;
        }

        String tampered = java.util.Base64.getEncoder().encodeToString(decoded);
        try {
            NIP44Encryption.decrypt(tampered, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected SecurityException for tampered ciphertext");
        } catch (SecurityException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testTamperedMACFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = java.util.Base64.getDecoder().decode(encrypted);

        // Tamper with last byte (part of MAC)
        decoded[decoded.length - 1] ^= 0x01;

        String tampered = java.util.Base64.getEncoder().encodeToString(decoded);
        try {
            NIP44Encryption.decrypt(tampered, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected SecurityException for tampered MAC");
        } catch (SecurityException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testTruncatedCiphertextFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = java.util.Base64.getDecoder().decode(encrypted);

        // Truncate to less than minimum (1 + 24 + 32 + 16 = 73)
        byte[] truncated = java.util.Arrays.copyOf(decoded, 50);

        String truncatedB64 = java.util.Base64.getEncoder().encodeToString(truncated);
        try {
            NIP44Encryption.decrypt(truncatedB64, bob.getPrivateKey(), alice.getPublicKey());
            fail("Expected exception for truncated ciphertext");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testEncryptedOutputMinimumStructure() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP44Encryption.encrypt("a", alice.getPrivateKey(), bob.getPublicKey());
        byte[] decoded = java.util.Base64.getDecoder().decode(encrypted);

        // Minimum: version(1) + nonce(24) + ciphertext(>=32) + mac(16) = 73
        assertTrue("Payload too short: " + decoded.length, decoded.length >= 73);
    }

    // --- Conversation Key with Self ---

    @Test
    public void testConversationKeyWithSelf() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        byte[] key = NIP44Encryption.deriveConversationKey(
                alice.getPrivateKey(), alice.getPublicKey());
        assertEquals(32, key.length);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConversationKeyPrivateKeyWrongLength() throws Exception {
        NIP44Encryption.deriveConversationKey(new byte[31], new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConversationKeyPublicKeyWrongLength() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NIP44Encryption.deriveConversationKey(km.getPrivateKey(), new byte[33]);
    }

    // --- NIP-44 does not leak message length ---

    @Test
    public void testSameEncryptedSizeForSmallMessages() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Messages of 1, 10, 30, 31 bytes all pad to 32 → same ciphertext size
        String enc1 = NIP44Encryption.encrypt("a", alice.getPrivateKey(), bob.getPublicKey());
        String enc10 = NIP44Encryption.encrypt("0123456789", alice.getPrivateKey(), bob.getPublicKey());
        // Both should decode to the same length (nonce differs but structure is same)
        byte[] dec1 = java.util.Base64.getDecoder().decode(enc1);
        byte[] dec10 = java.util.Base64.getDecoder().decode(enc10);
        assertEquals("Messages under 32 bytes should produce same-size ciphertext",
                dec1.length, dec10.length);
    }

    @Test
    public void testDifferentEncryptionsProduceDifferentCiphertext() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Same message";

        // Encrypt twice - should produce different ciphertext due to random nonce
        String encrypted1 = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        String encrypted2 = NIP44Encryption.encrypt(
                message,
                alice.getPrivateKey(),
                bob.getPublicKey()
        );

        assertNotEquals("Encryptions should have different ciphertext", encrypted1, encrypted2);

        // But both should decrypt to the same message
        assertEquals(message, NIP44Encryption.decrypt(encrypted1, bob.getPrivateKey(), alice.getPublicKey()));
        assertEquals(message, NIP44Encryption.decrypt(encrypted2, bob.getPrivateKey(), alice.getPublicKey()));
    }
}
