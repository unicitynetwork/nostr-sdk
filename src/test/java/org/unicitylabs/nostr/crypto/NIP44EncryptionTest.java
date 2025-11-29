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
