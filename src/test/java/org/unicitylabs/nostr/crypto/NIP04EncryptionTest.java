package org.unicitylabs.nostr.crypto;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Unit tests for NIP-04 AES-256-CBC encryption with ECDH key agreement.
 */
public class NIP04EncryptionTest {

    // --- Shared Secret Derivation ---

    @Test
    public void testSharedSecretIsSymmetric() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] aliceSecret = NIP04Encryption.deriveSharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] bobSecret = NIP04Encryption.deriveSharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        assertArrayEquals(aliceSecret, bobSecret);
        assertEquals(32, aliceSecret.length);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveSharedSecretPrivateKey31Bytes() throws Exception {
        NIP04Encryption.deriveSharedSecret(new byte[31], new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveSharedSecretPrivateKey33Bytes() throws Exception {
        NIP04Encryption.deriveSharedSecret(new byte[33], new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveSharedSecretPublicKey31Bytes() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NIP04Encryption.deriveSharedSecret(km.getPrivateKey(), new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveSharedSecretPublicKey33Bytes() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NIP04Encryption.deriveSharedSecret(km.getPrivateKey(), new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDeriveSharedSecretEmptyPrivateKey() throws Exception {
        NIP04Encryption.deriveSharedSecret(new byte[0], new byte[32]);
    }

    // --- Basic Encrypt/Decrypt Round-Trip ---

    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "Hello, Nostr!";

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());

        assertEquals(message, decrypted);
    }

    @Test
    public void testEncryptedOutputContainsIVSeparator() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP04Encryption.encrypt("test", alice.getPrivateKey(), bob.getPublicKey());
        assertTrue(encrypted.contains("?iv="));

        String[] parts = encrypted.split("\\?iv=");
        assertEquals(2, parts.length);
        assertTrue(parts[0].length() > 0);
        assertTrue(parts[1].length() > 0);
    }

    @Test
    public void testEachEncryptionProducesDifferentCiphertext() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "Same message";

        String enc1 = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        String enc2 = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());

        assertNotEquals(enc1, enc2);

        assertEquals(message, NIP04Encryption.decrypt(enc1, bob.getPrivateKey(), alice.getPublicKey()));
        assertEquals(message, NIP04Encryption.decrypt(enc2, bob.getPrivateKey(), alice.getPublicKey()));
    }

    // --- Compression Threshold (1024 bytes) ---

    @Test
    public void testMessageUnder1024BytesNotCompressed() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create a message just under the threshold
        StringBuilder sb = new StringBuilder();
        while (sb.toString().getBytes("UTF-8").length < 1023) {
            sb.append("a");
        }
        // Trim to exactly 1023 bytes
        while (sb.toString().getBytes("UTF-8").length > 1023) {
            sb.deleteCharAt(sb.length() - 1);
        }
        String message = sb.toString();
        assertTrue(message.getBytes("UTF-8").length <= 1023);

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        assertFalse("Should not be compressed", encrypted.startsWith("gz:"));

        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());
        assertEquals(message, decrypted);
    }

    @Test
    public void testMessageOf1024BytesNotCompressed() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Exactly 1024 bytes — threshold is > 1024, so == 1024 is NOT compressed
        char[] chars = new char[1024];
        Arrays.fill(chars, 'x');
        String message = new String(chars);
        assertEquals(1024, message.getBytes("UTF-8").length);

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        assertFalse("Exactly 1024 bytes should not be compressed", encrypted.startsWith("gz:"));

        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());
        assertEquals(message, decrypted);
    }

    @Test
    public void testMessageOver1024BytesIsCompressed() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // 1025 bytes — just over threshold
        char[] chars = new char[1025];
        Arrays.fill(chars, 'y');
        String message = new String(chars);
        assertEquals(1025, message.getBytes("UTF-8").length);

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        assertTrue("Should be compressed", encrypted.startsWith("gz:"));

        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());
        assertEquals(message, decrypted);
    }

    @Test
    public void testLargeMessageCompressionRoundTrip() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // 10KB of repetitive text (compresses well)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append("The quick brown fox jumps. ");
        }
        String message = sb.toString();
        assertTrue(message.getBytes("UTF-8").length > 1024);

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        assertTrue(encrypted.startsWith("gz:"));

        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());
        assertEquals(message, decrypted);
    }

    // --- Decryption Failure Cases ---

    @Test
    public void testDecryptWithWrongKeyFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        NostrKeyManager eve = NostrKeyManager.generate();

        String encrypted = NIP04Encryption.encrypt("secret", alice.getPrivateKey(), bob.getPublicKey());

        try {
            NIP04Encryption.decrypt(encrypted, eve.getPrivateKey(), alice.getPublicKey());
            fail("Expected decryption to fail with wrong key");
        } catch (Exception e) {
            // Expected — AES padding error
            assertNotNull(e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecryptMalformedCiphertextNoIVSeparator() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        NIP04Encryption.decrypt("invalidbase64data", alice.getPrivateKey(), bob.getPublicKey());
    }

    @Test
    public void testDecryptEmptyStringFails() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        try {
            NIP04Encryption.decrypt("", alice.getPrivateKey(), bob.getPublicKey());
            fail("Expected exception for empty ciphertext");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    // --- Unicode & Special Content ---

    @Test
    public void testUnicodeMessageRoundTrip() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "Hello! \u4f60\u597d \u041f\u0440\u0438\u0432\u0435\u0442 \ud83c\udf89";

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());

        assertEquals(message, decrypted);
    }

    @Test
    public void testEmptyMessageEncryptDecrypt() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP04Encryption.encrypt("", alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());

        assertEquals("", decrypted);
    }

    @Test
    public void testSingleCharacterMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String encrypted = NIP04Encryption.encrypt("a", alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());

        assertEquals("a", decrypted);
    }

    @Test
    public void testMessageWithSpecialCharacters() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "line1\nline2\ttab\"quotes\"\\backslash{json}[array]";

        String encrypted = NIP04Encryption.encrypt(message, alice.getPrivateKey(), bob.getPublicKey());
        String decrypted = NIP04Encryption.decrypt(encrypted, bob.getPrivateKey(), alice.getPublicKey());

        assertEquals(message, decrypted);
    }

    // --- NostrKeyManager NIP-04 Convenience Methods ---

    @Test
    public void testKeyManagerEncryptDecryptByteKeys() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "via KeyManager byte methods";

        String encrypted = alice.encrypt(message, bob.getPublicKey());
        String decrypted = bob.decrypt(encrypted, alice.getPublicKey());

        assertEquals(message, decrypted);
    }

    @Test
    public void testKeyManagerEncryptDecryptHexKeys() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        String message = "via KeyManager hex methods";

        String encrypted = alice.encryptHex(message, bob.getPublicKeyHex());
        String decrypted = bob.decryptHex(encrypted, alice.getPublicKeyHex());

        assertEquals(message, decrypted);
    }
}
