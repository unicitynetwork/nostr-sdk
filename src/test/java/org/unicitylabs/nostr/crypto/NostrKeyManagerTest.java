package org.unicitylabs.nostr.crypto;

import org.junit.Test;

import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Unit tests for NostrKeyManager — key management, signing, and encryption.
 */
public class NostrKeyManagerTest {

    // --- Factory: generate() ---

    @Test
    public void testGenerateCreatesValidKeypair() {
        NostrKeyManager km = NostrKeyManager.generate();

        assertEquals(32, km.getPrivateKey().length);
        assertEquals(32, km.getPublicKey().length);
        assertEquals(64, km.getPublicKeyHex().length());
        assertFalse(Arrays.equals(new byte[32], km.getPrivateKey()));
    }

    @Test
    public void testGenerateProducesUniqueKeys() {
        NostrKeyManager km1 = NostrKeyManager.generate();
        NostrKeyManager km2 = NostrKeyManager.generate();

        assertFalse(Arrays.equals(km1.getPrivateKey(), km2.getPrivateKey()));
        assertFalse(Arrays.equals(km1.getPublicKey(), km2.getPublicKey()));
    }

    // --- Factory: fromPrivateKey() ---

    @Test
    public void testFromPrivateKeyValid() {
        NostrKeyManager original = NostrKeyManager.generate();
        byte[] privateKey = original.getPrivateKey();

        NostrKeyManager restored = NostrKeyManager.fromPrivateKey(privateKey);

        assertArrayEquals(original.getPrivateKey(), restored.getPrivateKey());
        assertArrayEquals(original.getPublicKey(), restored.getPublicKey());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKeyEmpty() {
        NostrKeyManager.fromPrivateKey(new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKey31Bytes() {
        NostrKeyManager.fromPrivateKey(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKey33Bytes() {
        NostrKeyManager.fromPrivateKey(new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKey64Bytes() {
        NostrKeyManager.fromPrivateKey(new byte[64]);
    }

    // --- Factory: fromPrivateKeyHex() ---

    @Test
    public void testFromPrivateKeyHexValid() {
        NostrKeyManager original = NostrKeyManager.generate();
        String hex = original.getPrivateKeyHex();

        NostrKeyManager restored = NostrKeyManager.fromPrivateKeyHex(hex);

        assertArrayEquals(original.getPrivateKey(), restored.getPrivateKey());
        assertEquals(original.getPublicKeyHex(), restored.getPublicKeyHex());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKeyHexInvalidString() {
        NostrKeyManager.fromPrivateKeyHex("not_a_hex_string");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromPrivateKeyHexOddLength() {
        // 63 hex chars = invalid
        NostrKeyManager.fromPrivateKeyHex("a".repeat(63));
    }

    @Test
    public void testFromPrivateKeyHexCaseInsensitive() {
        NostrKeyManager original = NostrKeyManager.generate();
        String hexLower = original.getPrivateKeyHex();
        String hexUpper = hexLower.toUpperCase();

        NostrKeyManager restored = NostrKeyManager.fromPrivateKeyHex(hexUpper);
        assertEquals(original.getPublicKeyHex(), restored.getPublicKeyHex());
    }

    // --- Factory: fromNsec() ---

    @Test
    public void testFromNsecValid() {
        NostrKeyManager original = NostrKeyManager.generate();
        String nsec = original.getNsec();

        NostrKeyManager restored = NostrKeyManager.fromNsec(nsec);

        assertArrayEquals(original.getPrivateKey(), restored.getPrivateKey());
        assertEquals(original.getPublicKeyHex(), restored.getPublicKeyHex());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromNsecWithNpubThrows() {
        NostrKeyManager km = NostrKeyManager.generate();
        NostrKeyManager.fromNsec(km.getNpub()); // npub, not nsec
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFromNsecWithInvalidBech32() {
        NostrKeyManager.fromNsec("nsec1invalidchecksum");
    }

    // --- Key Format Getters ---

    @Test
    public void testAllKeyFormatsAreConsistent() {
        NostrKeyManager km = NostrKeyManager.generate();

        // Hex encoding of bytes should match hex getter
        assertEquals(km.getPrivateKeyHex(), bytesToHex(km.getPrivateKey()));
        assertEquals(km.getPublicKeyHex(), bytesToHex(km.getPublicKey()));

        // Bech32 round-trip
        Bech32.DecodedBech32 decodedNsec = Bech32.decode(km.getNsec());
        assertArrayEquals(km.getPrivateKey(), decodedNsec.data);

        Bech32.DecodedBech32 decodedNpub = Bech32.decode(km.getNpub());
        assertArrayEquals(km.getPublicKey(), decodedNpub.data);
    }

    @Test
    public void testGetPrivateKeyReturnsDefensiveCopy() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] key1 = km.getPrivateKey();
        byte[] key2 = km.getPrivateKey();

        // Modify first copy
        key1[0] ^= 0xFF;

        // Second copy should be unaffected
        assertArrayEquals(key2, km.getPrivateKey());
    }

    @Test
    public void testGetPublicKeyReturnsDefensiveCopy() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] key1 = km.getPublicKey();
        byte[] key2 = km.getPublicKey();

        key1[0] ^= 0xFF;

        assertArrayEquals(key2, km.getPublicKey());
    }

    @Test
    public void testNpubStartsWithNpub1() {
        NostrKeyManager km = NostrKeyManager.generate();
        assertTrue(km.getNpub().startsWith("npub1"));
    }

    @Test
    public void testNsecStartsWithNsec1() {
        NostrKeyManager km = NostrKeyManager.generate();
        assertTrue(km.getNsec().startsWith("nsec1"));
    }

    // --- Signing & Verification ---

    @Test
    public void testSignAndVerifyRoundTrip() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());

        byte[] sig = km.sign(hash);
        assertTrue(NostrKeyManager.verify(sig, hash, km.getPublicKey()));
    }

    @Test
    public void testSignHexReturns128CharString() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] hash = new byte[32];
        new java.security.SecureRandom().nextBytes(hash);

        String sigHex = km.signHex(hash);
        assertEquals(128, sigHex.length());
    }

    @Test
    public void testVerifyHexValid() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());
        String sigHex = km.signHex(hash);

        assertTrue(NostrKeyManager.verifyHex(sigHex, hash, km.getPublicKeyHex()));
    }

    @Test
    public void testVerifyHexWithInvalidHexReturnsFalse() {
        byte[] hash = new byte[32];
        assertFalse(NostrKeyManager.verifyHex("invalid_hex", hash, "invalid_hex"));
    }

    @Test
    public void testVerifyHexWithWrongKeyReturnsFalse() throws Exception {
        NostrKeyManager km1 = NostrKeyManager.generate();
        NostrKeyManager km2 = NostrKeyManager.generate();
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());
        String sigHex = km1.signHex(hash);

        assertFalse(NostrKeyManager.verifyHex(sigHex, hash, km2.getPublicKeyHex()));
    }

    // --- isMyPublicKey ---

    @Test
    public void testIsMyPublicKeyTrue() {
        NostrKeyManager km = NostrKeyManager.generate();
        assertTrue(km.isMyPublicKey(km.getPublicKeyHex()));
    }

    @Test
    public void testIsMyPublicKeyCaseInsensitive() {
        NostrKeyManager km = NostrKeyManager.generate();
        assertTrue(km.isMyPublicKey(km.getPublicKeyHex().toUpperCase()));
    }

    @Test
    public void testIsMyPublicKeyFalseForOtherKey() {
        NostrKeyManager km1 = NostrKeyManager.generate();
        NostrKeyManager km2 = NostrKeyManager.generate();
        assertFalse(km1.isMyPublicKey(km2.getPublicKeyHex()));
    }

    // --- clear() ---

    @Test
    public void testClearZerosOutPrivateKey() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] originalPublicKey = km.getPublicKey();

        km.clear();

        // Private key should be all zeros now
        byte[] clearedKey = km.getPrivateKey();
        assertArrayEquals(new byte[32], clearedKey);

        // Public key is still accessible (it was derived, not the secret)
        assertArrayEquals(originalPublicKey, km.getPublicKey());
    }

    // --- toString ---

    @Test
    public void testToStringDoesNotLeakFullKeys() {
        NostrKeyManager km = NostrKeyManager.generate();
        String str = km.toString();
        assertNotNull(str);
        assertTrue(str.contains("..."));
        // Should not contain full 64-char hex key
        assertFalse(str.contains(km.getPublicKeyHex()));
    }

    // --- Helper ---

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
