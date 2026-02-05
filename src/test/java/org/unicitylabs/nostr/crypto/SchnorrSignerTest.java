package org.unicitylabs.nostr.crypto;

import org.junit.Test;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Unit tests for BIP-340 Schnorr signatures.
 */
public class SchnorrSignerTest {

    // --- Public Key Derivation ---

    @Test
    public void testDerivePublicKeyFromValidPrivateKey() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] pubkey = SchnorrSigner.getPublicKey(km.getPrivateKey());

        assertNotNull(pubkey);
        assertEquals(32, pubkey.length);
    }

    @Test
    public void testPublicKeyDerivationIsDeterministic() {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);

        byte[] pubkey1 = SchnorrSigner.getPublicKey(privateKey);
        byte[] pubkey2 = SchnorrSigner.getPublicKey(privateKey);

        assertArrayEquals(pubkey1, pubkey2);
    }

    @Test
    public void testDifferentPrivateKeysProduceDifferentPublicKeys() {
        NostrKeyManager km1 = NostrKeyManager.generate();
        NostrKeyManager km2 = NostrKeyManager.generate();

        assertFalse(Arrays.equals(km1.getPublicKey(), km2.getPublicKey()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetPublicKeyWithEmptyKey() {
        SchnorrSigner.getPublicKey(new byte[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetPublicKeyWith31Bytes() {
        SchnorrSigner.getPublicKey(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetPublicKeyWith33Bytes() {
        SchnorrSigner.getPublicKey(new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetPublicKeyWith64Bytes() {
        SchnorrSigner.getPublicKey(new byte[64]);
    }

    @Test
    public void testPublicKeyWithLeadingZerosInPrivateKey() {
        // Private key with leading zeros — tests padTo32Bytes
        byte[] privateKey = new byte[32];
        privateKey[31] = 1; // Only last byte is nonzero
        byte[] pubkey = SchnorrSigner.getPublicKey(privateKey);
        assertEquals(32, pubkey.length);
    }

    // --- Signing ---

    @Test
    public void testSignProduces64ByteSignature() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig = SchnorrSigner.sign(message, privateKey);

        assertNotNull(sig);
        assertEquals(64, sig.length);
    }

    @Test
    public void testSignAndVerifyRoundTrip() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] publicKey = SchnorrSigner.getPublicKey(privateKey);

        byte[] message = MessageDigest.getInstance("SHA-256").digest("test".getBytes());
        byte[] sig = SchnorrSigner.sign(message, privateKey);

        assertTrue(SchnorrSigner.verify(sig, message, publicKey));
    }

    @Test
    public void testSignIsDeterministic() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig1 = SchnorrSigner.sign(message, privateKey);
        byte[] sig2 = SchnorrSigner.sign(message, privateKey);

        assertArrayEquals(sig1, sig2);
    }

    @Test
    public void testDifferentMessagesProduceDifferentSignatures() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] msg1 = MessageDigest.getInstance("SHA-256").digest("message1".getBytes());
        byte[] msg2 = MessageDigest.getInstance("SHA-256").digest("message2".getBytes());

        byte[] sig1 = SchnorrSigner.sign(msg1, privateKey);
        byte[] sig2 = SchnorrSigner.sign(msg2, privateKey);

        assertFalse(Arrays.equals(sig1, sig2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignWithWrongMessageLength31() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        SchnorrSigner.sign(new byte[31], privateKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignWithWrongMessageLength33() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        SchnorrSigner.sign(new byte[33], privateKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignWithEmptyMessage() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        SchnorrSigner.sign(new byte[0], privateKey);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignWithWrongPrivateKeyLength31() throws Exception {
        SchnorrSigner.sign(new byte[32], new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignWithWrongPrivateKeyLength33() throws Exception {
        SchnorrSigner.sign(new byte[32], new byte[33]);
    }

    // --- Verification ---

    @Test
    public void testVerifyValidSignature() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] publicKey = SchnorrSigner.getPublicKey(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig = SchnorrSigner.sign(message, privateKey);
        assertTrue(SchnorrSigner.verify(sig, message, publicKey));
    }

    @Test
    public void testVerifyWithWrongPublicKeyReturnsFalse() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig = SchnorrSigner.sign(message, privateKey);

        // Different key
        byte[] otherPubkey = NostrKeyManager.generate().getPublicKey();
        assertFalse(SchnorrSigner.verify(sig, message, otherPubkey));
    }

    @Test
    public void testVerifyWithTamperedMessageReturnsFalse() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] publicKey = SchnorrSigner.getPublicKey(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig = SchnorrSigner.sign(message, privateKey);

        // Tamper with message
        byte[] tampered = Arrays.copyOf(message, 32);
        tampered[0] ^= 0x01;
        assertFalse(SchnorrSigner.verify(sig, tampered, publicKey));
    }

    @Test
    public void testVerifyWithTamperedSignatureReturnsFalse() throws Exception {
        byte[] privateKey = new byte[32];
        new SecureRandom().nextBytes(privateKey);
        byte[] publicKey = SchnorrSigner.getPublicKey(privateKey);
        byte[] message = new byte[32];
        new SecureRandom().nextBytes(message);

        byte[] sig = SchnorrSigner.sign(message, privateKey);

        // Flip one bit in signature
        byte[] tampered = Arrays.copyOf(sig, 64);
        tampered[0] ^= 0x01;
        assertFalse(SchnorrSigner.verify(tampered, message, publicKey));
    }

    @Test
    public void testVerifyWithWrongSignatureLength63() {
        assertFalse(SchnorrSigner.verify(new byte[63], new byte[32], new byte[32]));
    }

    @Test
    public void testVerifyWithWrongSignatureLength65() {
        assertFalse(SchnorrSigner.verify(new byte[65], new byte[32], new byte[32]));
    }

    @Test
    public void testVerifyWithWrongMessageLength31() throws Exception {
        assertFalse(SchnorrSigner.verify(new byte[64], new byte[31], new byte[32]));
    }

    @Test
    public void testVerifyWithWrongMessageLength33() throws Exception {
        assertFalse(SchnorrSigner.verify(new byte[64], new byte[33], new byte[32]));
    }

    @Test
    public void testVerifyWithWrongPublicKeyLength31() throws Exception {
        assertFalse(SchnorrSigner.verify(new byte[64], new byte[32], new byte[31]));
    }

    @Test
    public void testVerifyWithWrongPublicKeyLength33() throws Exception {
        assertFalse(SchnorrSigner.verify(new byte[64], new byte[32], new byte[33]));
    }

    @Test
    public void testVerifyWithAllZeroInputs() {
        assertFalse(SchnorrSigner.verify(new byte[0], new byte[0], new byte[0]));
    }

    // --- Multiple keys round-trip ---

    @Test
    public void testMultipleKeypairsSignAndVerify() throws Exception {
        for (int i = 0; i < 5; i++) {
            NostrKeyManager km = NostrKeyManager.generate();
            byte[] message = MessageDigest.getInstance("SHA-256").digest(("msg" + i).getBytes());
            byte[] sig = SchnorrSigner.sign(message, km.getPrivateKey());

            assertTrue("Failed on iteration " + i, SchnorrSigner.verify(sig, message, km.getPublicKey()));

            // Verify against another key fails
            NostrKeyManager other = NostrKeyManager.generate();
            assertFalse("Should fail on iteration " + i, SchnorrSigner.verify(sig, message, other.getPublicKey()));
        }
    }
}
