package org.unicitylabs.nostr.crypto;

import org.junit.Test;
import org.unicitylabs.nostr.messaging.NIP17Protocol;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Security-critical path tests.
 * Verifies key clearing, copy semantics, NIP-17 anonymity, and timestamp privacy.
 *
 * Techniques: [RB] Risk-Based Testing
 */
public class SecurityCriticalTest {

    // ==========================================================
    // Key Clearing Tests
    // ==========================================================

    @Test
    public void testClearPreventsPrivateKeyAccess() {
        NostrKeyManager km = NostrKeyManager.generate();
        km.clear();

        // After clear, private key should be all zeros
        byte[] clearedKey = km.getPrivateKey();
        assertArrayEquals("Private key should be zeroed", new byte[32], clearedKey);
    }

    @Test
    public void testClearAllowsPublicKeyAccess() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] originalPubkey = km.getPublicKey();

        km.clear();

        // Public key should still be accessible
        assertArrayEquals(originalPubkey, km.getPublicKey());
    }

    @Test
    public void testSignAfterClearFailsWithZeroKey() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        km.clear();

        byte[] hash = MessageDigest.getInstance("SHA-256").digest("test".getBytes());

        // After clear(), private key is zeroed which is invalid for secp256k1
        // Zero key causes point at infinity in EC math, leading to exception
        try {
            km.sign(hash);
            fail("Expected exception when signing with zeroed key");
        } catch (Exception e) {
            // Expected - zero is not a valid private key on secp256k1
            assertNotNull(e);
        }
    }

    @Test
    public void testNip04EncryptAfterClearFailsWithZeroKey() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NostrKeyManager other = NostrKeyManager.generate();

        km.clear();

        // After clear(), private key is zeroed which is invalid for ECDH
        try {
            km.encryptHex("test", other.getPublicKeyHex());
            fail("Expected exception when encrypting with zeroed key");
        } catch (Exception e) {
            // Expected - zero key fails ECDH calculation
            assertNotNull(e);
        }
    }

    @Test
    public void testNip44EncryptAfterClearFailsWithZeroKey() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NostrKeyManager other = NostrKeyManager.generate();

        km.clear();

        // After clear(), private key is zeroed which is invalid for NIP-44 ECDH
        try {
            km.encryptNip44Hex("test", other.getPublicKeyHex());
            fail("Expected exception when NIP-44 encrypting with zeroed key");
        } catch (Exception e) {
            // Expected - zero key fails ECDH calculation
            assertNotNull(e);
        }
    }

    @Test
    public void testDeriveConversationKeyAfterClearFailsWithZeroKey() throws Exception {
        NostrKeyManager km = NostrKeyManager.generate();
        NostrKeyManager other = NostrKeyManager.generate();

        km.clear();

        // After clear(), private key is zeroed which is invalid for ECDH
        try {
            km.deriveConversationKey(other.getPublicKey());
            fail("Expected exception when deriving conversation key with zeroed key");
        } catch (Exception e) {
            // Expected - zero key fails ECDH calculation
            assertNotNull(e);
        }
    }

    // ==========================================================
    // Copy Semantics Tests
    // ==========================================================

    @Test
    public void testGetPrivateKeyReturnsCopy() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] key1 = km.getPrivateKey();
        String originalHex = bytesToHex(key1);

        // Modify the returned array
        key1[0] = (byte) 0xFF;
        key1[1] = (byte) 0xFF;

        // Get key again - should be unmodified
        byte[] key2 = km.getPrivateKey();
        assertEquals(originalHex, bytesToHex(key2));
    }

    @Test
    public void testGetPublicKeyReturnsCopy() {
        NostrKeyManager km = NostrKeyManager.generate();
        byte[] key1 = km.getPublicKey();
        String originalHex = bytesToHex(key1);

        // Modify the returned array
        key1[0] = (byte) 0xFF;

        // Get key again - should be unmodified
        byte[] key2 = km.getPublicKey();
        assertEquals(originalHex, bytesToHex(key2));
    }

    @Test
    public void testConstructorCopiesInputPrivateKey() {
        byte[] inputKey = new byte[32];
        Arrays.fill(inputKey, (byte) 0x42);

        NostrKeyManager km = NostrKeyManager.fromPrivateKey(inputKey);

        // Modify the original input
        inputKey[0] = (byte) 0xFF;

        // Key manager should still have the original value
        assertEquals((byte) 0x42, km.getPrivateKey()[0]);
    }

    // ==========================================================
    // NIP-17 Sender Anonymity Tests
    // ==========================================================

    @Test
    public void testGiftWrapPubkeyIsNotSenderPubkey() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                "secret message",
                null,
                null
        );

        // The gift wrap is signed by an ephemeral key, NOT Alice
        assertNotEquals("Gift wrap pubkey should not be sender's pubkey",
                alice.getPublicKeyHex(), giftWrap.getPubkey());
    }

    @Test
    public void testDifferentGiftWrapsUseDifferentEphemeralKeys() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event gw1 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "msg1", null, null);
        Event gw2 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "msg2", null, null);

        // Different ephemeral keys each time
        assertNotEquals("Each gift wrap should use different ephemeral key",
                gw1.getPubkey(), gw2.getPubkey());
    }

    @Test
    public void testGiftWrapRecipientTagPointsToActualRecipient() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                "message",
                null,
                null
        );

        assertEquals(bob.getPublicKeyHex(), giftWrap.getTagValue("p"));
    }

    @Test
    public void testGiftWrapKindIs1059() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                "message",
                null,
                null
        );

        assertEquals(EventKinds.GIFT_WRAP, giftWrap.getKind());
    }

    // ==========================================================
    // NIP-17 Timestamp Privacy Tests
    // ==========================================================

    @Test
    public void testTimestampsAreRandomizedWithinTwoDays() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        long now = System.currentTimeMillis() / 1000;
        long twoDays = 2 * 24 * 60 * 60;

        Set<Long> timestamps = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            Event gw = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "msg" + i, null, null);
            timestamps.add(gw.getCreatedAt());

            // All should be within +/- 2 days of now
            assertTrue("Timestamp should be >= now - 2 days",
                    gw.getCreatedAt() >= now - twoDays - 10);
            assertTrue("Timestamp should be <= now + 2 days",
                    gw.getCreatedAt() <= now + twoDays + 10);
        }

        // Not all timestamps should be the same (randomized)
        assertTrue("Timestamps should be randomized (expect > 1 unique value)",
                timestamps.size() > 1);
    }

    // ==========================================================
    // NIP-44 Conversation Key Symmetry Tests
    // ==========================================================

    @Test
    public void testConversationKeyIsSymmetric() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] keyAB = alice.deriveConversationKey(bob.getPublicKey());
        byte[] keyBA = bob.deriveConversationKey(alice.getPublicKey());

        assertArrayEquals("Conversation key should be symmetric (A->B equals B->A)",
                keyAB, keyBA);
    }

    @Test
    public void testSharedSecretIsSymmetric() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        byte[] secretAB = NIP04Encryption.deriveSharedSecret(alice.getPrivateKey(), bob.getPublicKey());
        byte[] secretBA = NIP04Encryption.deriveSharedSecret(bob.getPrivateKey(), alice.getPublicKey());

        assertArrayEquals("Shared secret should be symmetric", secretAB, secretBA);
    }

    // ==========================================================
    // AUTH Event Structure Tests
    // ==========================================================

    @Test
    public void testAuthEventStructure() {
        NostrKeyManager km = NostrKeyManager.generate();

        // Create AUTH event manually (simulating what client does)
        Event authEvent = new Event();
        authEvent.setKind(EventKinds.AUTH);
        authEvent.setPubkey(km.getPublicKeyHex());
        authEvent.setCreatedAt(System.currentTimeMillis() / 1000);
        authEvent.setContent("");
        authEvent.setTags(Arrays.asList(
                Arrays.asList("relay", "wss://relay.example.com"),
                Arrays.asList("challenge", "test-challenge-123")
        ));

        assertEquals(22242, authEvent.getKind());
        assertEquals("wss://relay.example.com", authEvent.getTagValue("relay"));
        assertEquals("test-challenge-123", authEvent.getTagValue("challenge"));
        assertEquals("", authEvent.getContent());
        assertEquals(km.getPublicKeyHex(), authEvent.getPubkey());
    }

    // ==========================================================
    // Memory Zeroing Tests
    // ==========================================================

    @Test
    public void testOriginalInputUnchangedAfterClear() throws Exception {
        byte[] privateKeyBytes = new byte[32];
        Arrays.fill(privateKeyBytes, (byte) 0x42);

        NostrKeyManager km = NostrKeyManager.fromPrivateKey(privateKeyBytes);

        // Verify key works before clear
        byte[] sig = km.sign(new byte[32]);
        assertEquals(64, sig.length);

        km.clear();

        // Original input should be unchanged (was copied)
        assertEquals((byte) 0x42, privateKeyBytes[0]);
    }

    // Helper
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
