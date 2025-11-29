package org.unicitylabs.nostr.messaging;

import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import static org.junit.Assert.*;

/**
 * Unit tests for NIP-17 Private Direct Messages Protocol.
 */
public class NIP17ProtocolTest {

    @Test
    public void testCreateAndUnwrapGiftWrap() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Hello Bob! This is a private message.";

        // Alice creates a gift-wrapped message for Bob
        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message
        );

        // Verify gift wrap structure
        assertNotNull(giftWrap);
        assertEquals(EventKinds.GIFT_WRAP, giftWrap.getKind());
        assertNotNull(giftWrap.getId());
        assertNotNull(giftWrap.getSig());
        assertNotNull(giftWrap.getContent());

        // Gift wrap pubkey should be ephemeral (not Alice's)
        assertNotEquals(alice.getPublicKeyHex(), giftWrap.getPubkey());

        // Gift wrap should have a "p" tag pointing to recipient
        String pTag = giftWrap.getTagValue("p");
        assertEquals(bob.getPublicKeyHex(), pTag);

        // Bob unwraps the message
        PrivateMessage privateMessage = NIP17Protocol.unwrap(giftWrap, bob);

        // Verify the unwrapped message
        assertNotNull(privateMessage);
        assertEquals(message, privateMessage.getContent());
        assertEquals(alice.getPublicKeyHex(), privateMessage.getSenderPubkey());
        assertEquals(bob.getPublicKeyHex(), privateMessage.getRecipientPubkey());
        assertEquals(EventKinds.CHAT_MESSAGE, privateMessage.getKind());
        assertTrue(privateMessage.isChatMessage());
        assertFalse(privateMessage.isReadReceipt());
        assertNull(privateMessage.getReplyToEventId());
    }

    @Test
    public void testCreateAndUnwrapWithReplyTo() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String originalEventId = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";
        String message = "This is a reply!";

        // Alice creates a reply message
        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message,
                originalEventId
        );

        // Bob unwraps
        PrivateMessage privateMessage = NIP17Protocol.unwrap(giftWrap, bob);

        assertEquals(message, privateMessage.getContent());
        assertEquals(originalEventId, privateMessage.getReplyToEventId());
    }

    @Test
    public void testCreateAndUnwrapReadReceipt() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String messageEventId = "msg123def456abc123def456abc123def456abc123def456abc123def456abcd";

        // Bob sends a read receipt to Alice
        Event giftWrap = NIP17Protocol.createReadReceipt(
                bob,
                alice.getPublicKeyHex(),
                messageEventId
        );

        // Verify gift wrap structure
        assertEquals(EventKinds.GIFT_WRAP, giftWrap.getKind());

        // Alice unwraps the read receipt
        PrivateMessage receipt = NIP17Protocol.unwrap(giftWrap, alice);

        assertNotNull(receipt);
        assertEquals(EventKinds.READ_RECEIPT, receipt.getKind());
        assertTrue(receipt.isReadReceipt());
        assertFalse(receipt.isChatMessage());
        assertEquals("", receipt.getContent()); // Read receipts have empty content
        assertEquals(bob.getPublicKeyHex(), receipt.getSenderPubkey());
        assertEquals(messageEventId, receipt.getReplyToEventId());
    }

    @Test
    public void testUnwrapFailsWithWrongRecipient() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();
        NostrKeyManager eve = NostrKeyManager.generate();

        String message = "Secret message for Bob only";

        // Alice creates a message for Bob
        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message
        );

        // Eve should not be able to unwrap
        try {
            NIP17Protocol.unwrap(giftWrap, eve);
            fail("Expected unwrap to fail with wrong recipient");
        } catch (Exception e) {
            // Expected - decryption should fail
            assertTrue(e.getMessage() != null);
        }
    }

    @Test
    public void testGiftWrapHidesTimestamp() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        long now = System.currentTimeMillis() / 1000;

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                "Test message"
        );

        // Gift wrap timestamp should be randomized (+/- 2 days)
        // It might be in the past or future
        long twoDays = 2 * 24 * 60 * 60;
        long timestamp = giftWrap.getCreatedAt();

        // Timestamp should be within +/- 2 days of now (with small buffer for test execution)
        long buffer = 60; // 1 minute buffer
        assertTrue("Timestamp should be within 2 days of now (got: " + timestamp + ", now: " + now + ")",
                timestamp >= now - twoDays - buffer &&
                timestamp <= now + twoDays + buffer);
    }

    @Test
    public void testGiftWrapUsesEphemeralKey() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create multiple gift wraps
        Event giftWrap1 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "Message 1");
        Event giftWrap2 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "Message 2");

        // Each should have a different ephemeral pubkey
        assertNotEquals(giftWrap1.getPubkey(), giftWrap2.getPubkey());

        // Neither should be Alice's pubkey
        assertNotEquals(alice.getPublicKeyHex(), giftWrap1.getPubkey());
        assertNotEquals(alice.getPublicKeyHex(), giftWrap2.getPubkey());

        // Both should still unwrap correctly
        PrivateMessage msg1 = NIP17Protocol.unwrap(giftWrap1, bob);
        PrivateMessage msg2 = NIP17Protocol.unwrap(giftWrap2, bob);

        assertEquals("Message 1", msg1.getContent());
        assertEquals("Message 2", msg2.getContent());

        // Both should identify Alice as the sender
        assertEquals(alice.getPublicKeyHex(), msg1.getSenderPubkey());
        assertEquals(alice.getPublicKeyHex(), msg2.getSenderPubkey());
    }

    @Test
    public void testInvalidGiftWrapKind() throws Exception {
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create a fake event with wrong kind
        Event fakeEvent = new Event();
        fakeEvent.setKind(EventKinds.ENCRYPTED_DM); // Wrong kind
        fakeEvent.setContent("fake");
        fakeEvent.setPubkey("abc123");

        try {
            NIP17Protocol.unwrap(fakeEvent, bob);
            fail("Expected exception for wrong event kind");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("not a gift wrap"));
        }
    }

    @Test
    public void testRumorSerialization() throws Exception {
        Rumor rumor = new Rumor(
                "abc123pubkey",
                1234567890L,
                EventKinds.CHAT_MESSAGE,
                java.util.Arrays.asList(
                        java.util.Arrays.asList("p", "recipient123"),
                        java.util.Arrays.asList("e", "event123", "", "reply")
                ),
                "Test content"
        );

        // Serialize
        String json = rumor.toJson();
        assertNotNull(json);
        assertTrue(json.contains("abc123pubkey"));
        assertTrue(json.contains("Test content"));

        // Deserialize
        Rumor restored = Rumor.fromJson(json);
        assertEquals(rumor.getPubkey(), restored.getPubkey());
        assertEquals(rumor.getCreatedAt(), restored.getCreatedAt());
        assertEquals(rumor.getKind(), restored.getKind());
        assertEquals(rumor.getContent(), restored.getContent());
    }

    @Test
    public void testRumorGetTagValue() {
        Rumor rumor = new Rumor(
                "pubkey",
                1234567890L,
                EventKinds.CHAT_MESSAGE,
                java.util.Arrays.asList(
                        java.util.Arrays.asList("p", "recipient123"),
                        java.util.Arrays.asList("e", "event456", "", "reply")
                ),
                "Content"
        );

        assertEquals("recipient123", rumor.getTagValue("p"));
        assertEquals("event456", rumor.getTagValue("e"));
        assertNull(rumor.getTagValue("nonexistent"));
    }

    @Test
    public void testPrivateMessageBuilder() {
        PrivateMessage message = PrivateMessage.builder()
                .eventId("event123")
                .senderPubkey("sender456")
                .recipientPubkey("recipient789")
                .content("Hello!")
                .timestamp(1234567890L)
                .kind(EventKinds.CHAT_MESSAGE)
                .replyToEventId("originalEvent")
                .build();

        assertEquals("event123", message.getEventId());
        assertEquals("sender456", message.getSenderPubkey());
        assertEquals("recipient789", message.getRecipientPubkey());
        assertEquals("Hello!", message.getContent());
        assertEquals(1234567890L, message.getTimestamp());
        assertEquals(EventKinds.CHAT_MESSAGE, message.getKind());
        assertEquals("originalEvent", message.getReplyToEventId());
        assertTrue(message.isChatMessage());
        assertFalse(message.isReadReceipt());
    }

    @Test
    public void testMinimalMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // NIP-44 requires at least 1 byte, so test with single character
        String message = "a";

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message
        );

        PrivateMessage privateMessage = NIP17Protocol.unwrap(giftWrap, bob);
        assertEquals(message, privateMessage.getContent());
    }

    @Test
    public void testUnicodeMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        String message = "Hello! \u4e2d\u6587 \ud83d\ude00 \u0420\u0443\u0441\u0441\u043a\u0438\u0439";

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message
        );

        PrivateMessage privateMessage = NIP17Protocol.unwrap(giftWrap, bob);
        assertEquals(message, privateMessage.getContent());
    }

    @Test
    public void testLongMessage() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        // Create a reasonably long message (NIP-44 has 65535 byte limit,
        // but gift wrap adds JSON overhead, so keep message under ~30KB)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            sb.append("This is line ").append(i).append(". ");
        }
        String message = sb.toString();

        Event giftWrap = NIP17Protocol.createGiftWrap(
                alice,
                bob.getPublicKeyHex(),
                message
        );

        PrivateMessage privateMessage = NIP17Protocol.unwrap(giftWrap, bob);
        assertEquals(message, privateMessage.getContent());
    }

    @Test
    public void testEventIdUniqueness() throws Exception {
        NostrKeyManager alice = NostrKeyManager.generate();
        NostrKeyManager bob = NostrKeyManager.generate();

        Event giftWrap1 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "Message");
        Event giftWrap2 = NIP17Protocol.createGiftWrap(alice, bob.getPublicKeyHex(), "Message");

        // Event IDs should be unique
        assertNotEquals(giftWrap1.getId(), giftWrap2.getId());
    }
}
