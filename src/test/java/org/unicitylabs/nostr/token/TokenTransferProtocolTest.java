package org.unicitylabs.nostr.token;

import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for TokenTransferProtocol.
 */
public class TokenTransferProtocolTest {

    // --- createTokenTransferEvent: Basic ---

    @Test
    public void testCreateBasicTokenTransferEvent() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();
        String tokenJson = "{\"token\":\"data123\"}";

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), tokenJson);

        assertEquals(EventKinds.TOKEN_TRANSFER, event.getKind());
        assertEquals(sender.getPublicKeyHex(), event.getPubkey());
        assertNotNull(event.getId());
        assertNotNull(event.getSig());
        assertEquals(64, event.getId().length());
        assertEquals(128, event.getSig().length());

        // Content should be encrypted (not plaintext)
        assertFalse(event.getContent().contains("token_transfer:"));
        assertTrue(event.getContent().contains("?iv="));

        // Check required tags
        assertEquals(recipient.getPublicKeyHex(), event.getTagValue("p"));
        assertEquals("token_transfer", event.getTagValue("type"));

        // No amount/symbol tags for basic version
        assertNull(event.getTagValue("amount"));
        assertNull(event.getTagValue("symbol"));
    }

    @Test
    public void testCreateTokenTransferWithAmountAndSymbol() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", BigInteger.valueOf(1000000), "ALPHA");

        assertEquals("1000000", event.getTagValue("amount"));
        assertEquals("ALPHA", event.getTagValue("symbol"));
    }

    @Test
    public void testCreateTokenTransferNullAmountAndSymbol() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", null, null);

        assertNull(event.getTagValue("amount"));
        assertNull(event.getTagValue("symbol"));
    }

    @Test
    public void testCreateTokenTransferWithReplyToEventId() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", null, null, "payment_req_123");

        assertEquals("payment_req_123", event.getTagValue("e"));
    }

    @Test
    public void testCreateTokenTransferWithNullReplyToEventId() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", null, null, null);

        assertNull(event.getTagValue("e"));
    }

    @Test
    public void testCreateTokenTransferWithEmptyReplyToEventId() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", null, null, "");

        assertNull(event.getTagValue("e"));
    }

    // --- parseTokenTransfer ---

    @Test
    public void testParseTokenTransferRoundTrip() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();
        String tokenJson = "{\"token\":\"abc123\",\"value\":42}";

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), tokenJson);

        String parsed = TokenTransferProtocol.parseTokenTransfer(event, recipient);
        assertEquals(tokenJson, parsed);
    }

    @Test
    public void testParseTokenTransferWrongKindThrows() throws Exception {
        Event event = new Event();
        event.setKind(EventKinds.TEXT_NOTE);

        try {
            TokenTransferProtocol.parseTokenTransfer(event, NostrKeyManager.generate());
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("not a token transfer"));
        }
    }

    @Test
    public void testParseTokenTransferWithWrongKeyFails() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();
        NostrKeyManager eve = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{\"token\":\"secret\"}");

        try {
            TokenTransferProtocol.parseTokenTransfer(event, eve);
            fail("Expected exception for wrong key");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    // --- Large Token JSON (triggers NIP-04 compression) ---

    @Test
    public void testLargeTokenJsonRoundTrip() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        // Create a large token JSON that exceeds 1024 bytes
        StringBuilder sb = new StringBuilder("{\"token\":\"");
        for (int i = 0; i < 200; i++) {
            sb.append("data_chunk_").append(i).append("_");
        }
        sb.append("\"}");
        String tokenJson = sb.toString();
        assertTrue(("token_transfer:" + tokenJson).getBytes("UTF-8").length > 1024);

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), tokenJson);

        // Content should be gz-compressed
        assertTrue(event.getContent().startsWith("gz:"));

        String parsed = TokenTransferProtocol.parseTokenTransfer(event, recipient);
        assertEquals(tokenJson, parsed);
    }

    // --- Metadata Extraction ---

    @Test
    public void testGetAmountFromEvent() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", BigInteger.valueOf(5000000), "SOL");

        assertEquals(BigInteger.valueOf(5000000), TokenTransferProtocol.getAmount(event));
    }

    @Test
    public void testGetAmountNoTag() {
        Event event = new Event();
        assertNull(TokenTransferProtocol.getAmount(event));
    }

    @Test
    public void testGetAmountNonNumeric() {
        Event event = new Event();
        event.setTags(java.util.Arrays.asList(
                java.util.Arrays.asList("amount", "not_a_number")
        ));
        assertNull(TokenTransferProtocol.getAmount(event));
    }

    @Test
    public void testGetAmountLargeValue() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        BigInteger largeAmount = new BigInteger("999999999999999999");
        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", largeAmount, "SOL");

        assertEquals(largeAmount, TokenTransferProtocol.getAmount(event));
    }

    @Test
    public void testGetSymbol() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", BigInteger.ONE, "ALPHA");

        assertEquals("ALPHA", TokenTransferProtocol.getSymbol(event));
    }

    @Test
    public void testGetSymbolNoTag() {
        Event event = new Event();
        assertNull(TokenTransferProtocol.getSymbol(event));
    }

    @Test
    public void testGetReplyToEventId() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{}", null, null, "evt_ref_123");

        assertEquals("evt_ref_123", TokenTransferProtocol.getReplyToEventId(event));
    }

    @Test
    public void testGetReplyToEventIdNoTag() {
        Event event = new Event();
        assertNull(TokenTransferProtocol.getReplyToEventId(event));
    }

    // --- Event ID and Signature Validity ---

    @Test
    public void testEventIdsAreUnique() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager recipient = NostrKeyManager.generate();

        Event event1 = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{\"a\":1}");
        Event event2 = TokenTransferProtocol.createTokenTransferEvent(
                sender, recipient.getPublicKeyHex(), "{\"a\":1}");

        // Different events due to different NIP-04 encryption IVs
        assertNotEquals(event1.getId(), event2.getId());
    }
}
