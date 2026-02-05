package org.unicitylabs.nostr.protocol;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for EventKinds — kind classification and naming.
 */
public class EventKindsTest {

    // --- Constants ---

    @Test
    public void testKindConstants() {
        assertEquals(0, EventKinds.PROFILE);
        assertEquals(1, EventKinds.TEXT_NOTE);
        assertEquals(2, EventKinds.RECOMMEND_RELAY);
        assertEquals(3, EventKinds.CONTACTS);
        assertEquals(4, EventKinds.ENCRYPTED_DM);
        assertEquals(5, EventKinds.DELETION);
        assertEquals(7, EventKinds.REACTION);
        assertEquals(13, EventKinds.SEAL);
        assertEquals(14, EventKinds.CHAT_MESSAGE);
        assertEquals(15, EventKinds.READ_RECEIPT);
        assertEquals(1059, EventKinds.GIFT_WRAP);
        assertEquals(10002, EventKinds.RELAY_LIST);
        assertEquals(22242, EventKinds.AUTH);
        assertEquals(30078, EventKinds.APP_DATA);
        assertEquals(31111, EventKinds.AGENT_PROFILE);
        assertEquals(31112, EventKinds.AGENT_LOCATION);
        assertEquals(31113, EventKinds.TOKEN_TRANSFER);
        assertEquals(31114, EventKinds.FILE_METADATA);
        assertEquals(31115, EventKinds.PAYMENT_REQUEST);
        assertEquals(31116, EventKinds.PAYMENT_REQUEST_RESPONSE);
    }

    // --- isReplaceable (kind == 0 || kind == 3 || 10000..19999) ---

    @Test
    public void testIsReplaceableProfile() {
        assertTrue(EventKinds.isReplaceable(0));
    }

    @Test
    public void testIsReplaceableContacts() {
        assertTrue(EventKinds.isReplaceable(3));
    }

    @Test
    public void testIsReplaceableTextNoteIsFalse() {
        assertFalse(EventKinds.isReplaceable(1));
    }

    @Test
    public void testIsReplaceableRangeStart() {
        assertTrue(EventKinds.isReplaceable(10000));
    }

    @Test
    public void testIsReplaceableRangeInside() {
        assertTrue(EventKinds.isReplaceable(10002));
    }

    @Test
    public void testIsReplaceableRangeEnd() {
        assertTrue(EventKinds.isReplaceable(19999));
    }

    @Test
    public void testIsReplaceableJustBelowRange() {
        assertFalse(EventKinds.isReplaceable(9999));
    }

    @Test
    public void testIsReplaceableEphemeralRangeStart() {
        assertFalse(EventKinds.isReplaceable(20000));
    }

    // --- isEphemeral (20000..29999) ---

    @Test
    public void testIsEphemeralAuth() {
        assertTrue(EventKinds.isEphemeral(22242));
    }

    @Test
    public void testIsEphemeralRangeStart() {
        assertTrue(EventKinds.isEphemeral(20000));
    }

    @Test
    public void testIsEphemeralRangeEnd() {
        assertTrue(EventKinds.isEphemeral(29999));
    }

    @Test
    public void testIsEphemeralJustBelow() {
        assertFalse(EventKinds.isEphemeral(19999));
    }

    @Test
    public void testIsEphemeralJustAbove() {
        assertFalse(EventKinds.isEphemeral(30000));
    }

    @Test
    public void testIsEphemeralTextNote() {
        assertFalse(EventKinds.isEphemeral(1));
    }

    // --- isParameterizedReplaceable (30000..39999) ---

    @Test
    public void testIsParameterizedAppData() {
        assertTrue(EventKinds.isParameterizedReplaceable(30078));
    }

    @Test
    public void testIsParameterizedTokenTransfer() {
        assertTrue(EventKinds.isParameterizedReplaceable(31113));
    }

    @Test
    public void testIsParameterizedRangeStart() {
        assertTrue(EventKinds.isParameterizedReplaceable(30000));
    }

    @Test
    public void testIsParameterizedRangeEnd() {
        assertTrue(EventKinds.isParameterizedReplaceable(39999));
    }

    @Test
    public void testIsParameterizedJustBelow() {
        assertFalse(EventKinds.isParameterizedReplaceable(29999));
    }

    @Test
    public void testIsParameterizedJustAbove() {
        assertFalse(EventKinds.isParameterizedReplaceable(40000));
    }

    // --- getName ---

    @Test
    public void testGetNameProfile() { assertEquals("Profile", EventKinds.getName(0)); }

    @Test
    public void testGetNameTextNote() { assertEquals("Text Note", EventKinds.getName(1)); }

    @Test
    public void testGetNameEncryptedDM() { assertEquals("Encrypted DM", EventKinds.getName(4)); }

    @Test
    public void testGetNameSeal() { assertEquals("Seal", EventKinds.getName(13)); }

    @Test
    public void testGetNameChatMessage() { assertEquals("Chat Message", EventKinds.getName(14)); }

    @Test
    public void testGetNameReadReceipt() { assertEquals("Read Receipt", EventKinds.getName(15)); }

    @Test
    public void testGetNameGiftWrap() { assertEquals("Gift Wrap", EventKinds.getName(1059)); }

    @Test
    public void testGetNameAuth() { assertEquals("Auth", EventKinds.getName(22242)); }

    @Test
    public void testGetNameTokenTransfer() { assertEquals("Token Transfer", EventKinds.getName(31113)); }

    @Test
    public void testGetNamePaymentRequest() { assertEquals("Payment Request", EventKinds.getName(31115)); }

    @Test
    public void testGetNamePaymentRequestResponse() { assertEquals("Payment Request Response", EventKinds.getName(31116)); }

    @Test
    public void testGetNameUnknown() {
        assertEquals("Unknown (99999)", EventKinds.getName(99999));
    }

    @Test
    public void testGetNameNegativeKind() {
        assertEquals("Unknown (-1)", EventKinds.getName(-1));
    }

    // --- Mutual exclusivity of ranges ---

    @Test
    public void testRangesMutuallyExclusive() {
        // A kind cannot be in two ranges at once
        for (int kind : new int[]{0, 3, 10000, 15000, 19999}) {
            assertTrue(EventKinds.isReplaceable(kind));
            assertFalse(EventKinds.isEphemeral(kind));
            assertFalse(EventKinds.isParameterizedReplaceable(kind));
        }
        for (int kind : new int[]{20000, 22242, 29999}) {
            assertFalse(EventKinds.isReplaceable(kind));
            assertTrue(EventKinds.isEphemeral(kind));
            assertFalse(EventKinds.isParameterizedReplaceable(kind));
        }
        for (int kind : new int[]{30000, 30078, 31113, 39999}) {
            assertFalse(EventKinds.isReplaceable(kind));
            assertFalse(EventKinds.isEphemeral(kind));
            assertTrue(EventKinds.isParameterizedReplaceable(kind));
        }
    }
}
