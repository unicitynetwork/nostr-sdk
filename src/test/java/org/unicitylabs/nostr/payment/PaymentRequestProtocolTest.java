package org.unicitylabs.nostr.payment;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.payment.PaymentRequestProtocol.*;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;

import java.math.BigInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for PaymentRequestProtocol.
 */
public class PaymentRequestProtocolTest {

    // --- PaymentRequest Construction ---

    @Test
    public void testPaymentRequestBigIntegerConstructor() {
        PaymentRequest req = new PaymentRequest(
                BigInteger.valueOf(1000000), "coin_id", "Pay me", "alice@unicity");

        assertEquals(BigInteger.valueOf(1000000), req.getAmount());
        assertEquals("coin_id", req.getCoinId());
        assertEquals("Pay me", req.getMessage());
        assertEquals("alice@unicity", req.getRecipientNametag());
        assertNotNull(req.getRequestId());
        assertEquals(8, req.getRequestId().length());
        assertNotNull(req.getDeadline());

        // Deadline should be approximately now + 5 minutes
        long expectedDeadline = System.currentTimeMillis() + PaymentRequestProtocol.DEFAULT_DEADLINE_MS;
        assertTrue(Math.abs(req.getDeadline() - expectedDeadline) < 1000);
    }

    @Test
    public void testPaymentRequestLongConstructor() {
        PaymentRequest req = new PaymentRequest(1000000L, "coin_id", "msg", "alice");
        assertEquals(BigInteger.valueOf(1000000), req.getAmount());
    }

    @Test
    public void testPaymentRequestWithExplicitDeadline() {
        long deadline = System.currentTimeMillis() + 60000;
        PaymentRequest req = new PaymentRequest(
                BigInteger.TEN, "coin", "msg", "alice", deadline);
        assertEquals(Long.valueOf(deadline), req.getDeadline());
    }

    @Test
    public void testPaymentRequestWithNullDeadline() {
        PaymentRequest req = new PaymentRequest(
                BigInteger.TEN, "coin", "msg", "alice", null);
        assertNull(req.getDeadline());
    }

    @Test
    public void testRequestIdIsUnique() {
        PaymentRequest req1 = new PaymentRequest(BigInteger.ONE, "c", "m", "a");
        PaymentRequest req2 = new PaymentRequest(BigInteger.ONE, "c", "m", "a");
        assertNotEquals(req1.getRequestId(), req2.getRequestId());
    }

    @Test
    public void testPaymentRequestLongWithDeadline() {
        long deadline = System.currentTimeMillis() + 10000;
        PaymentRequest req = new PaymentRequest(500L, "coin", "msg", "bob", deadline);
        assertEquals(BigInteger.valueOf(500), req.getAmount());
        assertEquals(Long.valueOf(deadline), req.getDeadline());
    }

    // --- PaymentRequest Expiration ---

    @Test
    public void testFreshRequestIsNotExpired() {
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "a");
        assertFalse(req.isExpired());
    }

    @Test
    public void testPastDeadlineRequestIsExpired() {
        PaymentRequest req = new PaymentRequest(
                BigInteger.ONE, "c", "m", "a", System.currentTimeMillis() - 1000);
        assertTrue(req.isExpired());
    }

    @Test
    public void testNullDeadlineNeverExpires() {
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "a", null);
        assertFalse(req.isExpired());
    }

    @Test
    public void testGetRemainingTimeMsForActiveRequest() {
        long deadline = System.currentTimeMillis() + 30000;
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "a", deadline);

        Long remaining = req.getRemainingTimeMs();
        assertNotNull(remaining);
        assertTrue(remaining > 0);
        assertTrue(remaining <= 30000);
    }

    @Test
    public void testGetRemainingTimeMsForExpiredRequest() {
        PaymentRequest req = new PaymentRequest(
                BigInteger.ONE, "c", "m", "a", System.currentTimeMillis() - 5000);

        Long remaining = req.getRemainingTimeMs();
        assertNotNull(remaining);
        assertEquals(Long.valueOf(0L), remaining);
    }

    @Test
    public void testGetRemainingTimeMsWithNullDeadline() {
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "a", null);
        assertNull(req.getRemainingTimeMs());
    }

    // --- PaymentRequest Setters ---

    @Test
    public void testPaymentRequestSetters() {
        PaymentRequest req = new PaymentRequest();
        req.setAmount(BigInteger.valueOf(999));
        req.setCoinId("test_coin");
        req.setMessage("hello");
        req.setRecipientNametag("bob");
        req.setRequestId("custom_id");
        req.setDeadline(12345L);

        assertEquals(BigInteger.valueOf(999), req.getAmount());
        assertEquals("test_coin", req.getCoinId());
        assertEquals("hello", req.getMessage());
        assertEquals("bob", req.getRecipientNametag());
        assertEquals("custom_id", req.getRequestId());
        assertEquals(Long.valueOf(12345L), req.getDeadline());
    }

    @Test
    public void testPaymentRequestSetAmountLong() {
        PaymentRequest req = new PaymentRequest();
        req.setAmount(42L);
        assertEquals(BigInteger.valueOf(42), req.getAmount());
    }

    // --- PaymentRequestResponse ---

    @Test
    public void testPaymentRequestResponseConstruction() {
        PaymentRequestResponse resp = new PaymentRequestResponse(
                "req123", "evt456", ResponseStatus.DECLINED, "Too expensive");

        assertEquals("req123", resp.getRequestId());
        assertEquals("evt456", resp.getOriginalEventId());
        assertEquals(ResponseStatus.DECLINED, resp.getStatus());
        assertEquals("Too expensive", resp.getReason());
    }

    @Test
    public void testPaymentRequestResponseSetters() {
        PaymentRequestResponse resp = new PaymentRequestResponse();
        resp.setRequestId("r1");
        resp.setOriginalEventId("e1");
        resp.setStatus(ResponseStatus.EXPIRED);
        resp.setReason("Timed out");

        assertEquals("r1", resp.getRequestId());
        assertEquals("e1", resp.getOriginalEventId());
        assertEquals(ResponseStatus.EXPIRED, resp.getStatus());
        assertEquals("Timed out", resp.getReason());
    }

    // --- createPaymentRequestEvent ---

    @Test
    public void testCreatePaymentRequestEventStructure() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        PaymentRequest request = new PaymentRequest(
                BigInteger.valueOf(5000000), "sol_coin_id", "Please pay", "alice@unicity");

        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), request);

        assertEquals(EventKinds.PAYMENT_REQUEST, event.getKind());
        assertEquals(sender.getPublicKeyHex(), event.getPubkey());
        assertNotNull(event.getId());
        assertNotNull(event.getSig());
        assertEquals(64, event.getId().length());

        // Check tags
        assertEquals(target.getPublicKeyHex(), event.getTagValue("p"));
        assertEquals("payment_request", event.getTagValue("type"));
        assertEquals("5000000", event.getTagValue("amount"));
        assertEquals("alice@unicity", event.getTagValue("recipient"));

        // Content should be encrypted
        assertTrue(event.getContent().contains("?iv="));
    }

    @Test
    public void testCreatePaymentRequestWithNullRecipientNametag() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        PaymentRequest request = new PaymentRequest();
        request.setAmount(BigInteger.ONE);
        request.setCoinId("coin");
        request.setRequestId("test_id");
        // recipientNametag is null

        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), request);

        assertNull(event.getTagValue("recipient"));
    }

    // --- parsePaymentRequest ---

    @Test
    public void testParsePaymentRequestRoundTrip() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        PaymentRequest original = new PaymentRequest(
                BigInteger.valueOf(42000), "coin123", "Coffee", "alice");

        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), original);

        PaymentRequest parsed = PaymentRequestProtocol.parsePaymentRequest(event, target);

        assertEquals(original.getAmount(), parsed.getAmount());
        assertEquals(original.getCoinId(), parsed.getCoinId());
        assertEquals(original.getMessage(), parsed.getMessage());
        assertEquals(original.getRecipientNametag(), parsed.getRecipientNametag());
        assertEquals(original.getRequestId(), parsed.getRequestId());
    }

    @Test
    public void testParsePaymentRequestWrongKindThrows() {
        Event event = new Event();
        event.setKind(EventKinds.TEXT_NOTE);

        try {
            PaymentRequestProtocol.parsePaymentRequest(event, NostrKeyManager.generate());
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("not a payment request"));
        }
    }

    @Test
    public void testParsePaymentRequestWithWrongKeyFails() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        NostrKeyManager eve = NostrKeyManager.generate();

        PaymentRequest request = new PaymentRequest(BigInteger.ONE, "c", "m", "a");
        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), request);

        try {
            PaymentRequestProtocol.parsePaymentRequest(event, eve);
            fail("Expected exception for wrong key");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    // --- createPaymentRequestResponseEvent ---

    @Test
    public void testCreateDeclineResponseEvent() throws Exception {
        NostrKeyManager responder = NostrKeyManager.generate();
        NostrKeyManager requester = NostrKeyManager.generate();

        PaymentRequestResponse response = new PaymentRequestResponse(
                "req_id_1", "orig_evt_id", ResponseStatus.DECLINED, "Insufficient funds");

        Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(
                responder, requester.getPublicKeyHex(), response);

        assertEquals(EventKinds.PAYMENT_REQUEST_RESPONSE, event.getKind());
        assertEquals(responder.getPublicKeyHex(), event.getPubkey());
        assertEquals(requester.getPublicKeyHex(), event.getTagValue("p"));
        assertEquals("payment_request_response", event.getTagValue("type"));
        assertEquals("DECLINED", event.getTagValue("status"));
        assertEquals("orig_evt_id", event.getTagValue("e"));
    }

    @Test
    public void testCreateExpiredResponseEvent() throws Exception {
        NostrKeyManager responder = NostrKeyManager.generate();
        NostrKeyManager requester = NostrKeyManager.generate();

        PaymentRequestResponse response = new PaymentRequestResponse(
                "req_id_2", "orig_evt_id", ResponseStatus.EXPIRED, null);

        Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(
                responder, requester.getPublicKeyHex(), response);

        assertEquals("EXPIRED", event.getTagValue("status"));
    }

    @Test
    public void testCreateResponseWithNullOriginalEventId() throws Exception {
        NostrKeyManager responder = NostrKeyManager.generate();
        NostrKeyManager requester = NostrKeyManager.generate();

        PaymentRequestResponse response = new PaymentRequestResponse(
                "req_id_3", null, ResponseStatus.DECLINED, "reason");

        Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(
                responder, requester.getPublicKeyHex(), response);

        assertNull(event.getTagValue("e"));
    }

    // --- parsePaymentRequestResponse ---

    @Test
    public void testParseDeclineResponseRoundTrip() throws Exception {
        NostrKeyManager responder = NostrKeyManager.generate();
        NostrKeyManager requester = NostrKeyManager.generate();

        PaymentRequestResponse original = new PaymentRequestResponse(
                "req_id_1", "orig_evt", ResponseStatus.DECLINED, "Too expensive");

        Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(
                responder, requester.getPublicKeyHex(), original);

        PaymentRequestResponse parsed = PaymentRequestProtocol.parsePaymentRequestResponse(
                event, requester);

        assertEquals(ResponseStatus.DECLINED, parsed.getStatus());
        assertEquals("req_id_1", parsed.getRequestId());
        assertEquals("orig_evt", parsed.getOriginalEventId());
        assertEquals("Too expensive", parsed.getReason());
    }

    @Test
    public void testParseExpiredResponseRoundTrip() throws Exception {
        NostrKeyManager responder = NostrKeyManager.generate();
        NostrKeyManager requester = NostrKeyManager.generate();

        PaymentRequestResponse original = new PaymentRequestResponse(
                "req_id_2", "evt2", ResponseStatus.EXPIRED, null);

        Event event = PaymentRequestProtocol.createPaymentRequestResponseEvent(
                responder, requester.getPublicKeyHex(), original);

        PaymentRequestResponse parsed = PaymentRequestProtocol.parsePaymentRequestResponse(
                event, requester);

        assertEquals(ResponseStatus.EXPIRED, parsed.getStatus());
        assertNull(parsed.getReason());
    }

    @Test
    public void testParseResponseWrongKindThrows() {
        Event event = new Event();
        event.setKind(EventKinds.TEXT_NOTE);

        try {
            PaymentRequestProtocol.parsePaymentRequestResponse(event, NostrKeyManager.generate());
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("not a payment request response"));
        }
    }

    // --- Metadata Extraction ---

    @Test
    public void testGetAmountFromEvent() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        PaymentRequest req = new PaymentRequest(
                BigInteger.valueOf(5000000000L), "coin", "msg", "alice");

        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), req);

        assertEquals(BigInteger.valueOf(5000000000L), PaymentRequestProtocol.getAmount(event));
    }

    @Test
    public void testGetAmountNoTag() {
        Event event = new Event();
        assertNull(PaymentRequestProtocol.getAmount(event));
    }

    @Test
    public void testGetAmountNonNumeric() {
        Event event = new Event();
        event.setTags(java.util.Arrays.asList(
                java.util.Arrays.asList("amount", "not_number")
        ));
        assertNull(PaymentRequestProtocol.getAmount(event));
    }

    @Test
    public void testGetRecipientNametag() throws Exception {
        NostrKeyManager sender = NostrKeyManager.generate();
        NostrKeyManager target = NostrKeyManager.generate();
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "alice@unicity");

        Event event = PaymentRequestProtocol.createPaymentRequestEvent(
                sender, target.getPublicKeyHex(), req);

        assertEquals("alice@unicity", PaymentRequestProtocol.getRecipientNametag(event));
    }

    @Test
    public void testGetResponseStatus() {
        Event event = new Event();
        event.setTags(java.util.Arrays.asList(
                java.util.Arrays.asList("status", "DECLINED")
        ));
        assertEquals("DECLINED", PaymentRequestProtocol.getResponseStatus(event));
    }

    @Test
    public void testGetOriginalEventId() {
        Event event = new Event();
        event.setTags(java.util.Arrays.asList(
                java.util.Arrays.asList("e", "orig_evt_123")
        ));
        assertEquals("orig_evt_123", PaymentRequestProtocol.getOriginalEventId(event));
    }

    // --- JSON Serialization of PaymentRequest ---

    @Test
    public void testPaymentRequestJsonRoundTrip() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        PaymentRequest original = new PaymentRequest(
                BigInteger.valueOf(42), "coin123", "test msg", "bob");

        String json = mapper.writeValueAsString(original);
        PaymentRequest parsed = mapper.readValue(json, PaymentRequest.class);

        assertEquals(original.getAmount(), parsed.getAmount());
        assertEquals(original.getCoinId(), parsed.getCoinId());
        assertEquals(original.getMessage(), parsed.getMessage());
        assertEquals(original.getRecipientNametag(), parsed.getRecipientNametag());
        assertEquals(original.getRequestId(), parsed.getRequestId());
        assertEquals(original.getDeadline(), parsed.getDeadline());
    }

    @Test
    public void testPaymentRequestResponseJsonRoundTrip() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        PaymentRequestResponse original = new PaymentRequestResponse(
                "req1", "evt1", ResponseStatus.DECLINED, "reason");

        String json = mapper.writeValueAsString(original);
        PaymentRequestResponse parsed = mapper.readValue(json, PaymentRequestResponse.class);

        assertEquals(original.getRequestId(), parsed.getRequestId());
        assertEquals(original.getOriginalEventId(), parsed.getOriginalEventId());
        assertEquals(original.getStatus(), parsed.getStatus());
        assertEquals(original.getReason(), parsed.getReason());
    }

    // --- toString ---

    @Test
    public void testPaymentRequestToString() {
        PaymentRequest req = new PaymentRequest(BigInteger.ONE, "c", "m", "a");
        String str = req.toString();
        assertNotNull(str);
        assertTrue(str.contains("PaymentRequest"));
        assertTrue(str.contains("amount=1"));
    }

    @Test
    public void testPaymentRequestResponseToString() {
        PaymentRequestResponse resp = new PaymentRequestResponse(
                "r1", "e1", ResponseStatus.DECLINED, "nope");
        String str = resp.toString();
        assertNotNull(str);
        assertTrue(str.contains("DECLINED"));
    }
}
