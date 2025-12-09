package org.unicitylabs.nostr.payment;

import org.junit.Test;
import org.unicitylabs.nostr.client.NostrClient;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.nametag.NametagBinding;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;
import org.unicitylabs.nostr.token.TokenTransferProtocol;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * E2E tests for payment request functionality.
 *
 * Usage:
 *   # Send a single payment request
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendPaymentRequest" -DtargetNametag=mp-9
 *
 *   # Send multiple payment requests
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendMultiplePaymentRequests" -DtargetNametag=mp-9
 *
 *   # Full flow with token transfer verification (requires manual wallet interaction)
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testFullPaymentRequestFlow" -DtargetNametag=mp-9
 *
 *   # Test decline flow - send request, manually reject in wallet, verify decline response
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testPaymentRequestDeclineFlow" -DtargetNametag=mp-9 -Damount=1000000000 -DcoinId=dee5f8ce778562eec90e9c38a91296a023210ccc76ff4c29d527ac3eb64ade93
 *
 *   # Test expiration flow - send request with short deadline, verify wallet cannot accept
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testPaymentRequestExpirationFlow" -DtargetNametag=mp-9 -Damount=500000000
 */
public class PaymentRequestE2ETest {

    // Configuration - can be overridden via system properties
    private static final String NOSTR_RELAY = System.getProperty("nostrRelay",
            "wss://nostr-relay.testnet.unicity.network");

    // Solana coin ID from the registry
    private static final String SOLANA_COIN_ID = "dee5f8ce778562eec90e9c38a91296a023210ccc76ff4c29d527ac3eb64ade93";

    // Default decimals for display (8 decimals)
    private static final int DEFAULT_DECIMALS = 8;

    /**
     * Send a single payment request to a wallet.
     */
    @Test
    public void testSendPaymentRequest() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");
        String recipientNametag = System.getProperty("recipientNametag", "test-requester-" + System.currentTimeMillis() % 10000);
        long amount = Long.parseLong(System.getProperty("amount", "1000000"));
        int decimals = Integer.parseInt(System.getProperty("decimals", String.valueOf(DEFAULT_DECIMALS)));
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        String message = System.getProperty("message", "Test payment request from E2E test");

        printHeader("Payment Request E2E Test");
        System.out.println("Parameters:");
        System.out.println("   Target nametag: " + targetNametag);
        System.out.println("   Recipient nametag: " + recipientNametag);
        System.out.println("   Amount: " + formatAmount(amount, decimals));
        System.out.println("   Coin ID: " + coinId.substring(0, 16) + "...");
        System.out.println("   Message: " + message);
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        try {
            // Connect
            System.out.println("Connecting to Nostr relay...");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            // Publish nametag binding for recipient
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, recipientNametag, "test-addr");
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("Recipient nametag published: " + recipientNametag);
            Thread.sleep(1000);

            // Resolve target
            String targetPubkey = resolveNametag(client, targetNametag);

            // Send payment request (no symbol - coinId precisely defines the token)
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, message, recipientNametag
            );
            System.out.println("Sending payment request...");
            String eventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("Payment request sent! Event ID: " + eventId.substring(0, 16) + "...");

            Thread.sleep(2000);

            printSuccess("Payment request sent successfully!");
            System.out.println("Summary:");
            System.out.println("   To: " + targetNametag);
            System.out.println("   Amount: " + formatAmount(amount, decimals));
            System.out.println("   From: " + recipientNametag);
            System.out.println();
            System.out.println("Check the wallet Settings > Payment Requests!");

        } finally {
            disconnect(client);
        }
    }

    /**
     * Send multiple payment requests for testing wallet UI.
     */
    @Test
    public void testSendMultiplePaymentRequests() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");

        printHeader("Multiple Payment Requests Test");

        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        try {
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            String targetPubkey = resolveNametag(client, targetNametag);

            // requests: amount, message
            String[][] requests = {
                    {"500000", "Coffee - small"},
                    {"1500000", "Lunch payment"},
                    {"10000000", "Monthly subscription"},
            };

            for (int i = 0; i < requests.length; i++) {
                String[] req = requests[i];
                long amount = Long.parseLong(req[0]);
                String message = req[1];
                String recipientNametag = "merchant-" + (i + 1);

                // Publish nametag for this merchant
                Event bindingEvent = NametagBinding.createBindingEvent(keyManager, recipientNametag, "addr-" + i);
                client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);

                PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                        amount, SOLANA_COIN_ID, message, recipientNametag
                );

                System.out.println("Sending request " + (i + 1) + ": " + formatAmount(amount, DEFAULT_DECIMALS) + " - " + message);
                client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
                System.out.println("   Sent (ID: " + request.getRequestId() + ")");

                Thread.sleep(500);
            }

            Thread.sleep(2000);
            printSuccess("All " + requests.length + " payment requests sent!");

        } finally {
            disconnect(client);
        }
    }

    /**
     * Full payment request flow with token transfer verification.
     * Requires manual wallet interaction to accept the payment.
     */
    @Test
    public void testFullPaymentRequestFlow() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");
        long amount = Long.parseLong(System.getProperty("amount", "100000"));
        int decimals = Integer.parseInt(System.getProperty("decimals", String.valueOf(DEFAULT_DECIMALS)));
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        int timeoutSeconds = Integer.parseInt(System.getProperty("timeout", "120"));

        String testNametag = "test-recv-" + System.currentTimeMillis() % 100000;
        String testAddress = "test-address-" + System.currentTimeMillis();

        printHeader("FULL PAYMENT REQUEST E2E TEST");
        System.out.println("Configuration:");
        System.out.println("   Target wallet nametag: " + targetNametag);
        System.out.println("   Test receiver nametag: " + testNametag);
        System.out.println("   Amount: " + formatAmount(amount, decimals));
        System.out.println("   Coin ID: " + coinId.substring(0, 16) + "...");
        System.out.println("   Timeout: " + timeoutSeconds + " seconds");
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        System.out.println("Generated test keypair: " + keyManager.getPublicKeyHex().substring(0, 32) + "...");

        NostrClient client = new NostrClient(keyManager);
        AtomicBoolean tokenReceived = new AtomicBoolean(false);
        AtomicReference<String> receivedTokenJson = new AtomicReference<>(null);
        AtomicReference<String> receivedReplyToEventId = new AtomicReference<>(null);
        AtomicReference<Event> receivedEvent = new AtomicReference<>(null);

        try {
            // Step 1: Connect
            printStep(1, "Connect to Nostr relay");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            // Step 2: Publish nametag
            printStep(2, "Publish test nametag binding");
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, testNametag, testAddress);
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("Nametag published: " + testNametag);
            Thread.sleep(1500);

            // Verify nametag
            String resolvedPubkey = client.queryPubkeyByNametag(testNametag).get(10, TimeUnit.SECONDS);
            if (resolvedPubkey != null && resolvedPubkey.equals(keyManager.getPublicKeyHex())) {
                System.out.println("Nametag verified");
            }

            // Step 3: Subscribe to token transfers
            printStep(3, "Subscribe to incoming token transfers");
            // Subscribe to both TOKEN_TRANSFER (31113) and ENCRYPTED_DM (4) to catch all transfer methods
            Filter dmFilter = Filter.builder()
                    .kinds(Arrays.asList(EventKinds.TOKEN_TRANSFER, EventKinds.ENCRYPTED_DM))
                    .pTags(keyManager.getPublicKeyHex())
                    .since(System.currentTimeMillis() / 1000 - 60)
                    .build();

            final String TOKEN_PREFIX = "token_transfer:";
            client.subscribe("token-transfer", dmFilter, event -> {
                System.out.println("Received event kind " + event.getKind() + " from: " + event.getPubkey().substring(0, 16) + "...");
                try {
                    String content = event.getContent();
                    String decrypted;

                    // Try to decrypt if it looks encrypted (contains "?iv=")
                    if (content.contains("?iv=")) {
                        decrypted = keyManager.decryptHex(content, event.getPubkey());
                        System.out.println("   Decrypted successfully");
                    } else {
                        // Content might already be plain or differently formatted
                        decrypted = content;
                        System.out.println("   Content not encrypted, using raw");
                    }

                    System.out.println("   Content preview: " + decrypted.substring(0, Math.min(100, decrypted.length())) + "...");

                    if (decrypted.startsWith(TOKEN_PREFIX)) {
                        System.out.println("TOKEN TRANSFER RECEIVED!");
                        receivedTokenJson.set(decrypted);
                        receivedEvent.set(event);

                        // Extract reply-to event ID for payment request correlation
                        String replyToId = TokenTransferProtocol.getReplyToEventId(event);
                        if (replyToId != null) {
                            receivedReplyToEventId.set(replyToId);
                            System.out.println("   Reply-to event ID (e tag): " + replyToId.substring(0, 16) + "...");
                        } else {
                            System.out.println("   No reply-to event ID (e tag) found");
                        }

                        tokenReceived.set(true);
                    }
                } catch (Exception e) {
                    System.out.println("   (Error processing: " + e.getMessage() + ")");
                    e.printStackTrace();
                }
            });
            System.out.println("Subscribed to incoming messages");

            // Step 4: Resolve target
            printStep(4, "Resolve target wallet nametag");
            String targetPubkey = resolveNametag(client, targetNametag);

            // Step 5: Send payment request
            printStep(5, "Send payment request");
            String message = "E2E Test - please accept!";
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, message, testNametag
            );
            String paymentRequestEventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("Payment request sent!");
            System.out.println("   Event ID: " + paymentRequestEventId.substring(0, 16) + "...");
            System.out.println("   Amount: " + formatAmount(amount, decimals));
            System.out.println("   Recipient: " + testNametag);

            // Step 6: Wait for user action
            printStep(6, "Waiting for wallet to accept payment request");
            System.out.println();
            System.out.println("+--------------------------------------------------------+");
            System.out.println("|  ACTION REQUIRED                                       |");
            System.out.println("|                                                        |");
            System.out.println("|  1. Open the wallet app                                |");
            System.out.println("|  2. Tap Settings (gear) > Payment Requests             |");
            System.out.println("|  3. Tap 'Pay' on the request from " + testNametag);
            System.out.println("|                                                        |");
            System.out.println("|  Waiting " + timeoutSeconds + " seconds...                             |");
            System.out.println("+--------------------------------------------------------+");
            System.out.println();

            long startTime = System.currentTimeMillis();
            long timeoutMs = timeoutSeconds * 1000L;
            while (!tokenReceived.get() && (System.currentTimeMillis() - startTime) < timeoutMs) {
                Thread.sleep(2000);
                int remaining = (int) ((timeoutMs - (System.currentTimeMillis() - startTime)) / 1000);
                System.out.print("\rWaiting... " + remaining + "s remaining    ");
            }
            System.out.println();

            // Step 7: Verify
            printStep(7, "Verify result");
            if (tokenReceived.get()) {
                printSuccess("Token transfer received!");
                System.out.println("Transfer Details:");
                System.out.println("   From: " + targetNametag);
                System.out.println("   To: " + testNametag);
                System.out.println("   Amount: " + formatAmount(amount, decimals));

                String tokenData = receivedTokenJson.get();
                if (tokenData != null) {
                    String jsonPart = tokenData.substring(TOKEN_PREFIX.length());
                    System.out.println("Payload: " + jsonPart.substring(0, Math.min(100, jsonPart.length())) + "...");
                }

                // Step 8: Verify payment request correlation (e tag)
                printStep(8, "Verify payment request correlation (e tag)");
                String replyToId = receivedReplyToEventId.get();
                if (replyToId != null) {
                    System.out.println("Token transfer contains reply-to event ID:");
                    System.out.println("   Expected (payment request): " + paymentRequestEventId);
                    System.out.println("   Actual (e tag in transfer): " + replyToId);

                    if (paymentRequestEventId.equals(replyToId)) {
                        printSuccess("CORRELATION VERIFIED!");
                        System.out.println("The token transfer correctly references the payment request.");
                        System.out.println("Server can match this transfer to the original request using:");
                        System.out.println("   TokenTransferProtocol.getReplyToEventId(event)");
                    } else {
                        System.out.println("WARNING: Event IDs do not match!");
                        System.out.println("   This may indicate an issue with the wallet implementation.");
                    }
                } else {
                    System.out.println("WARNING: No reply-to event ID (e tag) found in token transfer.");
                    System.out.println("   The wallet should include the payment request event ID");
                    System.out.println("   as an 'e' tag when responding to payment requests.");
                    System.out.println("   Expected: [\"e\", \"" + paymentRequestEventId.substring(0, 16) + "...\", \"\", \"reply\"]");
                }
            } else {
                System.out.println("TIMEOUT - No token transfer received");
                System.out.println("   Check wallet for errors or try again.");
            }

        } finally {
            disconnect(client);
        }
    }

    /**
     * Test payment request decline flow.
     *
     * This test:
     * 1. Sends a payment request to the wallet
     * 2. Waits for manual rejection in the wallet
     * 3. Verifies that a PAYMENT_REQUEST_RESPONSE event is received with DECLINED status
     *
     * Usage:
     *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testPaymentRequestDeclineFlow" \
     *       -DtargetNametag=mp-9 \
     *       -Damount=1000000000 \
     *       -DcoinId=dee5f8ce778562eec90e9c38a91296a023210ccc76ff4c29d527ac3eb64ade93
     */
    @Test
    public void testPaymentRequestDeclineFlow() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");
        BigInteger amount = new BigInteger(System.getProperty("amount", "1000000000")); // Default 10 SOL in lamports
        int decimals = Integer.parseInt(System.getProperty("decimals", String.valueOf(DEFAULT_DECIMALS)));
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        int timeoutSeconds = Integer.parseInt(System.getProperty("timeout", "120"));

        String testNametag = "decline-test-" + System.currentTimeMillis() % 100000;
        String testAddress = "decline-test-address-" + System.currentTimeMillis();

        printHeader("PAYMENT REQUEST DECLINE E2E TEST");
        System.out.println("Configuration:");
        System.out.println("   Target wallet nametag: " + targetNametag);
        System.out.println("   Test sender nametag: " + testNametag);
        System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
        System.out.println("   Coin ID: " + coinId.substring(0, 16) + "...");
        System.out.println("   Timeout: " + timeoutSeconds + " seconds");
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        System.out.println("Generated test keypair: " + keyManager.getPublicKeyHex().substring(0, 32) + "...");

        NostrClient client = new NostrClient(keyManager);
        AtomicBoolean declineReceived = new AtomicBoolean(false);
        AtomicReference<PaymentRequestProtocol.PaymentRequestResponse> receivedResponse = new AtomicReference<>(null);
        AtomicReference<String> paymentRequestEventId = new AtomicReference<>(null);

        try {
            // Step 1: Connect
            printStep(1, "Connect to Nostr relay");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            // Step 2: Publish nametag
            printStep(2, "Publish test nametag binding");
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, testNametag, testAddress);
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("Nametag published: " + testNametag);
            Thread.sleep(1500);

            // Step 3: Subscribe to payment request responses (DECLINE events)
            printStep(3, "Subscribe to payment request responses");
            Filter responseFilter = Filter.builder()
                    .kinds(Arrays.asList(EventKinds.PAYMENT_REQUEST_RESPONSE))
                    .pTags(keyManager.getPublicKeyHex())
                    .since(System.currentTimeMillis() / 1000 - 60)
                    .build();

            client.subscribe("decline-responses", responseFilter, event -> {
                System.out.println("Received event kind " + event.getKind() + " from: " + event.getPubkey().substring(0, 16) + "...");
                try {
                    PaymentRequestProtocol.PaymentRequestResponse response =
                            PaymentRequestProtocol.parsePaymentRequestResponse(event, keyManager);
                    System.out.println("PAYMENT REQUEST RESPONSE RECEIVED!");
                    System.out.println("   Status: " + response.getStatus());
                    System.out.println("   Request ID: " + response.getRequestId());
                    System.out.println("   Original Event ID: " + (response.getOriginalEventId() != null ?
                            response.getOriginalEventId().substring(0, 16) + "..." : "null"));
                    System.out.println("   Reason: " + response.getReason());

                    receivedResponse.set(response);
                    if (response.getStatus() == PaymentRequestProtocol.ResponseStatus.DECLINED) {
                        declineReceived.set(true);
                    }
                } catch (Exception e) {
                    System.out.println("   (Error processing: " + e.getMessage() + ")");
                }
            });
            System.out.println("Subscribed to payment request responses");

            // Step 4: Resolve target
            printStep(4, "Resolve target wallet nametag");
            String targetPubkey = resolveNametag(client, targetNametag);

            // Step 5: Send payment request
            printStep(5, "Send payment request");
            String message = "DECLINE TEST - Please REJECT this request!";
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, message, testNametag
            );
            String eventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            paymentRequestEventId.set(eventId);
            System.out.println("Payment request sent!");
            System.out.println("   Event ID: " + eventId.substring(0, 16) + "...");
            System.out.println("   Request ID: " + request.getRequestId());
            System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
            System.out.println("   Recipient: " + testNametag);

            // Step 6: Wait for user to decline
            printStep(6, "Waiting for wallet to DECLINE payment request");
            System.out.println();
            System.out.println("+--------------------------------------------------------+");
            System.out.println("|  ACTION REQUIRED                                       |");
            System.out.println("|                                                        |");
            System.out.println("|  1. Open the wallet app                                |");
            System.out.println("|  2. Tap Settings (gear) > Payment Requests             |");
            System.out.println("|  3. Tap 'REJECT' on the request from " + testNametag);
            System.out.println("|                                                        |");
            System.out.println("|  Waiting " + timeoutSeconds + " seconds...                             |");
            System.out.println("+--------------------------------------------------------+");
            System.out.println();

            long startTime = System.currentTimeMillis();
            long timeoutMs = timeoutSeconds * 1000L;
            while (!declineReceived.get() && (System.currentTimeMillis() - startTime) < timeoutMs) {
                Thread.sleep(2000);
                int remaining = (int) ((timeoutMs - (System.currentTimeMillis() - startTime)) / 1000);
                System.out.print("\rWaiting for decline... " + remaining + "s remaining    ");
            }
            System.out.println();

            // Step 7: Verify
            printStep(7, "Verify decline response");
            if (declineReceived.get()) {
                PaymentRequestProtocol.PaymentRequestResponse response = receivedResponse.get();
                printSuccess("DECLINE RESPONSE RECEIVED!");
                System.out.println("Response Details:");
                System.out.println("   Status: " + response.getStatus());
                System.out.println("   Request ID: " + response.getRequestId());
                System.out.println("   Original Event ID: " + response.getOriginalEventId());
                System.out.println("   Reason: " + (response.getReason() != null ? response.getReason() : "(none)"));

                // Verify correlation
                if (eventId.equals(response.getOriginalEventId())) {
                    printSuccess("EVENT ID CORRELATION VERIFIED!");
                    System.out.println("The decline response correctly references the original payment request.");
                } else if (request.getRequestId().equals(response.getRequestId())) {
                    System.out.println("Request ID matches (alternative correlation method)");
                } else {
                    System.out.println("WARNING: Event/Request ID mismatch");
                    System.out.println("   Expected Event ID: " + eventId);
                    System.out.println("   Received Event ID: " + response.getOriginalEventId());
                }
            } else {
                System.out.println("TIMEOUT - No decline response received");
                System.out.println("   Did you tap 'Reject' in the wallet?");
                System.out.println("   Make sure the wallet is sending PAYMENT_REQUEST_RESPONSE events.");
            }

        } finally {
            disconnect(client);
        }
    }

    /**
     * Test payment request expiration flow.
     *
     * This test:
     * 1. Sends a payment request with a very short deadline (30 seconds)
     * 2. Displays the request in wallet with countdown
     * 3. After expiration, verifies wallet cannot accept the payment
     *
     * Usage:
     *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testPaymentRequestExpirationFlow" \
     *       -DtargetNametag=mp-9 \
     *       -Damount=500000000 \
     *       -DdeadlineSeconds=30
     */
    @Test
    public void testPaymentRequestExpirationFlow() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");
        BigInteger amount = new BigInteger(System.getProperty("amount", "500000000")); // Default 5 SOL
        int decimals = Integer.parseInt(System.getProperty("decimals", String.valueOf(DEFAULT_DECIMALS)));
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        int deadlineSeconds = Integer.parseInt(System.getProperty("deadlineSeconds", "30"));
        int waitAfterExpiry = Integer.parseInt(System.getProperty("waitAfterExpiry", "60")); // Wait 60s after expiry

        String testNametag = "expiry-test-" + System.currentTimeMillis() % 100000;
        String testAddress = "expiry-test-address-" + System.currentTimeMillis();

        printHeader("PAYMENT REQUEST EXPIRATION E2E TEST");
        System.out.println("Configuration:");
        System.out.println("   Target wallet nametag: " + targetNametag);
        System.out.println("   Test sender nametag: " + testNametag);
        System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
        System.out.println("   Coin ID: " + coinId.substring(0, 16) + "...");
        System.out.println("   Deadline: " + deadlineSeconds + " seconds");
        System.out.println("   Wait after expiry: " + waitAfterExpiry + " seconds");
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        System.out.println("Generated test keypair: " + keyManager.getPublicKeyHex().substring(0, 32) + "...");

        NostrClient client = new NostrClient(keyManager);
        AtomicBoolean tokenReceived = new AtomicBoolean(false);
        AtomicBoolean declineReceived = new AtomicBoolean(false);
        AtomicReference<PaymentRequestProtocol.PaymentRequestResponse> receivedResponse = new AtomicReference<>(null);

        try {
            // Step 1: Connect
            printStep(1, "Connect to Nostr relay");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            // Step 2: Publish nametag
            printStep(2, "Publish test nametag binding");
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, testNametag, testAddress);
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("Nametag published: " + testNametag);
            Thread.sleep(1500);

            // Step 3: Subscribe to both token transfers AND payment request responses
            printStep(3, "Subscribe to token transfers and payment responses");

            // Token transfer subscription
            Filter tokenFilter = Filter.builder()
                    .kinds(Arrays.asList(EventKinds.TOKEN_TRANSFER, EventKinds.ENCRYPTED_DM))
                    .pTags(keyManager.getPublicKeyHex())
                    .since(System.currentTimeMillis() / 1000 - 60)
                    .build();

            final String TOKEN_PREFIX = "token_transfer:";
            client.subscribe("token-transfers", tokenFilter, event -> {
                try {
                    String content = event.getContent();
                    String decrypted;
                    if (content.contains("?iv=")) {
                        decrypted = keyManager.decryptHex(content, event.getPubkey());
                    } else {
                        decrypted = content;
                    }
                    if (decrypted.startsWith(TOKEN_PREFIX)) {
                        System.out.println("TOKEN TRANSFER RECEIVED (should NOT happen after expiry!)");
                        tokenReceived.set(true);
                    }
                } catch (Exception e) {
                    // Ignore decryption errors
                }
            });

            // Payment response subscription
            Filter responseFilter = Filter.builder()
                    .kinds(Arrays.asList(EventKinds.PAYMENT_REQUEST_RESPONSE))
                    .pTags(keyManager.getPublicKeyHex())
                    .since(System.currentTimeMillis() / 1000 - 60)
                    .build();

            client.subscribe("decline-responses", responseFilter, event -> {
                try {
                    PaymentRequestProtocol.PaymentRequestResponse response =
                            PaymentRequestProtocol.parsePaymentRequestResponse(event, keyManager);
                    System.out.println("PAYMENT RESPONSE RECEIVED: " + response.getStatus());
                    receivedResponse.set(response);
                    declineReceived.set(true);
                } catch (Exception e) {
                    // Ignore
                }
            });
            System.out.println("Subscribed to token transfers and payment responses");

            // Step 4: Resolve target
            printStep(4, "Resolve target wallet nametag");
            String targetPubkey = resolveNametag(client, targetNametag);

            // Step 5: Send payment request with short deadline
            printStep(5, "Send payment request with " + deadlineSeconds + "s deadline");
            long deadline = System.currentTimeMillis() + (deadlineSeconds * 1000L);
            String message = "EXPIRATION TEST - Wait for expiry, then try to accept!";
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, message, testNametag, deadline
            );
            String eventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("Payment request sent with deadline!");
            System.out.println("   Event ID: " + eventId.substring(0, 16) + "...");
            System.out.println("   Request ID: " + request.getRequestId());
            System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
            System.out.println("   Deadline: " + deadline + " (in " + deadlineSeconds + "s)");

            // Step 6: Wait for deadline to pass
            printStep(6, "Waiting for deadline to expire");
            System.out.println();
            System.out.println("+--------------------------------------------------------+");
            System.out.println("|  WAITING FOR EXPIRATION                                |");
            System.out.println("|                                                        |");
            System.out.println("|  DO NOT accept the request in the wallet yet!          |");
            System.out.println("|  Wait for the deadline to pass.                        |");
            System.out.println("|                                                        |");
            System.out.println("|  Deadline expires in: " + deadlineSeconds + " seconds                    |");
            System.out.println("+--------------------------------------------------------+");
            System.out.println();

            // Countdown to expiry
            for (int i = deadlineSeconds; i > 0; i--) {
                System.out.print("\rExpiring in " + i + " seconds...    ");
                Thread.sleep(1000);
            }
            System.out.println();
            System.out.println("DEADLINE HAS PASSED!");

            // Step 7: Instruct user to try accepting
            printStep(7, "Verify wallet blocks acceptance after expiry");
            System.out.println();
            System.out.println("+--------------------------------------------------------+");
            System.out.println("|  ACTION REQUIRED                                       |");
            System.out.println("|                                                        |");
            System.out.println("|  The payment request should now be EXPIRED.            |");
            System.out.println("|                                                        |");
            System.out.println("|  1. Open the wallet app                                |");
            System.out.println("|  2. Tap Settings > Payment Requests                    |");
            System.out.println("|  3. Try to tap 'Pay' on the expired request            |");
            System.out.println("|                                                        |");
            System.out.println("|  EXPECTED: Wallet should show 'Expired' status         |");
            System.out.println("|            and block the acceptance.                   |");
            System.out.println("|                                                        |");
            System.out.println("|  Waiting " + waitAfterExpiry + " seconds for any response...          |");
            System.out.println("+--------------------------------------------------------+");
            System.out.println();

            // Wait to see if user tries to accept (which should fail)
            long startTime = System.currentTimeMillis();
            long timeoutMs = waitAfterExpiry * 1000L;
            while (!tokenReceived.get() && !declineReceived.get() &&
                    (System.currentTimeMillis() - startTime) < timeoutMs) {
                Thread.sleep(2000);
                int remaining = (int) ((timeoutMs - (System.currentTimeMillis() - startTime)) / 1000);
                System.out.print("\rMonitoring... " + remaining + "s remaining    ");
            }
            System.out.println();

            // Step 8: Verify results
            printStep(8, "Verify expiration behavior");
            if (tokenReceived.get()) {
                System.out.println("FAILURE: Token transfer was received AFTER expiry!");
                System.out.println("   The wallet should NOT accept expired payment requests.");
                System.out.println("   This indicates a bug in the wallet's expiration handling.");
            } else {
                printSuccess("EXPIRATION TEST PASSED!");
                System.out.println("No token transfer was received after expiry.");
                System.out.println("The wallet correctly blocked acceptance of the expired request.");
                if (declineReceived.get()) {
                    System.out.println();
                    System.out.println("Additionally, a payment response was received:");
                    PaymentRequestProtocol.PaymentRequestResponse response = receivedResponse.get();
                    System.out.println("   Status: " + response.getStatus());
                }
            }

        } finally {
            disconnect(client);
        }
    }

    /**
     * Send a payment request with custom deadline for manual testing.
     *
     * Usage:
     *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendPaymentRequestWithDeadline" \
     *       -DtargetNametag=mp-9 \
     *       -Damount=1000000000 \
     *       -DdeadlineSeconds=300
     */
    @Test
    public void testSendPaymentRequestWithDeadline() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-9");
        String recipientNametag = System.getProperty("recipientNametag", "deadline-test-" + System.currentTimeMillis() % 10000);
        BigInteger amount = new BigInteger(System.getProperty("amount", "1000000000"));
        int decimals = Integer.parseInt(System.getProperty("decimals", String.valueOf(DEFAULT_DECIMALS)));
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        int deadlineSeconds = Integer.parseInt(System.getProperty("deadlineSeconds", "300")); // 5 minutes default
        String message = System.getProperty("message", "Test with deadline - expires in " + deadlineSeconds + "s");

        printHeader("Payment Request with Deadline Test");
        System.out.println("Parameters:");
        System.out.println("   Target nametag: " + targetNametag);
        System.out.println("   Recipient nametag: " + recipientNametag);
        System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
        System.out.println("   Coin ID: " + coinId.substring(0, 16) + "...");
        System.out.println("   Deadline: " + deadlineSeconds + " seconds from now");
        System.out.println("   Message: " + message);
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        try {
            // Connect
            System.out.println("Connecting to Nostr relay...");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("Connected to relay");

            // Publish nametag binding for recipient
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, recipientNametag, "test-addr");
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("Recipient nametag published: " + recipientNametag);
            Thread.sleep(1000);

            // Resolve target
            String targetPubkey = resolveNametag(client, targetNametag);

            // Calculate deadline
            long deadline = System.currentTimeMillis() + (deadlineSeconds * 1000L);

            // Send payment request with deadline
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, message, recipientNametag, deadline
            );
            System.out.println("Sending payment request with deadline...");
            String eventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("Payment request sent! Event ID: " + eventId.substring(0, 16) + "...");

            Thread.sleep(2000);

            printSuccess("Payment request with deadline sent successfully!");
            System.out.println("Summary:");
            System.out.println("   To: " + targetNametag);
            System.out.println("   Amount: " + formatBigIntegerAmount(amount, decimals));
            System.out.println("   From: " + recipientNametag);
            System.out.println("   Deadline: " + deadline + " (" + deadlineSeconds + "s from now)");
            System.out.println("   Request ID: " + request.getRequestId());
            System.out.println();
            System.out.println("Check the wallet Settings > Payment Requests!");
            System.out.println("The request should show the remaining time.");

        } finally {
            disconnect(client);
        }
    }

    // ==================== Helper Methods ====================

    private String resolveNametag(NostrClient client, String nametag) throws Exception {
        System.out.println("Resolving nametag '" + nametag + "'...");
        String pubkey = client.queryPubkeyByNametag(nametag).get(10, TimeUnit.SECONDS);
        if (pubkey == null) {
            throw new RuntimeException("Nametag not found: " + nametag);
        }
        System.out.println("Resolved to: " + pubkey.substring(0, 16) + "...");
        return pubkey;
    }

    private void disconnect(NostrClient client) {
        System.out.println();
        System.out.println("Disconnecting...");
        client.disconnect();
        System.out.println("Disconnected");
    }

    /**
     * Format amount for display with specified decimals.
     *
     * @param amount Amount in smallest units
     * @param decimals Number of decimal places
     * @return Formatted amount string
     */
    private String formatAmount(long amount, int decimals) {
        double divisor = Math.pow(10, decimals);
        double displayAmount = amount / divisor;
        return String.format("%." + Math.min(decimals, 8) + "f", displayAmount);
    }

    /**
     * Format BigInteger amount for display with specified decimals.
     *
     * @param amount Amount in smallest units (BigInteger for large values)
     * @param decimals Number of decimal places
     * @return Formatted amount string
     */
    private String formatBigIntegerAmount(BigInteger amount, int decimals) {
        java.math.BigDecimal divisor = java.math.BigDecimal.TEN.pow(decimals);
        java.math.BigDecimal displayAmount = new java.math.BigDecimal(amount).divide(divisor, decimals, java.math.RoundingMode.HALF_UP);
        return displayAmount.stripTrailingZeros().toPlainString();
    }

    private void printHeader(String title) {
        System.out.println("================================================================");
        System.out.println("  " + title);
        System.out.println("================================================================");
        System.out.println();
    }

    private void printStep(int step, String description) {
        System.out.println();
        System.out.println("------------------------------------------------------------");
        System.out.println("STEP " + step + ": " + description);
        System.out.println("------------------------------------------------------------");
    }

    private void printSuccess(String message) {
        System.out.println();
        System.out.println("================================================================");
        System.out.println("  SUCCESS: " + message);
        System.out.println("================================================================");
        System.out.println();
    }
}
