package org.unicitylabs.nostr.payment;

import org.junit.Test;
import org.unicitylabs.nostr.client.NostrClient;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.nametag.NametagBinding;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;
import org.unicitylabs.nostr.token.TokenTransferProtocol;

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
