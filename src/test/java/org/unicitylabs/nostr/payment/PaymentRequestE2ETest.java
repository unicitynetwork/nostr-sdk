package org.unicitylabs.nostr.payment;

import org.junit.Test;
import org.unicitylabs.nostr.client.NostrClient;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.nametag.NametagBinding;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * E2E tests for payment request functionality.
 *
 * Usage:
 *   # Send a single payment request
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendPaymentRequest" -DtargetNametag=mp-6
 *
 *   # Send multiple payment requests
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testSendMultiplePaymentRequests" -DtargetNametag=mp-6
 *
 *   # Full flow with token transfer verification (requires manual wallet interaction)
 *   ./gradlew e2eTest --tests "PaymentRequestE2ETest.testFullPaymentRequestFlow" -DtargetNametag=mp-6
 */
public class PaymentRequestE2ETest {

    // Configuration - can be overridden via system properties
    private static final String NOSTR_RELAY = System.getProperty("nostrRelay",
            "ws://unicity-nostr-relay-20250927-alb-1919039002.me-central-1.elb.amazonaws.com:8080");

    // Solana coin ID from the registry
    private static final String SOLANA_COIN_ID = "dee5f8ce778562eec90e9c38a91296a023210ccc76ff4c29d527ac3eb64ade93";

    /**
     * Send a single payment request to a wallet.
     */
    @Test
    public void testSendPaymentRequest() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-6");
        String recipientNametag = System.getProperty("recipientNametag", "test-requester-" + System.currentTimeMillis() % 10000);
        long amount = Long.parseLong(System.getProperty("amount", "1000000"));
        String symbol = System.getProperty("symbol", "SOL");
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        String message = System.getProperty("message", "Test payment request from E2E test");

        printHeader("Payment Request E2E Test");
        System.out.println("📋 Parameters:");
        System.out.println("   Target nametag: " + targetNametag);
        System.out.println("   Recipient nametag: " + recipientNametag);
        System.out.println("   Amount: " + formatAmount(amount, symbol));
        System.out.println("   Message: " + message);
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        try {
            // Connect
            System.out.println("🔗 Connecting to Nostr relay...");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("✅ Connected to relay");

            // Publish nametag binding for recipient
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, recipientNametag, "test-addr");
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("✅ Recipient nametag published: " + recipientNametag);
            Thread.sleep(1000);

            // Resolve target
            String targetPubkey = resolveNametag(client, targetNametag);

            // Send payment request
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, symbol, message, recipientNametag
            );
            System.out.println("📤 Sending payment request...");
            String eventId = client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("✅ Payment request sent! Event ID: " + eventId.substring(0, 16) + "...");

            Thread.sleep(2000);

            printSuccess("Payment request sent successfully!");
            System.out.println("📊 Summary:");
            System.out.println("   To: " + targetNametag);
            System.out.println("   Amount: " + formatAmount(amount, symbol));
            System.out.println("   From: " + recipientNametag);
            System.out.println();
            System.out.println("💡 Check the wallet Settings > Payment Requests!");

        } finally {
            disconnect(client);
        }
    }

    /**
     * Send multiple payment requests for testing wallet UI.
     */
    @Test
    public void testSendMultiplePaymentRequests() throws Exception {
        String targetNametag = System.getProperty("targetNametag", "mp-6");

        printHeader("Multiple Payment Requests Test");

        NostrKeyManager keyManager = NostrKeyManager.generate();
        NostrClient client = new NostrClient(keyManager);

        try {
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("✅ Connected to relay");

            String targetPubkey = resolveNametag(client, targetNametag);

            String[][] requests = {
                    {"500000", "SOL", "Coffee - small"},
                    {"1500000", "SOL", "Lunch payment"},
                    {"10000000", "SOL", "Monthly subscription"},
            };

            for (int i = 0; i < requests.length; i++) {
                String[] req = requests[i];
                long amount = Long.parseLong(req[0]);
                String symbol = req[1];
                String message = req[2];
                String recipientNametag = "merchant-" + (i + 1);

                // Publish nametag for this merchant
                Event bindingEvent = NametagBinding.createBindingEvent(keyManager, recipientNametag, "addr-" + i);
                client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);

                PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                        amount, SOLANA_COIN_ID, symbol, message, recipientNametag
                );

                System.out.println("📤 Sending request " + (i + 1) + ": " + formatAmount(amount, symbol) + " - " + message);
                client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
                System.out.println("   ✅ Sent (ID: " + request.getRequestId() + ")");

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
        String targetNametag = System.getProperty("targetNametag", "mp-6");
        long amount = Long.parseLong(System.getProperty("amount", "1000000"));
        String symbol = System.getProperty("symbol", "SOL");
        String coinId = System.getProperty("coinId", SOLANA_COIN_ID);
        int timeoutSeconds = Integer.parseInt(System.getProperty("timeout", "120"));

        String testNametag = "test-recv-" + System.currentTimeMillis() % 100000;
        String testAddress = "test-address-" + System.currentTimeMillis();

        printHeader("FULL PAYMENT REQUEST E2E TEST");
        System.out.println("📋 Configuration:");
        System.out.println("   Target wallet nametag: " + targetNametag);
        System.out.println("   Test receiver nametag: " + testNametag);
        System.out.println("   Amount: " + formatAmount(amount, symbol));
        System.out.println("   Timeout: " + timeoutSeconds + " seconds");
        System.out.println("   Relay: " + NOSTR_RELAY);
        System.out.println();

        NostrKeyManager keyManager = NostrKeyManager.generate();
        System.out.println("🔑 Generated test keypair: " + keyManager.getPublicKeyHex().substring(0, 32) + "...");

        NostrClient client = new NostrClient(keyManager);
        AtomicBoolean tokenReceived = new AtomicBoolean(false);
        AtomicReference<String> receivedTokenJson = new AtomicReference<>(null);

        try {
            // Step 1: Connect
            printStep(1, "Connect to Nostr relay");
            client.connect(NOSTR_RELAY).get(30, TimeUnit.SECONDS);
            System.out.println("✅ Connected to relay");

            // Step 2: Publish nametag
            printStep(2, "Publish test nametag binding");
            Event bindingEvent = NametagBinding.createBindingEvent(keyManager, testNametag, testAddress);
            client.publishEvent(bindingEvent).get(10, TimeUnit.SECONDS);
            System.out.println("✅ Nametag published: " + testNametag);
            Thread.sleep(1500);

            // Verify nametag
            String resolvedPubkey = client.queryPubkeyByNametag(testNametag).get(10, TimeUnit.SECONDS);
            if (resolvedPubkey != null && resolvedPubkey.equals(keyManager.getPublicKeyHex())) {
                System.out.println("✅ Nametag verified");
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
                System.out.println("📨 Received event kind " + event.getKind() + " from: " + event.getPubkey().substring(0, 16) + "...");
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
                        System.out.println("✅ TOKEN TRANSFER RECEIVED!");
                        receivedTokenJson.set(decrypted);
                        tokenReceived.set(true);
                    }
                } catch (Exception e) {
                    System.out.println("   (Error processing: " + e.getMessage() + ")");
                    e.printStackTrace();
                }
            });
            System.out.println("✅ Subscribed to incoming messages");

            // Step 4: Resolve target
            printStep(4, "Resolve target wallet nametag");
            String targetPubkey = resolveNametag(client, targetNametag);

            // Step 5: Send payment request
            printStep(5, "Send payment request");
            String message = "E2E Test - please accept!";
            PaymentRequestProtocol.PaymentRequest request = new PaymentRequestProtocol.PaymentRequest(
                    amount, coinId, symbol, message, testNametag
            );
            client.sendPaymentRequest(targetPubkey, request).get(10, TimeUnit.SECONDS);
            System.out.println("✅ Payment request sent!");
            System.out.println("   Amount: " + formatAmount(amount, symbol));
            System.out.println("   Recipient: " + testNametag);

            // Step 6: Wait for user action
            printStep(6, "Waiting for wallet to accept payment request");
            System.out.println();
            System.out.println("╔════════════════════════════════════════════════════════╗");
            System.out.println("║  🔔 ACTION REQUIRED                                    ║");
            System.out.println("║                                                        ║");
            System.out.println("║  1. Open the wallet app                                ║");
            System.out.println("║  2. Tap Settings (gear) > Payment Requests             ║");
            System.out.println("║  3. Tap 'Pay' on the request from " + testNametag);
            System.out.println("║                                                        ║");
            System.out.println("║  Waiting " + timeoutSeconds + " seconds...                             ║");
            System.out.println("╚════════════════════════════════════════════════════════╝");
            System.out.println();

            long startTime = System.currentTimeMillis();
            long timeoutMs = timeoutSeconds * 1000L;
            while (!tokenReceived.get() && (System.currentTimeMillis() - startTime) < timeoutMs) {
                Thread.sleep(2000);
                int remaining = (int) ((timeoutMs - (System.currentTimeMillis() - startTime)) / 1000);
                System.out.print("\r⏳ Waiting... " + remaining + "s remaining    ");
            }
            System.out.println();

            // Step 7: Verify
            printStep(7, "Verify result");
            if (tokenReceived.get()) {
                printSuccess("Token transfer received!");
                System.out.println("📊 Transfer Details:");
                System.out.println("   From: " + targetNametag);
                System.out.println("   To: " + testNametag);
                System.out.println("   Amount: " + formatAmount(amount, symbol));

                String tokenData = receivedTokenJson.get();
                if (tokenData != null) {
                    String jsonPart = tokenData.substring(TOKEN_PREFIX.length());
                    System.out.println("📦 Payload: " + jsonPart.substring(0, Math.min(100, jsonPart.length())) + "...");
                }
            } else {
                System.out.println("⚠️ TIMEOUT - No token transfer received");
                System.out.println("   Check wallet for errors or try again.");
            }

        } finally {
            disconnect(client);
        }
    }

    // ==================== Helper Methods ====================

    private String resolveNametag(NostrClient client, String nametag) throws Exception {
        System.out.println("🔍 Resolving nametag '" + nametag + "'...");
        String pubkey = client.queryPubkeyByNametag(nametag).get(10, TimeUnit.SECONDS);
        if (pubkey == null) {
            throw new RuntimeException("Nametag not found: " + nametag);
        }
        System.out.println("✅ Resolved to: " + pubkey.substring(0, 16) + "...");
        return pubkey;
    }

    private void disconnect(NostrClient client) {
        System.out.println();
        System.out.println("🔌 Disconnecting...");
        client.disconnect();
        System.out.println("✅ Disconnected");
    }

    private String formatAmount(long amount, String symbol) {
        double displayAmount = "SOL".equals(symbol)
                ? amount / 1_000_000_000.0
                : amount / 1_000_000.0;
        return String.format("%.6f %s", displayAmount, symbol);
    }

    private void printHeader(String title) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.printf("║   %-59s║%n", title);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    private void printStep(int step, String description) {
        System.out.println();
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("STEP " + step + ": " + description);
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    private void printSuccess(String message) {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.printf("║  ✅ %-57s║%n", message);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
