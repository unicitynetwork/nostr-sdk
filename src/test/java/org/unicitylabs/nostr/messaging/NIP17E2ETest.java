package org.unicitylabs.nostr.messaging;

import org.junit.Test;
import org.unicitylabs.nostr.client.NostrClient;
import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Filter;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * E2E tests for NIP-17 Private Direct Messages over real Nostr relay.
 *
 * Usage:
 *   # Run all NIP-17 E2E tests
 *   ./gradlew e2eTest --tests "NIP17E2ETest"
 *
 *   # Run with custom relay
 *   ./gradlew e2eTest --tests "NIP17E2ETest" -DnostrRelay=wss://your-relay.com
 */
public class NIP17E2ETest {

    private static final String NOSTR_RELAY = System.getProperty("nostrRelay",
            "wss://nostr-relay.testnet.unicity.network");

    private static final int TIMEOUT_SECONDS = 60;
    private static final int POLL_INTERVAL_MS = 500;
    private static final int MAX_POLL_ATTEMPTS = 20;

    /**
     * Test full messaging flow: Alice sends message, Bob retrieves and decrypts it.
     * Uses polling to query for the message since some relays don't route live events.
     */
    @Test
    public void testPrivateMessageRoundTrip() throws Exception {
        printHeader("NIP-17 Private Message Round Trip");
        System.out.println("Relay: " + NOSTR_RELAY);
        System.out.println();

        // Generate key pairs
        NostrKeyManager aliceKeys = NostrKeyManager.generate();
        NostrKeyManager bobKeys = NostrKeyManager.generate();

        System.out.println("Alice pubkey: " + aliceKeys.getPublicKeyHex().substring(0, 16) + "...");
        System.out.println("Bob pubkey:   " + bobKeys.getPublicKeyHex().substring(0, 16) + "...");

        NostrClient aliceClient = new NostrClient(aliceKeys);
        NostrClient bobClient = new NostrClient(bobKeys);

        try {
            // Step 1: Connect both clients
            printStep(1, "Connect clients to relay");
            CompletableFuture.allOf(
                    aliceClient.connect(NOSTR_RELAY),
                    bobClient.connect(NOSTR_RELAY)
            ).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            System.out.println("Both clients connected");

            // Step 2: Alice sends private message to Bob
            printStep(2, "Alice sends private message to Bob");
            String testMessage = "Hello Bob! This is a secret NIP-17 message. " + System.currentTimeMillis();
            String messageEventId = aliceClient.sendPrivateMessage(
                    bobKeys.getPublicKeyHex(),
                    testMessage,
                    null
            ).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            System.out.println("Message sent with gift wrap ID: " + messageEventId.substring(0, 16) + "...");

            // Step 3: Bob polls for the message by querying for the specific event ID
            printStep(3, "Bob polls for the message");
            PrivateMessage bobsMessage = pollForGiftWrap(bobClient, bobKeys, messageEventId);

            assertNotNull("Bob should receive the message", bobsMessage);
            assertEquals("Message content should match", testMessage, bobsMessage.getContent());
            assertEquals("Sender should be Alice", aliceKeys.getPublicKeyHex(), bobsMessage.getSenderPubkey());
            assertTrue("Should be a chat message", bobsMessage.isChatMessage());
            System.out.println("Bob received and verified the message!");
            System.out.println("  Content: \"" + bobsMessage.getContent() + "\"");

            // Step 4: Bob sends read receipt
            printStep(4, "Bob sends read receipt to Alice");
            String receiptEventId = bobClient.sendReadReceipt(
                    aliceKeys.getPublicKeyHex(),
                    bobsMessage.getEventId()
            ).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            System.out.println("Read receipt sent with gift wrap ID: " + receiptEventId.substring(0, 16) + "...");

            // Step 5: Alice polls for the read receipt
            printStep(5, "Alice polls for read receipt");
            PrivateMessage alicesReceipt = pollForGiftWrap(aliceClient, aliceKeys, receiptEventId);

            assertNotNull("Alice should receive the read receipt", alicesReceipt);
            assertTrue("Should be a read receipt", alicesReceipt.isReadReceipt());
            assertEquals("Receipt sender should be Bob", bobKeys.getPublicKeyHex(), alicesReceipt.getSenderPubkey());
            assertEquals("Receipt should reference original message",
                    bobsMessage.getEventId(), alicesReceipt.getReplyToEventId());
            System.out.println("Alice received and verified the read receipt!");

            printSuccess("NIP-17 round trip test passed!");

        } finally {
            aliceClient.disconnect();
            bobClient.disconnect();
            System.out.println("Clients disconnected");
        }
    }

    /**
     * Poll for a specific gift-wrapped event by ID and unwrap it.
     */
    private PrivateMessage pollForGiftWrap(NostrClient client, NostrKeyManager keys, String eventId)
            throws Exception {
        AtomicReference<PrivateMessage> result = new AtomicReference<>();
        CountDownLatch latch = new CountDownLatch(1);

        for (int attempt = 0; attempt < MAX_POLL_ATTEMPTS && result.get() == null; attempt++) {
            if (attempt > 0) {
                Thread.sleep(POLL_INTERVAL_MS);
            }

            String subId = "poll-" + attempt;
            Filter filter = Filter.builder()
                    .ids(eventId)
                    .build();

            client.subscribe(subId, filter, event -> {
                if (event.getId().equals(eventId)) {
                    System.out.println("  Found event: " + eventId.substring(0, 16) + "...");
                    try {
                        PrivateMessage msg = client.unwrapPrivateMessage(event);
                        result.set(msg);
                        latch.countDown();
                    } catch (Exception e) {
                        System.out.println("  Failed to unwrap: " + e.getMessage());
                    }
                }
            });

            // Wait briefly for response
            latch.await(1, TimeUnit.SECONDS);
            client.unsubscribe(subId);

            if (result.get() != null) {
                break;
            }
            System.out.println("  Attempt " + (attempt + 1) + ": event not found yet...");
        }

        return result.get();
    }

    // ==================== Helper Methods ====================

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
