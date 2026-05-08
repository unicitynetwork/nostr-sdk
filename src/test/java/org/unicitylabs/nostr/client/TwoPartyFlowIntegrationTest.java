package org.unicitylabs.nostr.client;

import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import org.unicitylabs.nostr.crypto.NostrKeyManager;
import org.unicitylabs.nostr.protocol.Event;
import org.unicitylabs.nostr.protocol.EventKinds;
import org.unicitylabs.nostr.protocol.Filter;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Two-party end-to-end test: Alice publishes a real kind-31113 token
 * transfer to Bob, Bob's consumer subscription receives it.
 *
 * <p>This is the test that would have caught the keepalive live-tail
 * regression. Earlier coverage asserted the {@code shape} of the
 * keepalive REQ filter, then locked in {@code authors:[self]} as the
 * expected shape — so when that filter was actually wrong (it matched
 * every event the wallet itself published), the tests confirmed the
 * bug rather than catching it. This test asserts the actual two-party
 * behavior end-to-end.</p>
 *
 * <p>Runs in two modes:</p>
 * <ol>
 *   <li>Default: spins up
 *       {@code ghcr.io/unicitynetwork/unicity-tokens-relay:latest} via
 *       testcontainers (hermetic). Skipped if Docker is unavailable.</li>
 *   <li>{@code RELAY_URL=wss://...}: uses that relay instead. Useful
 *       for verifying the fix against the deployed environment.</li>
 * </ol>
 *
 * <p>Run with:</p>
 * <pre>
 *   ./gradlew integrationTest --tests "org.unicitylabs.nostr.client.TwoPartyFlowIntegrationTest"
 *   RELAY_URL=wss://nostr-relay.testnet.unicity.network ./gradlew integrationTest \
 *       --tests "org.unicitylabs.nostr.client.TwoPartyFlowIntegrationTest"
 * </pre>
 */
public class TwoPartyFlowIntegrationTest {

    private static final int RELAY_INTERNAL_PORT = 8080;
    private static final String IMAGE =
            "ghcr.io/unicitynetwork/unicity-tokens-relay:latest";

    private static GenericContainer<?> container;
    private static String relayUrl;

    @BeforeClass
    public static void setUp() throws Exception {
        String externalRelay = System.getenv("RELAY_URL");
        if (externalRelay != null && !externalRelay.trim().isEmpty()) {
            relayUrl = externalRelay.trim();
            System.out.println("Using external relay: " + relayUrl);
            return;
        }

        try {
            DockerClientFactory.instance().client();
        } catch (IllegalStateException e) {
            Assume.assumeTrue("Docker not available: " + e.getMessage(), false);
            return;
        }

        // Pin to linux/amd64. The published image only ships an amd64
        // manifest; on Apple Silicon dev machines Docker Desktop runs
        // it under emulation, on linux/amd64 CI the path is native.
        // The published image only ships a linux/amd64 manifest. On
        // linux/amd64 CI runners that's the native path; on Apple
        // Silicon dev machines Docker Desktop falls back to the
        // single-arch manifest and runs it under emulation
        // automatically. (We deliberately do NOT call
        // withCreateContainerCmdModifier(cmd.withPlatform("linux/amd64"))
        // — that requires Docker API ≥ 1.41, and the docker-java client
        // bundled with testcontainers 1.20.4 sends a 1.32 header so
        // the call returns 400 BadRequest. The fall-back-to-only-
        // manifest path works everywhere.)
        container = new GenericContainer<>(IMAGE)
                .withExposedPorts(RELAY_INTERNAL_PORT)
                .waitingFor(Wait.forLogMessage(".*listening.*\\n", 1))
                .withStartupTimeout(Duration.ofSeconds(60));

        container.start();
        int mappedPort = container.getMappedPort(RELAY_INTERNAL_PORT);
        relayUrl = "ws://localhost:" + mappedPort;
        System.out.println("Relay started at: " + relayUrl);
        // Brief settle delay so the relay's WS upgrade handler is fully
        // wired before the first connect.
        Thread.sleep(500);
    }

    @AfterClass
    public static void tearDown() {
        if (container != null) {
            try { container.stop(); } catch (Exception e) { /* ignore */ }
        }
    }

    @Test
    public void aliceToBobTokenTransferIsReceivedByBob() throws Exception {
        NostrKeyManager aliceKeys = NostrKeyManager.generate();
        NostrKeyManager bobKeys = NostrKeyManager.generate();
        NostrClient alice = new NostrClient(aliceKeys);
        NostrClient bob = new NostrClient(bobKeys);

        try {
            // Short ping so a keepalive cycle fires inside the test.
            alice.setPingIntervalMs(2000);
            bob.setPingIntervalMs(2000);

            CompletableFuture.allOf(
                    alice.connect(relayUrl),
                    bob.connect(relayUrl)
            ).get(15, TimeUnit.SECONDS);

            // Bob subscribes for incoming token transfers addressed to him.
            CompletableFuture<Event> bobReceived = new CompletableFuture<>();
            Filter bobFilter = Filter.builder()
                    .kinds(EventKinds.TOKEN_TRANSFER)
                    .pTags(bobKeys.getPublicKeyHex())
                    .build();
            bob.subscribe(bobFilter, new NostrEventListener() {
                @Override
                public void onEvent(Event event) {
                    bobReceived.complete(event);
                }
                @Override
                public void onError(String subId, String error) {
                    bobReceived.completeExceptionally(
                            new RuntimeException("subscription error: " + error));
                }
            });

            // Let the subscription settle (relay sends EOSE) and at
            // least one keepalive cycle fire on Alice so any broken
            // filter would already be live.
            Thread.sleep(2500);

            // Alice publishes a real token transfer to Bob.
            String tokenJson = "{\"probe\":\"two-party-flow\",\"ts\":"
                    + System.currentTimeMillis() + "}";
            String eventId = alice.sendTokenTransfer(
                    bobKeys.getPublicKeyHex(), tokenJson)
                    .get(10, TimeUnit.SECONDS);
            assertTrue("event id must be 64 hex chars: " + eventId,
                    eventId.matches("^[0-9a-f]{64}$"));

            Event received = bobReceived.get(8, TimeUnit.SECONDS);
            assertEquals(eventId, received.getId());
            assertEquals(EventKinds.TOKEN_TRANSFER, received.getKind());
            assertEquals(aliceKeys.getPublicKeyHex(), received.getPubkey());
        } finally {
            alice.disconnect();
            bob.disconnect();
        }
    }

    @Test
    public void bobToAliceRoundTripWorksWhileKeepaliveActive() throws Exception {
        // Symmetric direction. Catches the case where a relay dedupes
        // events across overlapping subs — if the keepalive sub matched
        // the same event the consumer sub does, on some relays only one
        // would get the delivery and the wallet's flow would break.
        // With the unreachable-id keepalive filter, no overlap is
        // possible.
        NostrKeyManager aliceKeys = NostrKeyManager.generate();
        NostrKeyManager bobKeys = NostrKeyManager.generate();
        NostrClient alice = new NostrClient(aliceKeys);
        NostrClient bob = new NostrClient(bobKeys);

        try {
            alice.setPingIntervalMs(2000);
            bob.setPingIntervalMs(2000);
            CompletableFuture.allOf(
                    alice.connect(relayUrl),
                    bob.connect(relayUrl)
            ).get(15, TimeUnit.SECONDS);

            CompletableFuture<Event> aliceReceived = new CompletableFuture<>();
            alice.subscribe(
                    Filter.builder()
                            .kinds(EventKinds.TOKEN_TRANSFER)
                            .pTags(aliceKeys.getPublicKeyHex())
                            .build(),
                    new NostrEventListener() {
                        @Override
                        public void onEvent(Event event) {
                            aliceReceived.complete(event);
                        }
                        @Override
                        public void onError(String subId, String error) {
                            aliceReceived.completeExceptionally(
                                    new RuntimeException("subscription error: " + error));
                        }
                    });

            Thread.sleep(2500);
            String eventId = bob.sendTokenTransfer(
                    aliceKeys.getPublicKeyHex(),
                    "{\"probe\":\"reverse-direction\"}")
                    .get(10, TimeUnit.SECONDS);

            Event received = aliceReceived.get(8, TimeUnit.SECONDS);
            assertEquals(eventId, received.getId());
            assertEquals(bobKeys.getPublicKeyHex(), received.getPubkey());
        } finally {
            alice.disconnect();
            bob.disconnect();
        }
    }
}
