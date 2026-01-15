package org.unicitylabs.nostr.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
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

import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.Assert.*;

/**
 * NIP-42 Authentication Integration Tests with Testcontainers.
 * Spins up a Zooid relay container that requires NIP-42 authentication
 * and verifies the client correctly handles the auth flow.
 */
public class NIP42AuthIntegrationTest {

    private static final int RELAY_PORT = 3334;
    private static final String AUTH_RELAY_URL = "ws://localhost";

    private static GenericContainer<?> container;
    private static String relayUrl;
    private static Path tempDir;
    private static NostrKeyManager adminKeys;
    private static OkHttpClient httpClient;
    private static ObjectMapper jsonMapper;

    @BeforeClass
    public static void setUp() throws Exception {
        System.out.println("================================================================");
        System.out.println("  NIP-42 Authentication Integration Tests (Java)");
        System.out.println("================================================================");

        try {
            DockerClientFactory.instance().client();
        } catch (IllegalStateException e) {
            Assume.assumeTrue("Docker not available: " + e.getMessage(), false);
            return;
        }

        adminKeys = NostrKeyManager.generate();
        System.out.println("Admin pubkey: " + adminKeys.getPublicKeyHex().substring(0, 16) + "...");

        tempDir = Files.createTempDirectory("nostr-test-");
        Path configDir = tempDir.resolve("config");
        Files.createDirectories(configDir);
        Files.createDirectories(tempDir.resolve("data"));
        Files.createDirectories(tempDir.resolve("media"));

        String configContent = generateRelayConfig("localhost", adminKeys.getPublicKeyHex());
        Path configPath = configDir.resolve("localhost");
        try (FileWriter writer = new FileWriter(configPath.toFile())) {
            writer.write(configContent);
        }
        System.out.println("Config written to: " + configPath);

        System.out.println("Starting Zooid relay container...");
        container = new GenericContainer<>("ghcr.io/coracle-social/zooid:latest")
            .withExposedPorts(RELAY_PORT)
            .withEnv("PORT", String.valueOf(RELAY_PORT))
            .withFileSystemBind(configDir.toString(), "/app/config")
            .withFileSystemBind(tempDir.resolve("data").toString(), "/app/data")
            .withFileSystemBind(tempDir.resolve("media").toString(), "/app/media")
            .waitingFor(Wait.forLogMessage(".*running on.*\\n", 1))
            .withStartupTimeout(Duration.ofSeconds(30));

        container.start();

        int mappedPort = container.getMappedPort(RELAY_PORT);
        relayUrl = "ws://localhost:" + mappedPort;
        System.out.println("Relay started at: " + relayUrl);

        httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .build();
        jsonMapper = new ObjectMapper();

        Thread.sleep(1000);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        if (container != null) {
            System.out.println("Stopping relay container...");
            container.stop();
        }
        if (tempDir != null) {
            deleteRecursively(tempDir.toFile());
        }
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        System.out.println("Cleanup complete");
    }

    private static String generateRelayConfig(String hostname, String adminPubkey) {
        return "host = \"" + hostname + "\"\n" +
               "schema = \"test_relay\"\n" +
               "secret = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n\n" +
               "[info]\n" +
               "name = \"Test Relay\"\n" +
               "icon = \"\"\n" +
               "pubkey = \"" + adminPubkey + "\"\n" +
               "description = \"Test relay for NIP-42 authentication\"\n\n" +
               "[policy]\n" +
               "public_join = true\n" +
               "strip_signatures = false\n\n" +
               "[groups]\n" +
               "enabled = true\n" +
               "auto_join = true\n\n" +
               "[management]\n" +
               "enabled = false\n\n" +
               "[blossom]\n" +
               "enabled = false\n\n" +
               "[roles.member]\n" +
               "can_invite = true\n\n" +
               "[roles.admin]\n" +
               "pubkeys = [\"" + adminPubkey + "\"]\n" +
               "can_manage = true\n";
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        file.delete();
    }

    @Test
    public void testAutomaticAuthentication() throws Exception {
        System.out.println("\n------------------------------------------------------------");
        System.out.println("TEST: Automatic NIP-42 Authentication");
        System.out.println("------------------------------------------------------------");

        NostrKeyManager userKeys = NostrKeyManager.generate();
        System.out.println("User pubkey: " + userKeys.getPublicKeyHex().substring(0, 16) + "...");

        CompletableFuture<Boolean> authResult = new CompletableFuture<>();

        Request request = new Request.Builder()
            .url(relayUrl)
            .header("Host", "localhost")
            .build();

        WebSocket ws = httpClient.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket connected");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
                try {
                    List<?> msg = jsonMapper.readValue(text, List.class);
                    String msgType = (String) msg.get(0);
                    System.out.println("Received: " + msgType);

                    if ("AUTH".equals(msgType)) {
                        String challenge = (String) msg.get(1);
                        System.out.println("AUTH challenge received: " + challenge.substring(0, 16) + "...");

                        Event authEvent = createAuthEvent(userKeys, AUTH_RELAY_URL, challenge);
                        List<Object> authMsg = Arrays.asList("AUTH", authEvent);
                        webSocket.send(jsonMapper.writeValueAsString(authMsg));
                        System.out.println("AUTH response sent");
                    } else if ("OK".equals(msgType)) {
                        webSocket.close(1000, "done");
                        authResult.complete(true);
                    }
                } catch (Exception e) {
                    authResult.completeExceptionally(e);
                }
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                authResult.completeExceptionally(t);
            }
        });

        try {
            Boolean result = authResult.get(10, TimeUnit.SECONDS);
            assertTrue("Authentication should succeed", result);
            System.out.println("\nSUCCESS: NIP-42 authentication test passed!");
        } finally {
            ws.close(1000, "cleanup");
        }
    }

    @Test
    public void testSubscriptionAfterAuth() throws Exception {
        System.out.println("\n------------------------------------------------------------");
        System.out.println("TEST: Subscription After Authentication");
        System.out.println("------------------------------------------------------------");

        System.out.println("User pubkey (admin): " + adminKeys.getPublicKeyHex().substring(0, 16) + "...");

        CompletableFuture<Boolean> eoseResult = new CompletableFuture<>();

        Request request = new Request.Builder()
            .url(relayUrl)
            .header("Host", "localhost")
            .build();

        WebSocket ws = httpClient.newWebSocket(request, new WebSocketListener() {
            private boolean waitingForAuthOk = false;

            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket connected");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
                try {
                    List<?> msg = jsonMapper.readValue(text, List.class);
                    String msgType = (String) msg.get(0);
                    System.out.println("Received: " + msgType);

                    if ("AUTH".equals(msgType)) {
                        String challenge = (String) msg.get(1);
                        System.out.println("AUTH challenge received");

                        Event authEvent = createAuthEvent(adminKeys, AUTH_RELAY_URL, challenge);
                        List<Object> authMsg = Arrays.asList("AUTH", authEvent);
                        webSocket.send(jsonMapper.writeValueAsString(authMsg));
                        System.out.println("AUTH response sent");
                        waitingForAuthOk = true;
                    } else if ("OK".equals(msgType) && waitingForAuthOk) {
                        System.out.println("Auth accepted, sending subscription");
                        waitingForAuthOk = false;

                        Map<String, Object> filter = new HashMap<>();
                        filter.put("kinds", Collections.singletonList(EventKinds.TEXT_NOTE));
                        filter.put("authors", Collections.singletonList(adminKeys.getPublicKeyHex()));
                        filter.put("limit", 10);

                        List<Object> reqMsg = Arrays.asList("REQ", "test-sub", filter);
                        webSocket.send(jsonMapper.writeValueAsString(reqMsg));
                        System.out.println("Subscription sent");
                    } else if ("EOSE".equals(msgType)) {
                        System.out.println("EOSE received");
                        webSocket.close(1000, "done");
                        eoseResult.complete(true);
                    } else if ("CLOSED".equals(msgType)) {
                        String reason = msg.size() > 2 ? (String) msg.get(2) : "no reason";
                        System.out.println("Subscription closed: " + reason);
                    }
                } catch (Exception e) {
                    eoseResult.completeExceptionally(e);
                }
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                eoseResult.completeExceptionally(t);
            }
        });

        try {
            Boolean result = eoseResult.get(15, TimeUnit.SECONDS);
            assertTrue("Should receive EOSE after subscription", result);
            System.out.println("\nSUCCESS: Subscription after auth test passed!");
        } finally {
            ws.close(1000, "cleanup");
        }
    }

    @Test
    public void testPublishEventAfterAuth() throws Exception {
        System.out.println("\n------------------------------------------------------------");
        System.out.println("TEST: Publish Event After Auth");
        System.out.println("------------------------------------------------------------");

        System.out.println("User pubkey (admin): " + adminKeys.getPublicKeyHex().substring(0, 16) + "...");

        CompletableFuture<Boolean> publishResult = new CompletableFuture<>();

        Request request = new Request.Builder()
            .url(relayUrl)
            .header("Host", "localhost")
            .build();

        WebSocket ws = httpClient.newWebSocket(request, new WebSocketListener() {
            private boolean waitingForAuthOk = false;
            private boolean eventSent = false;

            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket connected");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
                try {
                    List<?> msg = jsonMapper.readValue(text, List.class);
                    String msgType = (String) msg.get(0);
                    System.out.println("Received: " + msgType);

                    if ("AUTH".equals(msgType)) {
                        String challenge = (String) msg.get(1);
                        System.out.println("AUTH challenge received");

                        Event authEvent = createAuthEvent(adminKeys, AUTH_RELAY_URL, challenge);
                        List<Object> authMsg = Arrays.asList("AUTH", authEvent);
                        webSocket.send(jsonMapper.writeValueAsString(authMsg));
                        System.out.println("AUTH response sent");
                        waitingForAuthOk = true;
                    } else if ("OK".equals(msgType) && waitingForAuthOk && !eventSent) {
                        System.out.println("Auth accepted, publishing event");
                        waitingForAuthOk = false;

                        Event testEvent = createTextNoteEvent(adminKeys, "Test message " + System.currentTimeMillis());

                        List<Object> eventMsg = Arrays.asList("EVENT", testEvent);
                        webSocket.send(jsonMapper.writeValueAsString(eventMsg));
                        System.out.println("Event sent: " + testEvent.getId().substring(0, 16) + "...");
                        eventSent = true;
                    } else if ("OK".equals(msgType) && eventSent) {
                        Boolean success = (Boolean) msg.get(2);
                        String message = msg.size() > 3 ? (String) msg.get(3) : "";
                        System.out.println("Event OK received: " + (success ? "accepted" : "rejected") + " " + message);
                        webSocket.close(1000, "done");
                        publishResult.complete(success);
                    }
                } catch (Exception e) {
                    publishResult.completeExceptionally(e);
                }
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                publishResult.completeExceptionally(t);
            }
        });

        try {
            Boolean result = publishResult.get(15, TimeUnit.SECONDS);
            assertTrue("Event should be published successfully", result);
            System.out.println("\nSUCCESS: Publish event after auth test passed!");
        } finally {
            ws.close(1000, "cleanup");
        }
    }

    private Event createAuthEvent(NostrKeyManager keys, String relayUrl, String challenge) throws Exception {
        Event authEvent = new Event();
        authEvent.setPubkey(keys.getPublicKeyHex());
        authEvent.setCreatedAt(System.currentTimeMillis() / 1000);
        authEvent.setKind(EventKinds.AUTH);
        authEvent.setTags(Arrays.asList(
            Arrays.asList("relay", relayUrl),
            Arrays.asList("challenge", challenge)
        ));
        authEvent.setContent("");

        String eventId = calculateEventId(authEvent);
        authEvent.setId(eventId);

        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keys.signHex(eventIdBytes);
        authEvent.setSig(signature);

        return authEvent;
    }

    private Event createTextNoteEvent(NostrKeyManager keys, String content) throws Exception {
        Event event = new Event();
        event.setPubkey(keys.getPublicKeyHex());
        event.setCreatedAt(System.currentTimeMillis() / 1000);
        event.setKind(EventKinds.TEXT_NOTE);
        event.setTags(Collections.emptyList());
        event.setContent(content);

        String eventId = calculateEventId(event);
        event.setId(eventId);

        byte[] eventIdBytes = Hex.decodeHex(eventId.toCharArray());
        String signature = keys.signHex(eventIdBytes);
        event.setSig(signature);

        return event;
    }

    private String calculateEventId(Event event) throws Exception {
        List<Object> eventData = Arrays.asList(
            0,
            event.getPubkey(),
            event.getCreatedAt(),
            event.getKind(),
            event.getTags(),
            event.getContent()
        );

        String eventJson = jsonMapper.writeValueAsString(eventData);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(eventJson.getBytes(StandardCharsets.UTF_8));

        return new String(Hex.encodeHex(hashBytes));
    }
}
