# Unicity Nostr SDK

Java SDK for Nostr protocol integration with Unicity blockchain applications.

## Features

- **Token Transfers**: Send and receive Unicity tokens via Nostr
- **Nametag Bindings**: Map Unicity nametags to Nostr public keys
- **Encrypted Messaging**: NIP-04 encrypted direct messages with compression
- **Location Broadcasting**: Agent location discovery for P2P networks
- **Profile Management**: Standard Nostr profiles
- **Multi-Relay Support**: Connect to multiple Nostr relays simultaneously
- **Pure Java**: No JNI dependencies, works on Android and JVM

## Requirements

- Java 11 or higher
- Android API 31+ (for Android applications)

## Installation

### Gradle

```gradle
dependencies {
    implementation("org.unicitylabs:unicity-nostr-sdk:1.0.0")
}
```

### Maven

```xml
<dependency>
    <groupId>org.unicitylabs</groupId>
    <artifactId>unicity-nostr-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Quick Start

### Initialize Client

```java
// Create key manager from private key
byte[] privateKey = ...; // 32-byte private key
NostrKeyManager keyManager = NostrKeyManager.fromPrivateKey(privateKey);

// Create client
NostrClient client = new NostrClient(keyManager);

// Connect to relays
client.connect("wss://relay.example.com");
```

### Send Encrypted Message

```java
String recipientPubkey = "...";
String message = "Hello, Nostr!";

client.publishEncryptedMessage(recipientPubkey, message)
    .thenAccept(eventId -> {
        System.out.println("Message sent: " + eventId);
    });
```

### Subscribe to Events

```java
Filter filter = Filter.builder()
    .kinds(EventKinds.ENCRYPTED_DM)
    .pTags(keyManager.getPublicKeyHex())
    .build();

client.subscribe(filter, new NostrEventListener() {
    @Override
    public void onEvent(Event event) {
        System.out.println("Received event: " + event.id);
    }
});
```

### Token Transfers

```java
// Send token to recipient (by pubkey)
String recipientPubkey = "..."; // Nostr public key (hex)
String tokenJson = ...; // Unicity token transfer package JSON

client.sendTokenTransfer(recipientPubkey, tokenJson)
    .thenAccept(eventId -> {
        System.out.println("Token sent: " + eventId);
    });

// SDK automatically:
// - Adds "token_transfer:" prefix
// - Creates kind 31113 (TOKEN_TRANSFER) event
// - Encrypts with NIP-04
// - Compresses with GZIP (for payloads > 1KB)
// - Signs with Schnorr
```

### Nametag Bindings

```java
// Publish nametag binding
client.publishNametagBinding("alice@unicity", "0x123...")
    .thenAccept(success -> {
        System.out.println("Binding published: " + success);
    });

// Query pubkey by nametag
client.queryPubkeyByNametag("alice@unicity")
    .thenAccept(pubkey -> {
        System.out.println("Found pubkey: " + pubkey);
    });
```

## Architecture

The SDK is organized into several packages:

- `org.unicitylabs.nostr.client` - Main client and relay management
- `org.unicitylabs.nostr.protocol` - Nostr protocol structures (Event, Filter, EventKinds)
- `org.unicitylabs.nostr.crypto` - Cryptographic operations (Schnorr, NIP-04, Bech32, KeyManager)
- `org.unicitylabs.nostr.nametag` - Nametag binding protocol and privacy-preserving hashing
- `org.unicitylabs.nostr.token` - Token transfer protocol with compression

## Dependencies

- Apache Commons Codec (hex encoding)
- OkHttp (WebSocket connections)
- BouncyCastle (Schnorr signatures)
- Jackson (JSON serialization)
- libphonenumber (phone number normalization)
- SLF4J (logging)

## Key Features

### NIP-04 Encryption with GZIP Compression
Messages larger than 1KB are automatically compressed with GZIP, reducing token transfer sizes by ~70%.

### Android Compatible
Uses legacy Apache Commons Codec API for compatibility with Android's system framework.

### Event Kinds
- **4** - Encrypted Direct Message (NIP-04)
- **30078** - Nametag Binding (parameterized replaceable)
- **31113** - Token Transfer (Unicity custom)

## Notes

- Uses `Hex.encodeHex()` (legacy API) instead of `Hex.encodeHexString()` for Android compatibility
- WebSocket EOFException during disconnect is normal and logged at DEBUG level
- All crypto operations use BouncyCastle (pure Java, no JNI except secp256k1)

## License

MIT License
