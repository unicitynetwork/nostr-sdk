package org.unicitylabs.nostr.crypto;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * NIP-44 encryption for Nostr private direct messages.
 * Implements XChaCha20-Poly1305 AEAD encryption with HKDF key derivation.
 * See: https://github.com/nostr-protocol/nips/blob/master/44.md
 */
public class NIP44Encryption {

    /** NIP-44 version byte */
    public static final byte VERSION = 0x02;

    /** Nonce size for XChaCha20 (24 bytes) */
    private static final int NONCE_SIZE = 24;

    /** MAC size for Poly1305 (16 bytes) */
    private static final int MAC_SIZE = 16;

    /** Minimum padded length */
    private static final int MIN_PADDED_LEN = 32;

    /** Maximum message length */
    private static final int MAX_MESSAGE_LEN = 65535;

    private static final ECNamedCurveParameterSpec CURVE_PARAMS = ECNamedCurveTable.getParameterSpec("secp256k1");

    private static final byte[] HKDF_SALT = "nip44-v2".getBytes(StandardCharsets.UTF_8);

    /**
     * Encrypt a message using NIP-44.
     *
     * @param message Plaintext message
     * @param myPrivateKey Sender's 32-byte private key
     * @param theirPublicKey Recipient's 32-byte x-only public key
     * @return Base64-encoded encrypted payload
     * @throws Exception if encryption fails
     */
    public static String encrypt(String message, byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        byte[] conversationKey = deriveConversationKey(myPrivateKey, theirPublicKey);
        return encryptWithKey(message, conversationKey);
    }

    /**
     * Encrypt a message using a pre-derived conversation key.
     *
     * @param message Plaintext message
     * @param conversationKey 32-byte conversation key
     * @return Base64-encoded encrypted payload
     * @throws Exception if encryption fails
     */
    public static String encryptWithKey(String message, byte[] conversationKey) throws Exception {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        if (messageBytes.length > MAX_MESSAGE_LEN) {
            throw new IllegalArgumentException("Message too long (max " + MAX_MESSAGE_LEN + " bytes)");
        }

        // Pad the message
        byte[] padded = pad(messageBytes);

        // Generate random nonce (24 bytes for XChaCha20)
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);

        // Derive message keys using HKDF
        byte[] messageKey = deriveMessageKey(conversationKey, nonce);
        byte[] chachaKey = Arrays.copyOfRange(messageKey, 0, 32);
        byte[] chachaNonce = Arrays.copyOfRange(messageKey, 32, 44);
        byte[] hmacKey = Arrays.copyOfRange(messageKey, 44, 76);

        // Encrypt with ChaCha20
        byte[] ciphertext = chacha20Encrypt(padded, chachaKey, chachaNonce);

        // Calculate HMAC (Poly1305-style authentication)
        byte[] mac = calculateMac(hmacKey, nonce, ciphertext);

        // Assemble payload: version(1) || nonce(24) || ciphertext || mac(16)
        byte[] payload = new byte[1 + NONCE_SIZE + ciphertext.length + MAC_SIZE];
        payload[0] = VERSION;
        System.arraycopy(nonce, 0, payload, 1, NONCE_SIZE);
        System.arraycopy(ciphertext, 0, payload, 1 + NONCE_SIZE, ciphertext.length);
        System.arraycopy(mac, 0, payload, 1 + NONCE_SIZE + ciphertext.length, MAC_SIZE);

        return Base64.getEncoder().encodeToString(payload);
    }

    /**
     * Decrypt a NIP-44 encrypted message.
     *
     * @param encryptedContent Base64-encoded encrypted payload
     * @param myPrivateKey Recipient's 32-byte private key
     * @param theirPublicKey Sender's 32-byte x-only public key
     * @return Decrypted plaintext message
     * @throws Exception if decryption fails
     */
    public static String decrypt(String encryptedContent, byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        byte[] conversationKey = deriveConversationKey(myPrivateKey, theirPublicKey);
        return decryptWithKey(encryptedContent, conversationKey);
    }

    /**
     * Decrypt a message using a pre-derived conversation key.
     *
     * @param encryptedContent Base64-encoded encrypted payload
     * @param conversationKey 32-byte conversation key
     * @return Decrypted plaintext message
     * @throws Exception if decryption fails
     */
    public static String decryptWithKey(String encryptedContent, byte[] conversationKey) throws Exception {
        byte[] payload = Base64.getDecoder().decode(encryptedContent);

        if (payload.length < 1 + NONCE_SIZE + MIN_PADDED_LEN + MAC_SIZE) {
            throw new IllegalArgumentException("Payload too short");
        }

        // Check version
        if (payload[0] != VERSION) {
            throw new IllegalArgumentException("Unsupported NIP-44 version: " + payload[0]);
        }

        // Extract components
        byte[] nonce = Arrays.copyOfRange(payload, 1, 1 + NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(payload, 1 + NONCE_SIZE, payload.length - MAC_SIZE);
        byte[] mac = Arrays.copyOfRange(payload, payload.length - MAC_SIZE, payload.length);

        // Derive message keys
        byte[] messageKey = deriveMessageKey(conversationKey, nonce);
        byte[] chachaKey = Arrays.copyOfRange(messageKey, 0, 32);
        byte[] chachaNonce = Arrays.copyOfRange(messageKey, 32, 44);
        byte[] hmacKey = Arrays.copyOfRange(messageKey, 44, 76);

        // Verify MAC
        byte[] expectedMac = calculateMac(hmacKey, nonce, ciphertext);
        if (!MessageDigest.isEqual(mac, expectedMac)) {
            throw new SecurityException("MAC verification failed");
        }

        // Decrypt with ChaCha20
        byte[] padded = chacha20Encrypt(ciphertext, chachaKey, chachaNonce); // ChaCha20 is symmetric

        // Unpad
        byte[] message = unpad(padded);

        return new String(message, StandardCharsets.UTF_8);
    }

    /**
     * Derive conversation key using ECDH + HKDF.
     * NIP-44 uses sorted public keys as salt for HKDF.
     *
     * @param myPrivateKey 32-byte private key
     * @param theirPublicKey 32-byte x-only public key
     * @return 32-byte conversation key
     * @throws Exception if key derivation fails
     */
    public static byte[] deriveConversationKey(byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        if (myPrivateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        if (theirPublicKey.length != 32) {
            throw new IllegalArgumentException("Public key must be 32 bytes");
        }

        // Perform ECDH to get shared X coordinate
        byte[] sharedX = computeSharedX(myPrivateKey, theirPublicKey);

        // Get my public key for salt derivation
        byte[] myPublicKey = SchnorrSigner.getPublicKey(myPrivateKey);

        // Create salt from sorted public keys
        byte[] salt = createSortedKeysSalt(myPublicKey, theirPublicKey);

        // Use HKDF to derive conversation key
        return hkdfExpand(sharedX, salt, HKDF_SALT, 32);
    }

    /**
     * Compute ECDH shared X coordinate.
     */
    private static byte[] computeSharedX(byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        // Reconstruct full public key point from x-coordinate
        BigInteger theirX = new BigInteger(1, theirPublicKey);
        ECPoint theirPoint = reconstructPublicKey(theirX);

        // Perform ECDH
        BigInteger myD = new BigInteger(1, myPrivateKey);
        ECPoint sharedPoint = theirPoint.multiply(myD).normalize();

        // Extract X coordinate
        byte[] sharedX = sharedPoint.getAffineXCoord().toBigInteger().toByteArray();

        // Normalize to 32 bytes
        if (sharedX.length > 32) {
            sharedX = Arrays.copyOfRange(sharedX, sharedX.length - 32, sharedX.length);
        } else if (sharedX.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(sharedX, 0, padded, 32 - sharedX.length, sharedX.length);
            sharedX = padded;
        }

        return sharedX;
    }

    /**
     * Reconstruct EC point from x-coordinate (assume even y).
     */
    private static ECPoint reconstructPublicKey(BigInteger x) {
        BigInteger p = CURVE_PARAMS.getCurve().getField().getCharacteristic();
        BigInteger y2 = x.modPow(BigInteger.valueOf(3), p).add(BigInteger.valueOf(7)).mod(p);
        BigInteger y = y2.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);

        // Choose even y (BIP-340 convention)
        if (y.testBit(0)) {
            y = p.subtract(y);
        }

        return CURVE_PARAMS.getCurve().createPoint(x, y);
    }

    /**
     * Create salt from lexicographically sorted public keys.
     */
    private static byte[] createSortedKeysSalt(byte[] pk1, byte[] pk2) {
        // Compare public keys lexicographically
        int cmp = compareBytes(pk1, pk2);

        byte[] salt = new byte[64];
        if (cmp <= 0) {
            System.arraycopy(pk1, 0, salt, 0, 32);
            System.arraycopy(pk2, 0, salt, 32, 32);
        } else {
            System.arraycopy(pk2, 0, salt, 0, 32);
            System.arraycopy(pk1, 0, salt, 32, 32);
        }
        return salt;
    }

    /**
     * Compare two byte arrays lexicographically.
     */
    private static int compareBytes(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int cmp = (a[i] & 0xFF) - (b[i] & 0xFF);
            if (cmp != 0) return cmp;
        }
        return a.length - b.length;
    }

    /**
     * HKDF-SHA256 key derivation.
     */
    private static byte[] hkdfExpand(byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(ikm, salt, info));
        byte[] output = new byte[length];
        hkdf.generateBytes(output, 0, length);
        return output;
    }

    /**
     * Derive message key from conversation key and nonce.
     */
    private static byte[] deriveMessageKey(byte[] conversationKey, byte[] nonce) {
        // message_key = HKDF-expand(conversation_key, nonce, 76)
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(conversationKey, nonce, new byte[0]));
        byte[] output = new byte[76];
        hkdf.generateBytes(output, 0, 76);
        return output;
    }

    /**
     * ChaCha20 encryption (XOR-based, works for both encrypt and decrypt).
     */
    private static byte[] chacha20Encrypt(byte[] input, byte[] key, byte[] nonce) {
        ChaCha7539Engine engine = new ChaCha7539Engine();
        engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));

        byte[] output = new byte[input.length];
        engine.processBytes(input, 0, input.length, output, 0);
        return output;
    }

    /**
     * Calculate HMAC-SHA256 for authentication.
     */
    private static byte[] calculateMac(byte[] key, byte[] nonce, byte[] ciphertext) throws Exception {
        // AAD = nonce
        // MAC = HMAC-SHA256(key, AAD || ciphertext)
        MessageDigest hmac = MessageDigest.getInstance("SHA-256");

        // Create HMAC using key
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        Arrays.fill(ipad, (byte) 0x36);
        Arrays.fill(opad, (byte) 0x5c);

        byte[] keyPadded = new byte[64];
        if (key.length > 64) {
            byte[] keyHash = MessageDigest.getInstance("SHA-256").digest(key);
            System.arraycopy(keyHash, 0, keyPadded, 0, keyHash.length);
        } else {
            System.arraycopy(key, 0, keyPadded, 0, key.length);
        }

        byte[] ipadKey = new byte[64];
        byte[] opadKey = new byte[64];
        for (int i = 0; i < 64; i++) {
            ipadKey[i] = (byte) (keyPadded[i] ^ ipad[i]);
            opadKey[i] = (byte) (keyPadded[i] ^ opad[i]);
        }

        // Inner hash: SHA256(ipadKey || nonce || ciphertext)
        hmac.reset();
        hmac.update(ipadKey);
        hmac.update(nonce);
        hmac.update(ciphertext);
        byte[] innerHash = hmac.digest();

        // Outer hash: SHA256(opadKey || innerHash)
        hmac.reset();
        hmac.update(opadKey);
        hmac.update(innerHash);
        byte[] mac = hmac.digest();

        // Return first 16 bytes (truncated to match Poly1305 output size)
        return Arrays.copyOf(mac, MAC_SIZE);
    }

    /**
     * Pad message according to NIP-44 spec (power-of-2 padding).
     * Format: length(2 bytes big-endian) || message || padding
     */
    public static byte[] pad(byte[] message) {
        int len = message.length;
        if (len < 1) {
            throw new IllegalArgumentException("Message too short");
        }
        if (len > MAX_MESSAGE_LEN) {
            throw new IllegalArgumentException("Message too long");
        }

        int paddedLen = calcPaddedLen(len);

        // Create padded buffer: 2-byte length prefix + padded content
        byte[] result = new byte[2 + paddedLen];

        // Big-endian length prefix
        result[0] = (byte) ((len >> 8) & 0xFF);
        result[1] = (byte) (len & 0xFF);

        // Copy message
        System.arraycopy(message, 0, result, 2, len);

        // Remaining bytes are already zero (padding)

        return result;
    }

    /**
     * Unpad message according to NIP-44 spec.
     */
    public static byte[] unpad(byte[] padded) {
        if (padded.length < 2 + MIN_PADDED_LEN) {
            throw new IllegalArgumentException("Padded message too short");
        }

        // Read big-endian length prefix
        int len = ((padded[0] & 0xFF) << 8) | (padded[1] & 0xFF);

        if (len < 1 || len > MAX_MESSAGE_LEN) {
            throw new IllegalArgumentException("Invalid message length: " + len);
        }

        int expectedPaddedLen = calcPaddedLen(len);
        if (padded.length != 2 + expectedPaddedLen) {
            throw new IllegalArgumentException("Invalid padding");
        }

        return Arrays.copyOfRange(padded, 2, 2 + len);
    }

    /**
     * Calculate padded length according to NIP-44 spec.
     * Uses power-of-2 chunk padding to hide message length.
     */
    public static int calcPaddedLen(int unpaddedLen) {
        if (unpaddedLen <= 0) {
            throw new IllegalArgumentException("Message too short");
        }
        if (unpaddedLen > MAX_MESSAGE_LEN) {
            throw new IllegalArgumentException("Message too long");
        }

        if (unpaddedLen <= 32) {
            return 32;
        }

        // Find next power of 2
        int nextPow2 = Integer.highestOneBit(unpaddedLen - 1) << 1;
        int chunk = Math.max(32, nextPow2 / 8);

        return ((unpaddedLen + chunk - 1) / chunk) * chunk;
    }

    private NIP44Encryption() {
        // Utility class
    }
}
