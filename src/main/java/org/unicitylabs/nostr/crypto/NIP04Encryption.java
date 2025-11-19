package org.unicitylabs.nostr.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * NIP-04 encryption for Nostr direct messages.
 * Implements AES-256-CBC encryption with ECDH key agreement.
 * Includes GZIP compression for large payloads (e.g., token transfers).
 * See: https://github.com/nostr-protocol/nips/blob/master/04.md
 */
public class NIP04Encryption {

    private static final ECNamedCurveParameterSpec CURVE_PARAMS = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final ECPoint G = CURVE_PARAMS.getG();

    // Compression threshold: compress messages larger than 1KB
    private static final int COMPRESSION_THRESHOLD = 1024;

    // Compression marker in content
    private static final String COMPRESSION_PREFIX = "gz:";

    /**
     * Encrypt a message for a recipient using NIP-04.
     * Automatically compresses large messages (>1KB).
     *
     * @param message Plaintext message
     * @param myPrivateKey Sender's 32-byte private key
     * @param theirPublicKey Recipient's 32-byte x-only public key
     * @return Encrypted content in format: base64(ciphertext)?iv=base64(iv) or gz:base64(compressed)?iv=base64(iv)
     */
    public static String encrypt(String message, byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        // Derive shared secret
        byte[] sharedSecret = deriveSharedSecret(myPrivateKey, theirPublicKey);

        // Convert message to bytes
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        // Compress if message is large
        boolean compressed = false;
        if (messageBytes.length > COMPRESSION_THRESHOLD) {
            messageBytes = compress(messageBytes);
            compressed = true;
        }

        // Generate random IV (16 bytes)
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // Encrypt with AES-256-CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(messageBytes);

        // Format: base64(encrypted)?iv=base64(iv) or gz:base64(encrypted)?iv=base64(iv)
        String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);

        String result = encryptedBase64 + "?iv=" + ivBase64;
        if (compressed) {
            result = COMPRESSION_PREFIX + result;
        }

        return result;
    }

    /**
     * Decrypt a NIP-04 encrypted message.
     * Automatically decompresses if message was compressed.
     *
     * @param encryptedContent Encrypted content from Nostr event
     * @param myPrivateKey Recipient's 32-byte private key
     * @param theirPublicKey Sender's 32-byte x-only public key
     * @return Decrypted plaintext message
     */
    public static String decrypt(String encryptedContent, byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        // Check if compressed
        boolean compressed = encryptedContent.startsWith(COMPRESSION_PREFIX);
        if (compressed) {
            encryptedContent = encryptedContent.substring(COMPRESSION_PREFIX.length());
        }

        // Parse encrypted content
        String[] parts = encryptedContent.split("\\?iv=");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted message format");
        }

        byte[] encrypted = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);

        // Derive shared secret
        byte[] sharedSecret = deriveSharedSecret(myPrivateKey, theirPublicKey);

        // Decrypt with AES-256-CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);

        // Decompress if needed
        if (compressed) {
            decrypted = decompress(decrypted);
        }

        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Derive shared secret using ECDH (Elliptic Curve Diffie-Hellman).
     * Shared secret = SHA-256(ECDH(myPrivateKey, theirPublicKey).x)
     *
     * @param myPrivateKey My 32-byte private key
     * @param theirPublicKey Their 32-byte x-only public key
     * @return 32-byte shared secret
     */
    public static byte[] deriveSharedSecret(byte[] myPrivateKey, byte[] theirPublicKey) throws Exception {
        if (myPrivateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        if (theirPublicKey.length != 32) {
            throw new IllegalArgumentException("Public key must be 32 bytes");
        }

        // Convert their x-only public key to full public key (assume even y)
        BigInteger theirX = new BigInteger(1, theirPublicKey);
        ECPoint theirPoint = reconstructPublicKey(theirX);

        // Perform ECDH: sharedPoint = theirPublicKey * myPrivateKey
        BigInteger myD = new BigInteger(1, myPrivateKey);
        ECPoint sharedPoint = theirPoint.multiply(myD).normalize();

        // Extract X coordinate from shared point
        byte[] sharedX = sharedPoint.getAffineXCoord().toBigInteger().toByteArray();

        // Pad/trim to 32 bytes
        if (sharedX.length > 32) {
            sharedX = Arrays.copyOfRange(sharedX, sharedX.length - 32, sharedX.length);
        } else if (sharedX.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(sharedX, 0, padded, 32 - sharedX.length, sharedX.length);
            sharedX = padded;
        }

        // Hash the shared X coordinate to get final shared secret
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(sharedX);
    }

    /**
     * Reconstruct full public key point from x-coordinate (assume even y).
     *
     * @param x X coordinate
     * @return Full EC point
     */
    private static ECPoint reconstructPublicKey(BigInteger x) {
        // y^2 = x^3 + 7 (mod p) for secp256k1
        BigInteger p = CURVE_PARAMS.getCurve().getField().getCharacteristic();
        BigInteger y2 = x.modPow(BigInteger.valueOf(3), p).add(BigInteger.valueOf(7)).mod(p);

        // y = sqrt(y2) = y2^((p+1)/4) (mod p) - works for p ≡ 3 (mod 4)
        BigInteger y = y2.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);

        // Choose even y (BIP-340 convention)
        if (y.testBit(0)) {
            y = p.subtract(y);
        }

        return CURVE_PARAMS.getCurve().createPoint(x, y);
    }

    /**
     * Compress data using GZIP.
     *
     * @param data Raw data
     * @return Compressed data
     */
    private static byte[] compress(byte[] data) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(data);
        }
        return baos.toByteArray();
    }

    /**
     * Decompress GZIP data.
     *
     * @param compressed Compressed data
     * @return Decompressed data
     */
    private static byte[] decompress(byte[] compressed) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(compressed);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPInputStream gzis = new GZIPInputStream(bais)) {
            byte[] buffer = new byte[4096];
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
        }
        return baos.toByteArray();
    }

    private NIP04Encryption() {
        // Utility class
    }
}
