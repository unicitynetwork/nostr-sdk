package org.unicitylabs.nostr.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * BIP-340 Schnorr signatures for Nostr using BouncyCastle (pure Java, no JNI).
 * See: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 */
public class SchnorrSigner {

    private static final ECNamedCurveParameterSpec CURVE_PARAMS = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final BigInteger N = CURVE_PARAMS.getN();
    private static final ECPoint G = CURVE_PARAMS.getG();

    /**
     * Derive x-only public key from private key (32 bytes).
     * BIP-340: Returns x-coordinate of P where P.y is even.
     *
     * @param privateKey 32-byte private key
     * @return 32-byte x-only public key
     */
    public static byte[] getPublicKey(byte[] privateKey) {
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        BigInteger d = new BigInteger(1, privateKey);
        ECPoint P = G.multiply(d).normalize();

        // BIP-340: x-only pubkey is x-coordinate of P (implicitly even y)
        byte[] x = P.getAffineXCoord().toBigInteger().toByteArray();
        return padTo32Bytes(x);
    }

    /**
     * Sign a message using BIP-340 Schnorr.
     *
     * @param message 32-byte message to sign
     * @param privateKey 32-byte private key
     * @return 64-byte signature (R.x || s)
     */
    public static byte[] sign(byte[] message, byte[] privateKey) throws Exception {
        if (message.length != 32) {
            throw new IllegalArgumentException("Message must be 32 bytes");
        }
        if (privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }

        BigInteger d = new BigInteger(1, privateKey);
        ECPoint P = G.multiply(d).normalize();

        // BIP-340: If P.y is odd, use negated private key
        if (P.getAffineYCoord().toBigInteger().testBit(0)) {
            d = N.subtract(d);
            P = G.multiply(d).normalize();
        }

        // Get x-only public key (P now has even y)
        byte[] px = padTo32Bytes(P.getAffineXCoord().toBigInteger().toByteArray());

        // Generate nonce k (deterministic from adjusted private key d and message)
        byte[] d_bytes = padTo32Bytes(d.toByteArray());
        byte[] k_bytes = taggedHash("BIP0340/nonce", concat(d_bytes, px, message));
        BigInteger k = new BigInteger(1, k_bytes).mod(N);

        if (k.equals(BigInteger.ZERO)) {
            throw new RuntimeException("Invalid k");
        }

        // Compute R = k*G
        ECPoint R = G.multiply(k).normalize();

        // Get R.x as 32 bytes (before potentially negating k)
        byte[] rx = padTo32Bytes(R.getAffineXCoord().toBigInteger().toByteArray());

        // BIP-340: If R.y is odd, negate k
        if (R.getAffineYCoord().toBigInteger().testBit(0)) {
            k = N.subtract(k);
        }

        // Compute challenge e = tagged_hash("BIP0340/challenge", R.x || P.x || message)
        byte[] e_bytes = taggedHash("BIP0340/challenge", concat(rx, px, message));
        BigInteger e = new BigInteger(1, e_bytes).mod(N);

        // Compute s = (k + e*d) mod n
        BigInteger s = k.add(e.multiply(d)).mod(N);

        // Return signature = R.x || s (64 bytes)
        byte[] sig = new byte[64];
        System.arraycopy(rx, 0, sig, 0, 32);
        byte[] s_bytes = padTo32Bytes(s.toByteArray());
        System.arraycopy(s_bytes, 0, sig, 32, 32);

        return sig;
    }

    /**
     * Verify a BIP-340 Schnorr signature.
     *
     * @param signature 64-byte signature
     * @param message 32-byte message
     * @param publicKey 32-byte x-only public key
     * @return true if signature is valid
     */
    public static boolean verify(byte[] signature, byte[] message, byte[] publicKey) {
        try {
            if (signature.length != 64) return false;
            if (message.length != 32) return false;
            if (publicKey.length != 32) return false;

            // Parse signature
            byte[] rx = Arrays.copyOfRange(signature, 0, 32);
            byte[] s_bytes = Arrays.copyOfRange(signature, 32, 64);
            BigInteger r = new BigInteger(1, rx);
            BigInteger s = new BigInteger(1, s_bytes);

            // Check r and s are in valid range
            if (r.compareTo(CURVE_PARAMS.getCurve().getField().getCharacteristic()) >= 0) return false;
            if (s.compareTo(N) >= 0) return false;

            // Compute challenge e
            byte[] e_bytes = taggedHash("BIP0340/challenge", concat(rx, publicKey, message));
            BigInteger e = new BigInteger(1, e_bytes).mod(N);

            // Reconstruct P from x-coordinate (assume even y)
            BigInteger px = new BigInteger(1, publicKey);
            ECPoint P = CURVE_PARAMS.getCurve().createPoint(px, getYCoordinate(px, false));

            // Compute R = s*G - e*P
            ECPoint R = G.multiply(s).add(P.multiply(e.negate())).normalize();

            // Check R.y is even and R.x matches r
            if (R.getAffineYCoord().toBigInteger().testBit(0)) return false;
            return R.getAffineXCoord().toBigInteger().equals(r);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get Y coordinate from X coordinate on secp256k1 curve.
     *
     * @param x X coordinate
     * @param isOdd true if Y should be odd, false if even
     * @return Y coordinate
     */
    private static BigInteger getYCoordinate(BigInteger x, boolean isOdd) {
        // y^2 = x^3 + 7 (mod p)
        BigInteger p = CURVE_PARAMS.getCurve().getField().getCharacteristic();
        BigInteger y2 = x.modPow(BigInteger.valueOf(3), p).add(BigInteger.valueOf(7)).mod(p);

        // y = y2^((p+1)/4) (mod p) - works for p ≡ 3 (mod 4)
        BigInteger y = y2.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);

        // Choose correct parity
        if (y.testBit(0) != isOdd) {
            y = p.subtract(y);
        }

        return y;
    }

    /**
     * Tagged hash as specified in BIP-340.
     */
    private static byte[] taggedHash(String tag, byte[] msg) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] tagHash = sha256.digest(tag.getBytes());
        sha256.reset();
        sha256.update(tagHash);
        sha256.update(tagHash);
        sha256.update(msg);
        return sha256.digest();
    }

    /**
     * Pad or trim byte array to exactly 32 bytes.
     */
    private static byte[] padTo32Bytes(byte[] bytes) {
        if (bytes.length == 32) {
            return bytes;
        }
        if (bytes.length > 32) {
            // Remove leading zeros
            return Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length);
        }
        // Pad with leading zeros
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
        return padded;
    }

    /**
     * Concatenate byte arrays.
     */
    private static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    private SchnorrSigner() {
        // Utility class
    }
}
