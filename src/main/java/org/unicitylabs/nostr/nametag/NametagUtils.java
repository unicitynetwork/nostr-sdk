package org.unicitylabs.nostr.nametag;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;

/**
 * Utility class for deterministic nametag hashing.
 * This ensures privacy and allows phone numbers to be used as nametags.
 *
 * <p>Examples:
 * <ul>
 * <li>Regular nametag: "alice" → hash("unicity:nametag:alice")</li>
 * <li>Phone as nametag: "+14155552671" → hash("unicity:nametag:+14155552671")</li>
 * </ul>
 *
 * <p>This way phone numbers can BE nametags naturally!
 */
public class NametagUtils {

    /**
     * Private constructor to prevent instantiation.
     */
    private NametagUtils() {
    }

    private static final String NAMETAG_SALT = "unicity:nametag:";
    private static final String ADDRESS_SALT = "unicity:address:";
    private static final PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

    /** Minimum nametag length (after normalization). */
    public static final int NAMETAG_MIN_LENGTH = 3;

    /** Maximum nametag length (after normalization). */
    public static final int NAMETAG_MAX_LENGTH = 20;

    /**
     * Hash a nametag for privacy-preserving storage on Nostr.
     * Works for both regular nametags and phone numbers.
     *
     * @param nametag The nametag string (e.g., "alice" or "+14155552671")
     * @param defaultCountry Default country code for phone normalization (e.g., "US")
     * @return Hex-encoded SHA-256 hash of the nametag
     */
    public static String hashNametag(String nametag, String defaultCountry) {
        // Normalize the nametag
        String normalized = normalizeNametag(nametag, defaultCountry);

        // Hash with salt
        String input = NAMETAG_SALT + normalized;
        return sha256(input);
    }

    /**
     * Hash a nametag with default country "US".
     *
     * @param nametag the nametag to hash
     * @return hex-encoded SHA-256 hash of the nametag
     */
    public static String hashNametag(String nametag) {
        return hashNametag(nametag, "US");
    }

    /**
     * Normalize a nametag before hashing.
     * - If it looks like a phone number, normalize to E.164
     * - Otherwise, lowercase and trim
     *
     * @param nametag The raw nametag
     * @param defaultCountry Default country for phone normalization
     * @return Normalized nametag
     */
    public static String normalizeNametag(String nametag, String defaultCountry) {
        String trimmed = nametag.trim();

        // Check if it looks like a phone number
        if (isLikelyPhoneNumber(trimmed)) {
            // Try to normalize as phone
            String normalized = normalizePhoneNumber(trimmed, defaultCountry);
            if (normalized != null) {
                return normalized;
            }
            // If phone normalization fails, fall through to standard normalization
        }

        // For regular nametags: lowercase, remove @unicity suffix
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.endsWith("@unicity")) {
            return lower.substring(0, lower.length() - 8);
        }
        return lower;
    }

    /**
     * Normalize a phone number to E.164 format.
     *
     * @param phoneNumber Phone number in any format
     * @param defaultCountry Default country code (e.g., "US")
     * @return E.164 formatted phone number or null if invalid
     */
    private static String normalizePhoneNumber(String phoneNumber, String defaultCountry) {
        String cleaned = phoneNumber.trim();
        if (cleaned.isEmpty()) {
            return null;
        }

        try {
            Phonenumber.PhoneNumber parsedNumber;
            if (cleaned.startsWith("+")) {
                // Already has country code
                parsedNumber = phoneUtil.parse(cleaned, null);
            } else {
                // Use default country for local numbers
                parsedNumber = phoneUtil.parse(cleaned, defaultCountry);
            }

            // Validate the parsed number
            if (!phoneUtil.isValidNumber(parsedNumber)) {
                return null;
            }

            // Format to E.164 (e.g., +14155552671)
            return phoneUtil.format(parsedNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
        } catch (NumberParseException e) {
            // Invalid phone number format
            return null;
        }
    }

    /**
     * Check if a string looks like a phone number.
     * Simple heuristic: starts with + or has >50% digits
     */
    private static boolean isLikelyPhoneNumber(String str) {
        if (str.startsWith("+")) {
            return true;
        }

        int digitCount = 0;
        for (char c : str.toCharArray()) {
            if (Character.isDigit(c)) {
                digitCount++;
            }
        }

        int totalCount = str.length();
        // More than 50% digits and at least 7 digits total
        return digitCount >= 7 && (float) digitCount / totalCount > 0.5f;
    }

    /**
     * Compute SHA-256 hash of a string.
     * Public so other classes (e.g., NametagBinding) can use it for d-tag generation.
     *
     * @param input Input string
     * @return Hex-encoded hash
     */
    public static String sha256Hex(String input) {
        return sha256(input);
    }

    /**
     * Hash an address for use as an indexed relay tag.
     * Enables reverse lookup: address to binding event.
     *
     * @param address Address string (e.g., DIRECT://..., alpha1..., PROXY://...)
     * @return Hex-encoded SHA-256 hash
     */
    public static String hashAddressForTag(String address) {
        return sha256(ADDRESS_SALT + address);
    }

    /**
     * Encrypt a nametag with AES-GCM using a key derived from the private key via HKDF.
     * Enables nametag recovery on wallet import.
     *
     * @param nametag Plain text nametag
     * @param privateKeyHex Hex-encoded private key for key derivation
     * @return Base64-encoded encrypted data (IV + ciphertext + auth tag)
     * @throws Exception if encryption fails
     */
    public static String encryptNametag(String nametag, String privateKeyHex) throws Exception {
        byte[] key = deriveNametagEncryptionKey(privateKeyHex);
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        byte[] data = nametag.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] encrypted = cipher.doFinal(data);

        // Combine IV + ciphertext (includes auth tag)
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypt a nametag encrypted with encryptNametag().
     *
     * @param encryptedBase64 Base64-encoded encrypted data (IV + ciphertext + auth tag)
     * @param privateKeyHex Hex-encoded private key for key derivation
     * @return Decrypted nametag, or null if decryption fails (wrong key)
     */
    public static String decryptNametag(String encryptedBase64, String privateKeyHex) {
        try {
            byte[] key = deriveNametagEncryptionKey(privateKeyHex);
            byte[] combined = Base64.getDecoder().decode(encryptedBase64);

            byte[] iv = new byte[12];
            System.arraycopy(combined, 0, iv, 0, 12);
            byte[] ciphertext = new byte[combined.length - 12];
            System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Derive an AES-256 encryption key from a private key using HKDF-SHA256.
     * Must match the TypeScript implementation exactly:
     * - IKM = hex-decoded private key bytes
     * - Salt = SHA256("sphere-nametag-salt")
     * - Info = "nametag-encryption"
     * - Output = 32 bytes
     */
    private static byte[] deriveNametagEncryptionKey(String privateKeyHex) {
        byte[] privateKeyBytes = hexToBytes(privateKeyHex);
        byte[] saltInput = "sphere-nametag-salt".getBytes(StandardCharsets.UTF_8);

        // SHA256 the salt input (matching TS: sha256(saltInput))
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] salt = digest.digest(saltInput);

            byte[] info = "nametag-encryption".getBytes(StandardCharsets.UTF_8);

            // HKDF using BouncyCastle
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(privateKeyBytes, salt, info));
            byte[] derivedKey = new byte[32];
            hkdf.generateBytes(derivedKey, 0, 32);
            return derivedKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Convert hex string to byte array.
     */
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    /**
     * Compute SHA-256 hash of a string.
     *
     * @param input Input string
     * @return Hex-encoded hash
     */
    private static String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Check if two nametags resolve to the same hash.
     * Useful for comparing different formats of the same identifier.
     *
     * @param tag1 First nametag
     * @param tag2 Second nametag
     * @param defaultCountry Default country code
     * @return true if both hash to the same value
     */
    public static boolean areSameNametag(String tag1, String tag2, String defaultCountry) {
        return hashNametag(tag1, defaultCountry).equals(hashNametag(tag2, defaultCountry));
    }

    /**
     * Format a nametag for display purposes.
     * Hides middle digits for phone numbers.
     *
     * @param nametag The nametag
     * @param defaultCountry Default country code
     * @return Display-friendly version
     */
    public static String formatForDisplay(String nametag, String defaultCountry) {
        String normalized = normalizeNametag(nametag, defaultCountry);

        // Check if it's a phone number
        if (isLikelyPhoneNumber(normalized)) {
            // Hide middle digits: +1415***2671
            if (normalized.length() >= 10) {
                String start = normalized.substring(0, 5);
                String end = normalized.substring(normalized.length() - 4);
                return start + "***" + end;
            }
        }

        // Regular nametag - return normalized
        return normalizeNametag(nametag, defaultCountry);
    }

    /**
     * Check if a string is a valid phone number.
     *
     * @param str            String to check
     * @param defaultCountry Default country code (e.g., "US")
     * @return true if the string is a valid phone number
     */
    public static boolean isPhoneNumber(String str, String defaultCountry) {
        try {
            Phonenumber.PhoneNumber parsed;
            if (str.startsWith("+")) {
                parsed = phoneUtil.parse(str, null);
            } else {
                parsed = phoneUtil.parse(str, defaultCountry);
            }
            return phoneUtil.isValidNumber(parsed);
        } catch (NumberParseException e) {
            return false;
        }
    }

    /**
     * Check if a string is a valid phone number (default country "US").
     *
     * @param str String to check
     * @return true if the string is a valid phone number
     */
    public static boolean isPhoneNumber(String str) {
        return isPhoneNumber(str, "US");
    }

    /**
     * Validate a nametag string. Strips leading @, normalizes, then checks format.
     * Regular nametags: lowercase alphanumeric, underscore, hyphen, 3-20 chars.
     * Phone numbers: validated via libphonenumber.
     *
     * @param nametag        Nametag to validate
     * @param defaultCountry Default country code for phone normalization
     * @return true if the nametag is valid
     */
    public static boolean isValidNametag(String nametag, String defaultCountry) {
        String stripped = nametag.startsWith("@") ? nametag.substring(1) : nametag;
        String normalized = normalizeNametag(stripped, defaultCountry);

        if (isPhoneNumber(normalized)) {
            return true;
        }

        return normalized.matches(
                "^[a-z0-9_-]{" + NAMETAG_MIN_LENGTH + "," + NAMETAG_MAX_LENGTH + "}$"
        );
    }

    /**
     * Validate a nametag string (default country "US").
     *
     * @param nametag Nametag to validate
     * @return true if the nametag is valid
     */
    public static boolean isValidNametag(String nametag) {
        return isValidNametag(nametag, "US");
    }
}