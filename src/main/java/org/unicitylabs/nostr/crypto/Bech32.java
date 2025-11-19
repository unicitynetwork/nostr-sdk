package org.unicitylabs.nostr.crypto;

import java.util.Arrays;

/**
 * Bech32 encoding utility for Nostr keys (NIP-19).
 * Encodes keys as npub (public) and nsec (private).
 * See: https://github.com/nostr-protocol/nips/blob/master/19.md
 */
public class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /**
     * Encode data with Bech32.
     *
     * @param hrp Human-readable part (e.g., "npub", "nsec")
     * @param data Data bytes to encode
     * @return Bech32-encoded string
     */
    public static String encode(String hrp, byte[] data) {
        int[] values = convertBits(data, 8, 5, true);
        int[] checksum = createChecksum(hrp, values);
        int[] combined = new int[values.length + checksum.length];
        System.arraycopy(values, 0, combined, 0, values.length);
        System.arraycopy(checksum, 0, combined, values.length, checksum.length);

        StringBuilder result = new StringBuilder(hrp).append('1');
        for (int value : combined) {
            result.append(CHARSET.charAt(value));
        }
        return result.toString();
    }

    /**
     * Decode a Bech32 string.
     *
     * @param bech32 Bech32-encoded string
     * @return Pair of (hrp, data bytes)
     */
    public static DecodedBech32 decode(String bech32) {
        int pos = bech32.lastIndexOf('1');
        if (pos < 1) {
            throw new IllegalArgumentException("Invalid bech32 string");
        }

        String hrp = bech32.substring(0, pos).toLowerCase();
        String dataStr = bech32.substring(pos + 1);

        int[] data = new int[dataStr.length()];
        for (int i = 0; i < dataStr.length(); i++) {
            int idx = CHARSET.indexOf(Character.toLowerCase(dataStr.charAt(i)));
            if (idx < 0) {
                throw new IllegalArgumentException("Invalid character in bech32 string");
            }
            data[i] = idx;
        }

        if (!verifyChecksum(hrp, data)) {
            throw new IllegalArgumentException("Invalid checksum");
        }

        int[] values = Arrays.copyOf(data, data.length - 6);
        byte[] bytes = convertBits(values, 5, 8, false);

        return new DecodedBech32(hrp, bytes);
    }

    /**
     * Convert bits from one base to another.
     */
    private static int[] convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        int maxAcc = (1 << (fromBits + toBits - 1)) - 1;

        int[] result = new int[data.length * fromBits / toBits + (pad ? 1 : 0)];
        int resultIdx = 0;

        for (byte b : data) {
            int value = b & 0xFF;
            acc = ((acc << fromBits) | value) & maxAcc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result[resultIdx++] = (acc >> bits) & maxv;
            }
        }

        if (pad) {
            if (bits > 0) {
                result[resultIdx++] = (acc << (toBits - bits)) & maxv;
            }
        } else {
            if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
                throw new IllegalArgumentException("Invalid padding in convertBits");
            }
        }

        return Arrays.copyOf(result, resultIdx);
    }

    /**
     * Convert bits from one base to another (int array input).
     */
    private static byte[] convertBits(int[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        int maxAcc = (1 << (fromBits + toBits - 1)) - 1;

        byte[] result = new byte[data.length * fromBits / toBits + (pad ? 1 : 0)];
        int resultIdx = 0;

        for (int value : data) {
            acc = ((acc << fromBits) | value) & maxAcc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                result[resultIdx++] = (byte) ((acc >> bits) & maxv);
            }
        }

        if (pad) {
            if (bits > 0) {
                result[resultIdx++] = (byte) ((acc << (toBits - bits)) & maxv);
            }
        } else {
            if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
                throw new IllegalArgumentException("Invalid padding in convertBits");
            }
        }

        return Arrays.copyOf(result, resultIdx);
    }

    /**
     * Create Bech32 checksum.
     */
    private static int[] createChecksum(String hrp, int[] values) {
        int[] enc = new int[hrpExpand(hrp).length + values.length + 6];
        System.arraycopy(hrpExpand(hrp), 0, enc, 0, hrpExpand(hrp).length);
        System.arraycopy(values, 0, enc, hrpExpand(hrp).length, values.length);

        int mod = polymod(enc) ^ 1;
        int[] checksum = new int[6];
        for (int i = 0; i < 6; i++) {
            checksum[i] = (mod >> (5 * (5 - i))) & 31;
        }
        return checksum;
    }

    /**
     * Verify Bech32 checksum.
     */
    private static boolean verifyChecksum(String hrp, int[] values) {
        int[] enc = new int[hrpExpand(hrp).length + values.length];
        System.arraycopy(hrpExpand(hrp), 0, enc, 0, hrpExpand(hrp).length);
        System.arraycopy(values, 0, enc, hrpExpand(hrp).length, values.length);
        return polymod(enc) == 1;
    }

    /**
     * Expand HRP for checksum calculation.
     */
    private static int[] hrpExpand(String hrp) {
        int[] result = new int[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            result[i] = hrp.charAt(i) >> 5;
        }
        result[hrp.length()] = 0;
        for (int i = 0; i < hrp.length(); i++) {
            result[hrp.length() + 1 + i] = hrp.charAt(i) & 31;
        }
        return result;
    }

    /**
     * Compute Bech32 polymod.
     */
    private static int polymod(int[] values) {
        int[] gen = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        int chk = 1;
        for (int value : values) {
            int b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ value;
            for (int i = 0; i < 5; i++) {
                if (((b >> i) & 1) != 0) {
                    chk ^= gen[i];
                }
            }
        }
        return chk;
    }

    /**
     * Result of Bech32 decoding.
     */
    public static class DecodedBech32 {
        public final String hrp;
        public final byte[] data;

        public DecodedBech32(String hrp, byte[] data) {
            this.hrp = hrp;
            this.data = data;
        }
    }

    private Bech32() {
        // Utility class
    }
}
