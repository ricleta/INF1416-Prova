import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import java.util.concurrent.*;
public class DeltaForce {
    private static final String ALGORITHM = "AES";
    private static final String PADDING = "AES/CBC/PKCS5Padding";
    private static final String PRNG = "SHA1PRNG";
    private static final int KEY_SIZE = 128;

    private static String seed;
    private static String originalPlainText;
    private static byte[] encryptedText;
    private static final int NUM_THREADS = Runtime.getRuntime().availableProcessors(); // Use available processors
    private static volatile boolean found = false; // Flag to stop other threads once found
    private static SecretKey secretKey;

    public static void main(String[] args) throws Exception {

        if (args.length != 3) {
            System.out.println("Usage: java DeltaForce <seed> <originalPlainText> <encryptedTextHex>");
        }

        System.out.println("NUM_THREADS = " + NUM_THREADS);

        seed = args[0];

        originalPlainText = args[1];

        String encryptedTextHex = args[2];
        secretKey = generateAESKey(seed);

        try {
            encryptedText = hexStringToByteArray(encryptedTextHex);
            bruteForceAttack();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SecretKey generateAESKey(String seed) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        SecureRandom secureRandom = SecureRandom.getInstance(PRNG);

        secureRandom.setSeed(seed.getBytes(StandardCharsets.UTF_8));
        keyGenerator.init(KEY_SIZE, secureRandom);
        return keyGenerator.generateKey();
    }

    private static String decryptAES(byte[] encryptedText, SecretKey secretKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedText);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    private static void bruteForceAttack() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(NUM_THREADS);
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < NUM_THREADS; i++) {
            final int threadId = i;
            executor.submit(() -> {
                long currentIV = threadId;
                while (!found) {
                    try {
                        // Check if the current IV is too large for String.format
                        // This is a simple safeguard, a more robust solution might involve BigInteger for IV
                        if (currentIV > 9999999999999999L) { // Max value for 16 digits
                            System.err.println("IV value too large for 16-digit format. Stopping thread " + threadId);
                            break;
                        }

                        String ivAscii = String.format("%016d", currentIV);
                        byte[] iv = ivAscii.getBytes(StandardCharsets.UTF_8); // Specify UTF-8 for consistency

                        String decryptedText = decryptAES(encryptedText, secretKey, iv);

                        if (decryptedText.contains(originalPlainText)) {
                            if (!found) { // Double-check to avoid multiple prints
                                synchronized (DeltaForce.class) { // Synchronize to ensure only one thread prints and sets found
                                    if (!found) {
                                        found = true;
                                        long endTime = System.currentTimeMillis();
                                        System.out.println("Decrypted text found by thread " + threadId + "!");
                                        System.out.println("IV: " + ivAscii);
                                        System.out.println("Decrypted text: " + decryptedText);
                                        System.out.println("Time taken: " + (endTime - startTime) + " ms");
                                    }
                                }
                            }
                        }
                        currentIV += NUM_THREADS; // Increment by NUM_THREADS to distribute work
                    } catch (Exception e) {
                        // Log the exception but don't stop the entire application
                        System.err.println("Error in thread " + threadId + " at IV " + currentIV + ": " + e.getMessage());
                        // Optionally, increment currentIV to skip the problematic value
                        currentIV += NUM_THREADS;
                    }
                }
            });
        }

        executor.shutdown();
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS); // Wait for all tasks to complete or found
    }
}