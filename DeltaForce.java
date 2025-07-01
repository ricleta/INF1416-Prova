import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class DeltaForce {
    private static final String ALGORITHM = "AES";
    private static final String PADDING = "AES/CBC/PKCS5Padding";
    private static final String PRNG = "SHA1PRNG";
    private static final int KEY_SIZE = 128;

    private static String seed;
    private static String originalPlainText;
    private static byte[] encryptedText;


    public static void main(String[] args) throws Exception {

        if (args.length != 3) {
            System.out.println("Usage: java DeltaForce <seed> <originalPlainText> <encryptedTextHex>");
        }

        seed = args[0];

        originalPlainText = args[1];

        String encryptedTextHex = args[2];

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

    private static void bruteForceAttack() throws Exception
    {
        int i = 0;
        while(true) {
            System.out.println("Trying IV: " + i);

            String ivAscii = String.format("%016d", i);

            byte[] iv = ivAscii.getBytes();

            SecretKey secretKey = generateAESKey(seed);

            String decryptedText = decryptAES(encryptedText, secretKey, iv);

            if (decryptedText.contains(originalPlainText)) {
                System.out.println("Decrypted text found!");
                System.out.println("IV: " + ivAscii);
                System.out.println("Decrypted text: " + decryptedText);
                break;
            }

            i++;
        }
    }
}