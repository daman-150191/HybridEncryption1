package org.example;


/*
Crypto Project - Hybrid Encryption 1 - Damanpreet Kaur and Gargi Sehguri
*/

/* Sources

https://www.baeldung.com/java-aes-encryption-decryption
https://www.baeldung.com/java-rsa
http://cse-212294.cse.chalmers.se/courses/crypto/pa/setup/java/CubeRoot.java

*/
import org.apache.commons.codec.binary.Hex;
import javax.crypto.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static String encrypt(String algorithm, String input, SecretKey key
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key
    ) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeySpecException {
        CubeRoot cb = new CubeRoot();
        System.out.println("\n ****************** AES ************************");

        SecretKey key = generateKey(128);
        String secretMessage = String.format("%s", Hex.encodeHexString(key.getEncoded()));
        System.out.println("Key "+secretMessage);

        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the input string");
        String input = sc.nextLine();
        String algorithm = "AES/ECB/PKCS5Padding";
        String cipherText = encrypt(algorithm, input, key);
        String plainText = decrypt(algorithm, cipherText, key);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        String ciphertext_hexString = Hex.encodeHexString(decoded);
        System.out.println("AES CipherText (in HEX) - "+ciphertext_hexString);
        System.out.println("AES Decrypted PlainText (in String) - "+plainText);


        // RSA Based encryption and Decryption
        System.out.println("\n ****************** RSA ************************");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        RSAKeyGenParameterSpec kpgSpec = new RSAKeyGenParameterSpec(512, BigInteger.valueOf(3));
        kpg.initialize(kpgSpec);
        KeyPair pair = kpg.genKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        RSAPublicKey pub = (RSAPublicKey) publicKey;

        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        String encoded_hexString = Hex.encodeHexString(encryptedMessageBytes);
        System.out.println("RSA algo encoded (IN HEX)- "+encoded_hexString);

        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        System.out.println("RSA algo decoded (IN HEX)- "+decryptedMessage);



        /*
        RSA using plain text form where Cipher = (Plain^e) mod n and Plain= (Cipher^d) mod N

        Since Plaintext is 128 bit key with max value 0xffffffffffffffffffffffffffffffff which is less than the cube_root(N) making mod N unnecessary w
        with exponent as 3.
        */
        System.out.println("\n ****************** RSA using plain method ************************");

        BigInteger message = new BigInteger(Hex.encodeHexString((key.getEncoded())), 16);
        BigInteger modulo = new BigInteger(String.valueOf(pub.getModulus()), 16);
        BigInteger plain_RSA = (message.multiply(message).multiply(message)).mod(modulo);
        System.out.println("CipherText for key RSA plain form (in HEX) - "+Hex.encodeHexString(plain_RSA.toByteArray()));
        System.out.println("PlainText for key RSA (in HEX) - "+Hex.encodeHexString(cb.cbrt(plain_RSA).mod(modulo).toByteArray()));


    }
}
class CubeRoot {

    static public BigInteger cbrt(BigInteger val) {
        return root(3, new BigDecimal(val)).toBigInteger();
    }


    static private BigDecimal root(final int n, final BigDecimal x) {
        if (x.compareTo(BigDecimal.ZERO) < 0) {
            throw new ArithmeticException("negative argument " + x.toString()
                    + " of root");
        }
        if (n <= 0) {
            throw new ArithmeticException("negative power " + n + " of root");
        }
        if (n == 1) {
            return x;
        }
        BigDecimal s = new BigDecimal(Math.pow(x.doubleValue(), 1.0 / n));

        final BigDecimal nth = new BigDecimal(n);

        final BigDecimal xhighpr = scalePrec(x, 2);
        MathContext mc = new MathContext(2 + x.precision());

        final double eps = x.ulp().doubleValue() / (2 * n * x.doubleValue());
        for (;;) {

            BigDecimal c = xhighpr.divide(s.pow(n - 1), mc);
            c = s.subtract(c);
            MathContext locmc = new MathContext(c.precision());
            c = c.divide(nth, locmc);
            s = s.subtract(c);
            if (Math.abs(c.doubleValue() / s.doubleValue()) < eps) {
                break;
            }
        }
        return s.round(new MathContext(err2prec(eps)));
    }


    static private BigDecimal scalePrec(final BigDecimal x, int d) {
        return x.setScale(d + x.scale());
    }

    static private int err2prec(double xerr) {
        return 1 + (int) (Math.log10(Math.abs(0.5 / xerr)));
    }

}
