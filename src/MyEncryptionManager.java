import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class MyEncryptionManager {


    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    String calculateHMAC(String data, byte[] key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

        String HMAC_SHA256 = "HmacSHA256";
        Mac sha256_HMAC = Mac.getInstance(HMAC_SHA256);

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, HMAC_SHA256);
        sha256_HMAC.init(secretKeySpec);

        return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes()));
    }

    private SecretKey generateSymmetricKey(String password, int keySize, int hashIterations) throws GeneralSecurityException {

        // Creating a new instance of
        // SecureRandom class.
        SecureRandom securerandom
                = new SecureRandom();

        // Passing the string to
        // KeyGenerator
        KeyGenerator keygenerator
                = KeyGenerator.getInstance("AES");

        // Initializing the KeyGenerator
        // with 256 bits.
        keygenerator.init(256, securerandom);
        SecretKey key = keygenerator.generateKey();
        return key;

    }


    public KeyPair generateNewRsaKeys(int keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        return pair;
    }

    public KeyPair generateNewDiffieHelmanECKeys(int keySize) throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(keySize);
        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;

    }


    public SecretKey generateNewAesKey(int keySize) throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize); // for example
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;

    }


    public byte[] encryptWithRsa(PublicKey publicKey, byte[] secretMessageBytes) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(secretMessageBytes);
        return encryptedBytes;

    }

    public byte[] encryptWithRsa(PrivateKey privateKey, byte[] secretMessageBytes) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedBytes = cipher.doFinal(secretMessageBytes);
        return encryptedBytes;

    }

    public byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedMessageBytes) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessageBytes);
        return decryptedBytes;

    }

    public byte[] decryptWithRsa(PublicKey publicKey, byte[] encryptedMessageBytes) throws GeneralSecurityException {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessageBytes);
        return decryptedBytes;

    }

    public PublicKey getPublicKeyFromCertificateFile(String certificateFilePath) throws CertificateException, FileNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(certificateFilePath);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }


}