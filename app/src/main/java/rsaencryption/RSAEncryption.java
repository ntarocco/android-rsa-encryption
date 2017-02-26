package rsaencryption;

import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class RSAEncryption {

    public static final String RSA_ALGORITHM = "RSA";
    public static final String CIPHER_RSA_WITH_PADDING = "RSA/NONE/OAEPWithSHA256AndMGF1Padding";
    public static final String PROVIDER = "BC";
    public static final int BASE64_FLAG = Base64.DEFAULT;

    /**
     * Encrypt a string with RSA using a public key and handling base64 decoding/encoding
     *
     * @param publicKeyBase64 the public key base64 encoded
     * @param inputData       the data to encrypt
     * @return the data encrypted and base64 encoded
     */
    public byte[] encrypt(byte[] publicKeyBase64, String inputData) throws InvalidKeySpecException, NoSuchAlgorithmException,
            BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {

        byte[] publicKeyBytes = Base64.decode(publicKeyBase64, BASE64_FLAG);

        PublicKey publicKey = getPublicKey(publicKeyBytes);
        byte[] encrypted = encrypt(publicKey, inputData);

        return Base64.encode(encrypted, BASE64_FLAG);
    }

    /**
     * Encrypt a string with RSA using a public key
     *
     * @param publicKey the public key
     * @param inputData the data to encrypt
     * @return the data encrypted
     */
    private byte[] encrypt(PublicKey publicKey, String inputData) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = getEncryptionCipher(publicKey);

        byte[] messageBytes = inputData.getBytes();
        return cipher.doFinal(messageBytes, 0, messageBytes.length);
    }

    /**
     * Create and return the encryption cipher
     */
    private Cipher getEncryptionCipher(PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_RSA_WITH_PADDING, PROVIDER);
        cipher.init(ENCRYPT_MODE, publicKey);
        return cipher;
    }

    /**
     * Create and return the PublicKey object from the public key bytes
     */
    private PublicKey getPublicKey(byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(keySpec);
    }
}
