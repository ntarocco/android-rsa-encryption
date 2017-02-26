package rsaencryption;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;

import com.google.gson.Gson;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import rsaencryption.bouncycastletest.R;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class MainActivity extends AppCompatActivity {

    private static final String PUBLIC_KEY_BASE64_ENCODED = "INSERT HERE";
    private static final String PRIVATE_KEY_BASE64_ENCODED = "INSERT HERE";

    private final Gson gson = new Gson();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        byte[] privateKey = Base64.decode(PRIVATE_KEY_BASE64_ENCODED, RSAEncryption.BASE64_FLAG);

        try {

            PayLoadRequest request = new PayLoadRequest(
                    "first field",
                    "你好我叫精你好 你好我叫精你好"
            );

            System.out.println("-------------------------------------------------------------------------------------------------------------");
            System.out.println("JSON");
            System.out.println(gson.toJson(request));
            System.out.println("-------------------------------------------------------------------------------------------------------------");

            byte[] base64EncryptedMessage = new RSAEncryption().encrypt(PUBLIC_KEY_BASE64_ENCODED.getBytes(), gson.toJson(request));
            String base64EncryptedMessageString = new String(base64EncryptedMessage);

            System.out.println("ENCRYPTED MESSAGE BASE64");
            System.out.print(base64EncryptedMessageString);
            System.out.println("/END ENCRYPTED MESSAGE BASE64");

            System.out.println("-------------------------------------------------------------------------------------------------------------");
            byte[] decryptedMessage = decryptString(privateKey, base64EncryptedMessageString);
            System.out.println("DECRYPTED MESSAGE: " + new String(decryptedMessage));
            System.out.println("-------------------------------------------------------------------------------------------------------------");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] decryptString(byte[] privateKeyBytes, String base64EncryptedMessageString) throws BadPaddingException, IllegalBlockSizeException,
            NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {

        PrivateKey privateKey = getPrivateKey(privateKeyBytes);

        Cipher cipher = getDecryptionCipher(privateKey);

        byte[] encryptedMessageBytes = Base64.decode(base64EncryptedMessageString, RSAEncryption.BASE64_FLAG);
        return cipher.doFinal(encryptedMessageBytes, 0, encryptedMessageBytes.length);
    }

    private Cipher getDecryptionCipher(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeyException {
        Cipher cipher = Cipher.getInstance(RSAEncryption.CIPHER_RSA_WITH_PADDING, RSAEncryption.PROVIDER);
        cipher.init(DECRYPT_MODE, privateKey);
        return cipher;
    }

    private PrivateKey getPrivateKey(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSAEncryption.RSA_ALGORITHM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(keySpec);
    }
}
