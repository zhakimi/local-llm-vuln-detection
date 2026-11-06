import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CardVault {
    private final SecretKey key;

    public CardVault(SecretKey key) {
        this.key = key;
    }

    public byte[] encryptCardNumber(byte[] pan) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(pan);
    }
}
