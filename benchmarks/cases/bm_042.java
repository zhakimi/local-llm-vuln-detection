import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CardVault {
    private static final SecureRandom RNG = new SecureRandom();
    private final SecretKey key;

    public CardVault(SecretKey key) {
        this.key = key;
    }

    public byte[] encryptCardNumber(byte[] pan) throws Exception {
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(pan);
        return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
    }
}
