import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SMCPMulticastSocket extends MulticastSocket {

    int counter = 0;
    String username;

    private static final int MAX_SIZE = 65536;


    byte[]	keyBytes = new byte[] {
            0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef,
            0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab,(byte)0xcd, (byte)0xef
    };

    SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher;

    public SMCPMulticastSocket(int port, String username) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        super(port);
        this.username = username;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
    }

    public void send(DatagramPacket packet) throws IOException {

        try {
            byte[] securePayload = securePayload(packet);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(securePayload);

            packet.setData(outputStream.toByteArray());
            packet.setLength(outputStream.size());

            super.send(packet);

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {

        DatagramPacket p = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

        super.receive(p);

        byte[] encrypted = Arrays.copyOf(p.getData(), p.getLength());

        // Decifrar
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainText = cipher.doFinal(encrypted);

            packet.setData(Arrays.copyOf(plainText, MAX_SIZE));
            packet.setLength(plainText.length);

            packet.setAddress(p.getAddress());
            packet.setPort(p.getPort());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }


    }

    private byte[] securePayload(DatagramPacket packet) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        counter++;
        byte[] nonce = new byte[128];
        new SecureRandom().nextBytes(nonce);
        byte[] plainText = Arrays.copyOf(packet.getData(), packet.getLength());

        int hash = plainText.hashCode();

        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(username.getBytes());
        msg.write(counter);
        msg.write(nonce);
        msg.write(plainText);
        msg.write(hash);


        // Cifrar
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(msg.toByteArray());

        ByteArrayOutputStream full = new ByteArrayOutputStream();
        full.write(cipherText);

        return full.toByteArray();

    }


}
