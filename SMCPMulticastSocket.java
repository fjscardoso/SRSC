import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.util.encoders.Base64Encoder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class SMCPMulticastSocket extends MulticastSocket {

    private static final byte VERSION = 0x00;
    private static final byte MSGTYPE = 0x01;
    private static final String cipherMode = "AES/ECB/PKCS5Padding";


    protected String sId;
    protected int counter = 0;

    protected List<Integer> nounces;

    private static final int MAX_SIZE = 65536;

    Key key;
    Key HMacKey;
    Cipher cipher;

    public SMCPMulticastSocket(int port, String sId) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CertificateException, UnrecoverableKeyException {
        super(port);
        this.sId = sId;
        nounces = new ArrayList<Integer>();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        cipher = Cipher.getInstance(cipherMode, "BC");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        FileInputStream stream = new FileInputStream("mykeystore.jceks");
        keyStore.load(stream, "password".toCharArray());

        key = keyStore.getKey("mykey1", "password".toCharArray());
        HMacKey = keyStore.getKey("mykey2", "password".toCharArray());
    }

    public void send(DatagramPacket packet) throws IOException {

        try {

            byte[] securePayload = securePayload(packet);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outputStream);

            dataStream.write(VERSION);
            dataStream.writeUTF(sId);
            dataStream.write(MSGTYPE);
            dataStream.writeUTF(buildSAttr());
            dataStream.writeInt(securePayload.length);
            dataStream.write(securePayload);
            dataStream.write(buildFastSecureMCheck(outputStream.toByteArray()));
            packet.setData(outputStream.toByteArray());
            packet.setLength(outputStream.size());

            super.send(packet);
            System.out.println("manda a mensagem");

        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    private String buildSAttr() throws NoSuchAlgorithmException {

        String sAttr = sId  + "/sessionName/" + cipherMode + "SHA-256" + "HMacSHA1";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        return Base64.getEncoder().encodeToString(digest.digest(sAttr.getBytes()));

    }

    @Override
    public void receive(DatagramPacket packet) throws IOException {

        try{
        DatagramPacket p = new DatagramPacket(new byte[MAX_SIZE], MAX_SIZE);

        super.receive(p);
        System.out.println("recebe a mensagem");



        DataInputStream istream2 =
                new DataInputStream(new ByteArrayInputStream(p.getData(),
                        0, p.getLength()));


        if(VERSION != istream2.read())
            throw new RuntimeException();

        if(!sId.equals(istream2.readUTF()))
            throw new RuntimeException();

        if(MSGTYPE != istream2.read())
            throw new RuntimeException();

        if(!istream2.readUTF().equals(buildSAttr()))
            throw new RuntimeException();

        int sizeSecurePayload = istream2.readInt();
        byte[] encrypted = new byte[sizeSecurePayload];

        istream2.readFully(encrypted, 0, sizeSecurePayload);

        byte[] fastSecureMCheck = new byte[istream2.available()];
        istream2.readFully(fastSecureMCheck, 0, istream2.available());

        byte[] completeMessage = Arrays.copyOfRange(p.getData(), 0, p.getLength() - fastSecureMCheck.length);

        if(Arrays.equals(fastSecureMCheck, buildFastSecureMCheck(completeMessage)))

        // Decifrar
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedSecurePayload = cipher.doFinal(encrypted);

            DataInputStream istream =
                    new DataInputStream(new ByteArrayInputStream(decryptedSecurePayload,
                            0, decryptedSecurePayload.length));


            int c = istream.readInt();
            if(c != counter)
                throw new RuntimeException();

            int nounce = istream.readInt();

            //for(int i = 0; i < nounces.size(); i++)
            //    System.out.println(nounces.get(i));

            if(!nounces.contains(nounce))
                nounces.add(nounce);
            else
                throw new RuntimeException();


            int size = istream.readInt();
            byte[] plainText = new byte[size];
            istream.readFully(plainText, 0, size);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(plainText);

            byte[] hashFromMessage = new byte[istream.available()];
            istream.readFully(hashFromMessage, 0, istream.available());

            if(!Arrays.equals(hash, hashFromMessage))
                throw new RuntimeException();



            packet.setData(plainText);
            packet.setLength(size);

            packet.setAddress(p.getAddress());
            packet.setPort(p.getPort());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }


    }

    private byte[] securePayload(DatagramPacket packet) throws IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException {


/**        DataInputStream istream =
                new DataInputStream(new ByteArrayInputStream(packet.getData(),
                        packet.getOffset(), packet.getLength()));

        long magic = istream.readLong();
        int opCode = istream.readInt();

*/
        counter++;
        int nounce = new SecureRandom().nextInt(99999);
        byte[] plainText = Arrays.copyOf(packet.getData(), packet.getLength());
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(plainText);

        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(msg);
        dataStream.writeInt(counter);
        dataStream.writeInt(nounce);
        dataStream.writeInt(plainText.length);
        dataStream.write(plainText);
        dataStream.write(hash);

        // Cifrar
        cipher.init(Cipher.ENCRYPT_MODE, key);


        byte[] cipherText = cipher.doFinal(msg.toByteArray());
        ByteArrayOutputStream full = new ByteArrayOutputStream();
        full.write(cipherText);

        return full.toByteArray();

    }

    public byte[] buildFastSecureMCheck(byte[] bytes) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        Mac hMac = Mac.getInstance("HMacSHA1", "BC");
        hMac.init(HMacKey);

        return hMac.doFinal(bytes);

    }


}
