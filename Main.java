import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Main {

    private static int counter = 0;
    private static int kps_counter = 0;
    private static int kps = 0;
    private static long ts = System.currentTimeMillis();
    private static long ts2 = System.currentTimeMillis();
    private static String essid;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        BufferedReader passwords = new BufferedReader(new FileReader(args[3]));
        essid = args[1];
        File pcap_file = new File(args[4]);

        boolean run = true;

        HandshakeData handshakeData = get_handshake_data(essid, pcap_file);

        while (run) {

            run = cycle(passwords, handshakeData);
        }
    }

    private static HandshakeData get_handshake_data(String essid, File pcap_file) throws IOException {
        HandshakeData handshakeData = new HandshakeData();
        handshakeData.amac = new byte[6];
        handshakeData.smac = new byte[6];
        handshakeData.anonce = new byte[32];
        handshakeData.snonce = new byte[32];
        handshakeData.mic = new byte[16];

        boolean beacon = false;
        boolean handshake1 = false;
        boolean handshake2 = false;

        byte[] pcap_bytes = Files.readAllBytes(pcap_file.toPath());

        for (int i = 0; i < pcap_bytes.length; i++) {
            if (pcap_bytes[i] == (byte) 0x80 && pcap_bytes[i + 1] == (byte) 0x00 && !beacon) {
                String test_essid = "";
                int essid_length = pcap_bytes[i + 37];
                for (int j = 0; j < essid_length; j++) {
                    test_essid += (char) pcap_bytes[i + 38 + j];
                }
                if (test_essid.equals(essid)) {
                    for (int k = 0; k < 6; k++) {
                        handshakeData.amac[k] = pcap_bytes[i + 10 + k];
                    }
                    beacon = true;
                }
            }
            if (pcap_bytes[i] == (byte) 0x88 && pcap_bytes[i + 1] == (byte) 0x02 && !handshake1) {
                byte[] test_amac = new byte[6];
                for (int j = 0; j < 6; j++) {
                    test_amac[j] = pcap_bytes[i + 10 + j];
                }
                if (Arrays.equals(test_amac, handshakeData.amac)) {
                    for (int k = 0; k < 6; k++) {
                        handshakeData.smac[k] = pcap_bytes[i + 4 + k];
                    }
                    for (int k = 0; k < 32; k++) {
                        handshakeData.anonce[k] = pcap_bytes[i + 51 + k];
                    }
                    handshake1 = true;
                }
            }
            if (pcap_bytes[i] == (byte) 0x88 && pcap_bytes[i + 1] == (byte) 0x01 && beacon && handshake1 && !handshake2) {
                byte[] test_amac = new byte[6];
                byte[] test_smac = new byte[6];
                for (int j = 0; j < 6; j++) {
                    test_amac[j] = pcap_bytes[i + 4 + j];
                }
                for (int j = 0; j < 6; j++) {
                    test_smac[j] = pcap_bytes[i + 10 + j];
                }
                if (Arrays.equals(test_amac, handshakeData.amac) && Arrays.equals(test_smac, handshakeData.smac)) {
                    for (int k = 0; k < 32; k++) {
                        handshakeData.snonce[k] = pcap_bytes[i + 51 + k];
                    }
                    for (int k = 0; k < 16; k++) {
                        handshakeData.mic[k] = pcap_bytes[i + 115 + k];
                        pcap_bytes[i + 115 + k] = (byte) 0x00;
                    }
                    handshakeData.data = new byte[99 + pcap_bytes[i + 34 + 98]];
                    for (int k = 0; k < 99; k++) {
                        handshakeData.data[k] = pcap_bytes[i + 34 + k];
                    }
                    for (int k = 0; k < (int) handshakeData.data[98]; k++) {
                        handshakeData.data[k+99] = pcap_bytes[i + 35 + 98 + k];
                    }
                    handshake2 = true;
                } else {
                    handshake1 = false;
                }
            }
            if (beacon && handshake1 && handshake2) {
                break;
            }
        }
        return handshakeData;
    }

    private static byte[] calculate_pmk(String password, String essid) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int pass_length = password.length();
        int essid_length = essid.length();
        char[] pass_char = new char[pass_length];
        char[] essid_char = new char[essid_length];
        byte[] essid_bytes = new byte[essid_length];

        for (int i = 0; i < pass_length; i++) {
            pass_char[i] = password.charAt(i);
        }
        for (int i = 0; i < essid_length; i++) {
            essid_char[i] = essid.charAt(i);
        }
        for (int i = 0; i < essid_length; i++) {
            essid_bytes[i] = (byte) essid_char[i];
        }
        return hashPassword(pass_char, essid_bytes, 4096, 256);
    }

    private static boolean cycle(BufferedReader passwords, HandshakeData handshakeData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        String password = passwords.readLine();
        if (password == null) {
            System.out.println("\nKey not in dictionary!");
            System.exit(0);
        }
        counter += 1;
        byte[] pmk = calculate_pmk(password, essid);
        byte[] ptk = calculate_ptk(handshakeData.amac, handshakeData.smac, handshakeData.anonce, handshakeData.snonce, pmk);
        byte[] mic = calculate_mic(ptk, handshakeData.data);

        if (System.currentTimeMillis() - ts >= 1000) {
            kps = counter - kps_counter;
            kps_counter = counter;
            ts = System.currentTimeMillis();
        }

        if (System.currentTimeMillis() - ts2 >= 50) {
            System.out.println(String.format("\nKeys tested: %d (%d k/s)", counter, kps));
            System.out.println("Current Passphrase: " + password);
            System.out.println("Master Key: " + bytes_to_hex(pmk));
            System.out.println("Transient Key: " + bytes_to_hex(ptk));
            System.out.println("Message Integrity Check: " + bytes_to_hex(mic));
            ts2 = System.currentTimeMillis();
        }

        if (Arrays.equals(mic, handshakeData.mic)) {
            System.out.println(String.format("\nKeys tested: %d (%d k/s)", counter, kps));
            System.out.println("Current Passphrase: " + password);
            System.out.println("Master Key: " + bytes_to_hex(pmk));
            System.out.println("Transient Key: " + bytes_to_hex(ptk));
            System.out.println("Message Integrity Check: " + bytes_to_hex(mic));
            System.out.println("\nKey Found! [ " + password + " ]");
            return false;
        }
        return true;
    }

    private static byte[] hashPassword(char[] password, byte[] salt, int iterations, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey key = skf.generateSecret(spec);
        return key.getEncoded();
    }

    private static byte[] hashHMAC(byte[] key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec spec = new SecretKeySpec(key, "HmacSHA1");
        mac.init(spec);
        return mac.doFinal(message);
    }

    private static byte[] calculate_ptk(byte[] amac, byte[] smac, byte[] anonce, byte[] snonce, byte[] pmk) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] ptk = new byte[80];
        byte[] pke_seed = {(byte) 0x50, (byte) 0x61, (byte) 0x69, (byte) 0x72, (byte) 0x77, (byte) 0x69, (byte) 0x73,
                (byte) 0x65, (byte) 0x20, (byte) 0x6b, (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x65, (byte) 0x78,
                (byte) 0x70, (byte) 0x61, (byte) 0x6e, (byte) 0x73, (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x00};
        byte[] pke = new byte[100];
        System.arraycopy(pke_seed, 0, pke, 0, 23);

        byte[] minmac = new byte[6];
        byte[] maxmac = new byte[6];
        byte[] minnonce = new byte[32];
        byte[] maxnonce = new byte[32];

        for (int i = 0; i < 6; i++) {
            int amaci = (int) amac[i] & 0xff;
            int smaci = (int) smac[i] & 0xff;

            if (amaci < smaci) {
                System.arraycopy(amac, 0, minmac, 0, 6);
                System.arraycopy(smac, 0, maxmac, 0, 6);
                break;
            }
            else if (amaci > smaci) {
                System.arraycopy(amac, 0, maxmac, 0, 6);
                System.arraycopy(smac, 0, minmac, 0, 6);
                break;
            }
        }
        for (int i = 0; i < 32; i++) {
            int anoncei = (int) anonce[i] & 0xff;
            int snoncei = (int) snonce[i] & 0xff;

            if (anoncei < snoncei) {
                System.arraycopy(anonce, 0, minnonce, 0, 32);
                System.arraycopy(snonce, 0, maxnonce, 0, 32);
                break;
            }
            else if (anoncei > snoncei) {
                System.arraycopy(anonce, 0, maxnonce, 0, 32);
                System.arraycopy(snonce, 0, minnonce, 0, 32);
                break;
            }
        }

        System.arraycopy(minmac, 0, pke, 23, 6);
        System.arraycopy(maxmac, 0, pke, 29, 6);
        System.arraycopy(minnonce, 0, pke, 35, 32);
        System.arraycopy(maxnonce, 0, pke, 67, 32);
        pke[99] = (byte) 0x00;

        for (int i = 0; i < 4; i++) {
            pke[99] = (byte) i;
            System.arraycopy(hashHMAC(pmk, pke), 0, ptk, i*20, 20);
        }

        return ptk;
    }

    private static byte[] calculate_mic(byte[] ptk, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] short_ptk = new byte[16];
        byte[] mic;
        byte[] short_mic = new byte[16];

        System.arraycopy(ptk, 0, short_ptk, 0, 16);
        mic = hashHMAC(short_ptk, data);
        System.arraycopy(mic, 0, short_mic, 0, 16);

        return short_mic;
    }

    private static String bytes_to_hex(byte[] bytes) {
        String hexstring = "";
        int[] values = new int[bytes.length];
        for (int i = 0; i < values.length; i++) {
            values[i] = (int) bytes[i] & 0xff;
        }
        for (int i = 0; i < values.length; i++) {
            if (values[i] < 16) {
                hexstring += "0";
            }
            hexstring += Integer.toHexString(values[i]);
            if (i < values.length - 1) {
                hexstring += " ";
            }
        }
        return hexstring;
    }
}
