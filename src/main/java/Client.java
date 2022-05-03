import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.UUID;

public class Client {

    private Socket socket = null;
    private String address;
    private int port;

    private KeyPair pair;

    public Client(String address,int port) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            pair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        this.address = address;
        this.port = port;
        try {
            socket = new Socket(address, port);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private void reconnectSocket() {
        if (this.socket.isClosed()) {
            try {
                this.socket = new Socket(this.address, this.port);
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }

    }

    public void sendRequest(String key, boolean toEncrypt, long fileSize,String hash) {
        DataClassMessage dataClass = new DataClassMessage(key,toEncrypt,fileSize);
        if(!hash.equals("")) dataClass.setHash(hash);
        try {
            serializeAndSend(dataClass);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void sendRequestSharedSecret(String key, boolean toEncrypt,long fileSize, String hash,int nPartsCreated,int nPartsNeeded) {
        DataClassMessage dataClass = new DataClassMessage(key,toEncrypt,fileSize);
        if(!hash.equals("")) dataClass.setHash(hash);
        dataClass.setSecretShare(true,nPartsCreated,nPartsNeeded);
        try {
            serializeAndSend(dataClass);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void sendFile(String path) throws IOException {
        File file =  new File(path);
        FileInputStream f = new FileInputStream(file);
        OutputStream bos = this.socket.getOutputStream();
        int bytesread = 0;
        byte[] buffer = new byte[1024*8];
        while((bytesread = f.read(buffer)) > 0) {
            bos.write(buffer,0,bytesread);
        }
        f.close();

    }

    private void serializeAndSend(Object dataClass) throws IOException {
        ObjectOutputStream os = new ObjectOutputStream(this.socket.getOutputStream());
        os.writeObject(dataClass);
    }

    private void receiveFinalInfo() throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ObjectInputStream is = new ObjectInputStream(this.socket.getInputStream());
        DataReportMessage dataReportMessage = (DataReportMessage) is.readObject();
        System.out.println("hash: " + dataReportMessage.getHash());
        System.out.println("key to decrypt: " + dataReportMessage.getKeyToDecrypt());
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
        byte[] keyToDecrypt = Base64.getDecoder().decode(dataReportMessage.getKeyToDecrypt());
        byte[] decryptedKey = decryptCipher.doFinal(keyToDecrypt);
        String keyToDecryptString = Base64.getEncoder().encodeToString(decryptedKey);
        System.out.println("key decrypted(RSA) to be used to decrypt: " + keyToDecryptString);
        this.socket.close();
    }

    private void encryptFile(String fileName,boolean sharedKey) {
        if(sharedKey) return;
        encryptFile(fileName, false,0,0);
    }
    private void encryptFile(String fileName,boolean sharedKey,int nPartsCreated, int nPartsNeeded) {
        File f = new File(fileName);
        long fileSizeL = (long)f.length();
        byte[] pubKey = pair.getPublic().getEncoded();
        String pubKeyB64 = Base64.getEncoder().encodeToString(pubKey);
        if(sharedKey){
            sendRequestSharedSecret(pubKeyB64,true,fileSizeL,"",nPartsCreated,nPartsNeeded);
        }else {
            sendRequest(pubKeyB64,true,fileSizeL,"");
        }
        try {
            sendFile("toenc.txt");
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }
        try {
            receiveFinalInfo();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private void participateInSharedSecret(String hash) {
        byte[] pubKey = pair.getPublic().getEncoded();
        String pubKeyB64 = Base64.getEncoder().encodeToString(pubKey);
        sendRequestSharedSecret(pubKeyB64,true,0,hash,0,0);
        try {
            receiveFinalInfo();
        }catch (Exception e) {
            System.out.println("Error participating in shared secret");
        }
    }

    private String receiveFile() throws IOException {
        String filename = UUID.randomUUID().toString();
        File tmp = new File(filename);
        FileOutputStream f = new FileOutputStream(tmp);
        InputStream inputStream = this.socket.getInputStream();
        byte[] content = new byte[1024*8];
        int bytesreceived = 0;
        while((bytesreceived = inputStream.read(content,0,content.length)) > 0) {
            f.write(content,0,bytesreceived);
        }
        f.close();
        return filename;
    }
    private String decryptFile(String hash,String key) {
        sendRequest(key,false,0 ,hash);
        try{
            return receiveFile();
        } catch (IOException e) {
            System.out.println("Error receiving decrypted file");

        }
        return "";
    }

    public static int menu(Scanner input) {
        int selection;


        /***************************************************/

        System.out.println("Choose from these choices");
        System.out.println("-------------------------\n");
        System.out.println("1 - Encrypt");
        System.out.println("2 - Decrypt");
        System.out.println("3 - Encrypt with shared secret");
        System.out.println("4 - Join member of shared secret(Encrypt)");
        System.out.println("5 - Join member of shared secret(Decrypt)");
        System.out.println("6 - Quit");

        selection = input.nextInt();
        return selection;
    }



    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Client c = new Client("127.0.0.1",8000);
        Scanner input = new Scanner(System.in);
        boolean quit = false;
        while(!quit) {
            c.reconnectSocket();
            int choice = menu(input);
            switch (choice){
                case 1:
                    c.encryptFile("toenc.txt",false);
                    break;
                case 2:
                    System.out.print("Hash: ");
                    input.nextLine();
                    String hash = input.nextLine();
                    System.out.print("Key: ");
                    String key = input.nextLine();
                    String filename = c.decryptFile(hash,key);
                    System.out.println("File decrypted to: " + filename );
                    break;
                case 3:
                    System.out.print("Parts Created: ");
                    input.nextLine();
                    int partsCreated = input.nextInt();
                    System.out.print("Parts Needed: ");
                    input.nextLine();
                    int partsNeeded = input.nextInt();
                    c.encryptFile("toenc.txt",true,partsCreated,partsNeeded);
                    break;
                case 4:
                    System.out.print("Hash: ");
                    input.nextLine();
                    String hashSharedSecret = input.nextLine();
                    c.participateInSharedSecret(hashSharedSecret);
                    break;
                case 5:
                    System.out.print("Hash: ");
                    input.nextLine();
                    String hash1 = input.nextLine();
                    System.out.print("Key: ");
                    String key1 = input.nextLine();
                    c.decryptFile(hash1,key1);
                    break;
                default:
                    quit = true;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
