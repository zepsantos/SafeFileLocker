import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

public class ServerWorker implements Runnable{
    private Socket socket = null;
    private String public_key = null;
    private DS ds = null;
    public ServerWorker(Socket sock) {
        try {
            this.socket = sock;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    @Override
    public void run() {
        try {
            InputStream tmp = this.socket.getInputStream();
            ObjectInputStream ois = new ObjectInputStream(tmp);
            DataClassMessage dc = (DataClassMessage) ois.readObject();
            DataReportMessage reportMessage = null;
            String filename = receiveFile(dc.getFileSize());
            String hash = dc.getHash();
            DS ds = DS.getInstance();
            if (dc.isToEncrypt()) {
                //Encrypt
                byte[] keyToDecrypt = null;
                byte[] pub_key = Base64.getDecoder().decode(dc.getKey());
                if(filename != null) {
                    Object[] opExec = FileOperations.HashFileAndEncrypt(filename);

                    hash = (String) opExec[0];
                    keyToDecrypt = (byte[]) opExec[1];
                    filename = (String) opExec[2];
                    DataClass dataclass = new DataClass(hash,filename);
                    ds.addToDataClassHashMap(dataclass);
                }


                if(dc.isSecretShared()) {
                    if (filename != null) {
                        System.out.println("Key before Split: " + Base64.getEncoder().encodeToString(keyToDecrypt));
                        keyToDecrypt = ds.splitSecret(hash,dc.getnPartsCreated(),dc.getnPartsNeeded(),keyToDecrypt);
                        DataClass tmpdataClass = ds.getFromDataClassHashMap(hash);
                        tmpdataClass.setSecretShare(true,dc.getnPartsCreated(),dc.getnPartsNeeded());
                    }else {
                        keyToDecrypt = ds.popFromSecretManagerAKey(hash);
                    }
                }
                if(keyToDecrypt != null) {
                    String tmpKey = Base64.getEncoder().encodeToString(keyToDecrypt);
                    System.out.println("Chave para verificar: " + tmpKey);
                    String encryptedKeyToDecrypt = RSAEncryptKey(pub_key, keyToDecrypt);
                    reportMessage = new DataReportMessage(hash,encryptedKeyToDecrypt);
                } else {
                    reportMessage = new DataReportMessage(hash,null);
                    reportMessage.setStatus(2);
                }
                sendReport(reportMessage);
            } else {
                //Decrypt
                byte[] key = Base64.getDecoder().decode(dc.getKey());
                hash = dc.getHash();
                DataClass encryptedData = ds.getFileNameByHash(hash);
                filename = null;
                if(encryptedData.isSecretShared()) {
                    key = ds.joinSecrets(hash,key);
                }
                if(key != null) {
                    filename = FileOperations.decryptFile(encryptedData.getFilePath(),key);
                    sendFile(filename);
                }
            }



        } catch (IOException | ClassNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchPaddingException |
                 IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }


    }

    private String RSAEncryptKey(byte[] pubkey, byte[] keyToDecrypt) {
        try {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubkey);
            PublicKey pb = keyFactory.generatePublic(publicKeySpec);
            encryptCipher.init(Cipher.ENCRYPT_MODE, pb);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(keyToDecrypt);
            return Base64.getEncoder().encodeToString(encryptedMessageBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
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
        file.delete();


    }

    private void sendReport(DataReportMessage reportMessage) {
        try {
            serializeAndSend(reportMessage);
        } catch (Exception e) {
            System.out.println("Failed to send report with hash + key");
        } finally {
            try {
                this.socket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void serializeAndSend(Object dataClass) throws IOException {
        ObjectOutputStream os = new ObjectOutputStream(this.socket.getOutputStream());
        os.writeObject(dataClass);
    }
    private String receiveFile(long fileSize) throws IOException {
        if(fileSize == 0) return null;
        String filename = UUID.randomUUID().toString();
        File tmp = new File(filename);
        FileOutputStream f = new FileOutputStream(tmp);
        InputStream inputStream = this.socket.getInputStream();
        byte[] content = new byte[1024*8];
        int bytesreceived = 0;
        while((bytesreceived = inputStream.read(content,0,Math.min((int)fileSize,content.length))) > 0) {
            fileSize -= bytesreceived;
            f.write(content,0,bytesreceived);
        }
        f.close();
        return filename;
    }


}
