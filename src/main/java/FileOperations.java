import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.jcajce.provider.digest.MD5;
import org.bouncycastle.jcajce.provider.digest.SHA512;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import static org.bouncycastle.jcajce.provider.symmetric.util.PBE.MD5;

public class FileOperations {

    public FileOperations( ) {

    }

    /**
     * Recebe uma stream onde vai receber o ficheiro , gera o hash e encripta o ficheiro com o nome do hash
     * @param
     * @return
     * @throws IOException
     */
    public static Object[] HashFileAndEncrypt(String filename) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException {
        File tempFile = new File(filename);
        FileInputStream fileInputStream = new FileInputStream(tempFile);
        MessageDigest messageDigest = new MD5.Digest();
        DigestInputStream digestInputStream = new DigestInputStream(fileInputStream,messageDigest);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
        byte[] ivarr = new byte[16];
        new SecureRandom().nextBytes(ivarr);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        IvParameterSpec iv =  new IvParameterSpec(ivarr);
        cipher.init(Cipher.ENCRYPT_MODE,key,iv);
        int bytesread = 0;
        byte[] buffer = new byte[1024*8];
        String lockedPath = UUID.randomUUID().toString();
        File cipFile = new File(lockedPath);
        FileOutputStream outputStream = new FileOutputStream(cipFile);
        System.out.println("Locked FILE: " + lockedPath);
        while((bytesread=digestInputStream.read(buffer,0, buffer.length)) != -1) {
            byte[] cipherMessageBlock = cipher.update(buffer,0,bytesread);
            outputStream.write(cipherMessageBlock);
        }
        digestInputStream.close();
        outputStream.close();
        boolean status = tempFile.delete();
        if(!status) {
            System.out.println("Couldn't delete temporary file from server");
        }

        byte[] digest = digestInputStream.getMessageDigest().digest();
        String hash = Base64.getEncoder().encodeToString(digest);
        byte[] keybytes = key.getEncoded();
        byte[] ivbytes = iv.getIV();
        byte[] keywiv= new byte[keybytes.length + ivbytes.length];
        System.arraycopy(keybytes,0,keywiv,0,keybytes.length);
        System.arraycopy(ivbytes,0,keywiv,keybytes.length,ivbytes.length);
        Object[] a = new Object[3];
        a[0] = hash;
        a[1] = keywiv;
        a[2] = lockedPath;
        return a;
    }

    public static String decryptFile(String filename,byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        byte[] keywiv = key;
        byte[] keybytes = Arrays.copyOfRange(keywiv,0,keywiv.length-16);
        byte[] ivbytes = Arrays.copyOfRange(keywiv,keybytes.length,keywiv.length);

        SecretKey secretKey = new SecretKeySpec(keybytes,"AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
        cipher.init(Cipher.DECRYPT_MODE,secretKey, new IvParameterSpec(ivbytes));

        String tmpPath = UUID.randomUUID().toString();
        System.out.println("Decrypting file with id : " + tmpPath);
        File cipFile = new File(filename);
        File tmpFile = new File(tmpPath);
        FileOutputStream outputStream = new FileOutputStream(tmpFile);
        try(FileInputStream inputStream = new FileInputStream(cipFile)) {
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream,cipher);
            int bytesRead = 0;
            byte[] buffer = new byte[(int)cipFile.length()];
            while((bytesRead=inputStream.read(buffer,0,buffer.length)) != -1) {
                cipherOutputStream.write(buffer,0,bytesRead);
            }
            cipherOutputStream.close();
        }
        if(tmpFile.length() > 0) {
            cipFile.delete();
        }
        return tmpPath;
    }




}
