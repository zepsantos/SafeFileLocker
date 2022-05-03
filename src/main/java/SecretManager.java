import com.codahale.shamir.Scheme;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.util.MessageDigestUtils;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SecretManager implements Serializable {
    private int partsNeeded = 0;
    private int partsCreated = 0;
    private Map<Integer,byte[]> parts;

    private Map<String,Integer> hashedIntegersForParts;
    private int partCounter = 0;
    private Queue<byte[]> partsAvailable;
    private String hash;
    private Scheme scheme;
    public SecretManager(String hash, int partsCreated,int partsNeeded) {
        this.hash = hash;
        this.partsNeeded = partsNeeded;
        this.partsCreated = partsCreated;
        this.partsAvailable = new ConcurrentLinkedQueue<>();
        this.scheme = new Scheme(new SecureRandom(),partsCreated,partsNeeded);
        this.parts = new HashMap<>();
        this.hashedIntegersForParts = new HashMap<>();
    }

    public boolean isReadyToDecrypt() {
        return this.parts.size() >= partsNeeded;
    }


    public String getHash() {
        return hash;
    }

    public void addPart(byte[] part) {
        Integer i = this.hashedIntegersForParts.get(calculateKeyDigest(part));
        if(i != null) this.parts.put(i,part);
    }

    public void splitSecret(byte[] keyToDecrypt) {
        Map<Integer, byte[]> parts = scheme.split(keyToDecrypt);
        for(Map.Entry<Integer,byte[]> e : parts.entrySet() ) {
            this.hashedIntegersForParts.put(calculateKeyDigest(e.getValue()),e.getKey());
            addToAvailablePartsQueue(e.getValue());
        }
    }


    private String calculateKeyDigest(byte[] part) {
        MessageDigest messageDigest = new SHA1.Digest();
        return Base64.getEncoder().encodeToString(messageDigest.digest(part));
    }

    private void addToAvailablePartsQueue(byte[] part ) {
        this.partsAvailable.add(part);
    }

    public byte[] getAPart() {
        return this.partsAvailable.poll();
    }

    public byte[] joinSecrets() {
        byte[] key = scheme.join(this.parts);
        System.out.println("JoinSecrets: " + Base64.getEncoder().encodeToString(key));
        return key;
    }

    public boolean firstPartInserted() {
        return this.parts.size() <= 1;
    }

}
