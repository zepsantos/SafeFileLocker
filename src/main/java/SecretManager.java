import com.codahale.shamir.Scheme;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SecretManager {
    private int partsNeeded = 0;
    private int partsCreated = 0;
    private Map<Integer,byte[]> parts;
    private int partCounter = 0;
    private Queue<byte[]> partsAvailable;
    private String hash;
    private Scheme scheme;
    public SecretManager(String hash, int partsNeeded,int partsCreated) {
        this.hash = hash;
        this.partsNeeded = partsNeeded;
        this.partsCreated = partsCreated;
        this.partsAvailable = new ConcurrentLinkedQueue<>();
        this.scheme = new Scheme(new SecureRandom(),partsCreated,partsNeeded);
        this.parts = new HashMap<>();
    }

    public boolean isReadyToDecrypt() {
        return this.parts.size() >= partsNeeded;
    }


    public String getHash() {
        return hash;
    }

    public void addPart(byte[] part) {
        this.parts.put(this.partCounter++,part);
    }

    public void splitSecret(byte[] keyToDecrypt) {
        Map<Integer, byte[]> parts = scheme.split(keyToDecrypt);
        for(byte[] part:parts.values() ) {
            addToAvailablePartsQueue(part);
        }
    }

    private void addToAvailablePartsQueue(byte[] part ) {
        this.partsAvailable.add(part);
    }

    public byte[] getAPart() {
        return this.partsAvailable.poll();
    }

    public byte[] joinSecrets() {
        byte[] key = scheme.join(this.parts);
        return key;
    }

    public boolean firstPartInserted() {
        return this.partCounter <= 1;
    }

}
