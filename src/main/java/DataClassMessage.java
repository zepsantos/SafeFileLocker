import java.io.Serializable;
import java.util.Arrays;

public class DataClassMessage implements Serializable {
    private boolean toEncrypt;
    private boolean secretShare = false;
    private int nPartsCreated = 0;
    private int nPartsNeeded = 0;

    private String key = null;


    private String hash = null;
    private long fileSize = 0;

    public DataClassMessage(String key ,boolean toEncrypt,long fileSize) {
        this.key = key;
        this.toEncrypt = toEncrypt;
        this.fileSize = fileSize;
    }

    public void setSecretShare(boolean secretShare, int nPartsCreated , int nPartsNeeded) {
        this.secretShare = secretShare;
        this.nPartsCreated = nPartsCreated;
        this.nPartsNeeded = nPartsNeeded;
    }

    public int getnPartsCreated() {
        return nPartsCreated;
    }

    public int getnPartsNeeded() {
        return nPartsNeeded;
    }

    public String getKey() {
        return key;
    }

    public boolean isSecretShared() {
        return secretShare;
    }

    public boolean isToEncrypt() {
        return toEncrypt;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getHash() {
        return hash;
    }

    public long getFileSize() {
        return fileSize;
    }
}
