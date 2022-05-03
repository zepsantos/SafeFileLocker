public class DataClass {
    private String filePath;
    private String hash;
    private boolean secretShare = false;
    private int nPartsCreated = 0;
    private int nPartsNeeded = 0;

    public DataClass(String hash, String filePath) {
        this.hash = hash;
        this.filePath = filePath;
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

    public String getHash() {
        return hash;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public boolean isSecretShared() {
        return this.secretShare;
    }
}
