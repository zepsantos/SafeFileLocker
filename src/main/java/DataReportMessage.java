import java.io.Serializable;
import java.util.Arrays;

public class DataReportMessage implements Serializable {
    private String hash;
    private String keyToDecrypt;
    private int status = 1;

    public DataReportMessage(String hash ,String keyToDecrypt) {
        this.hash = hash;
        this.keyToDecrypt = keyToDecrypt;
    }

    public String getHash() {
        return hash;
    }

    public String getKeyToDecrypt() {
        return keyToDecrypt;
    }

    public void setStatus(int status) {
        this.status = status;
    }
    public int getStatus() {
        return this.status;
    }

    public boolean isSucessfull() {
        return this.status == 1;
    }

}
