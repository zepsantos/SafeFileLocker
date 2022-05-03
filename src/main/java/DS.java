import java.util.HashMap;
import java.util.Map;

public class DS {
    public static DS instance = null;
    private Map<String,DataClass> dataClassHashMap;

    private Map<String,SecretManager> SecretManagerMap;
    //Leva uma estrutura de dados para acomodar os ficheiros e a cifra
    private DS() {
        dataClassHashMap = new HashMap<>();
        SecretManagerMap = new HashMap<>();
    }

    public static DS getInstance() {
        if (instance == null) {
            instance = new DS();
        }
        return instance;
    }

    public DataClass getFileNameByHash(String hash) {
        if(dataClassHashMap.containsKey(hash)) {
            return dataClassHashMap.get(hash);
        }
        return null;
    }
    public void addToDataClassHashMap(DataClass dc) {
        dataClassHashMap.put(dc.getHash(),dc);
    }

    public DataClass getFromDataClassHashMap(String hash) {
        return dataClassHashMap.get(hash);
    }

    public byte[] splitSecret(String hash,int n , int k,byte[] keyToDecrypt) {
        SecretManager tmp = this.SecretManagerMap.get(hash);
        if(tmp == null) {
            tmp = new SecretManager(hash,n,k);
            this.SecretManagerMap.put(hash,tmp);
        }
        tmp.splitSecret(keyToDecrypt);

        return popFromSecretManagerAKey(hash);
    }


    public byte[] popFromSecretManagerAKey(String hash) {
        SecretManager tmp = this.SecretManagerMap.get(hash);
        return tmp.getAPart();
    }

    /**
     * Blocking call to first person sharing a secret in order to retrieve the full key at the end
     * @param hash
     * @param secretBytes
     * @return
     */
    public byte[] joinSecrets(String hash,byte[] secretBytes) throws InterruptedException {
        byte[] key = null;
        SecretManager tmp = this.SecretManagerMap.get(hash);
        if(tmp == null) return null;
        addSecretToSecretManager(tmp,secretBytes);
        if(tmp.firstPartInserted()) {
           while(!tmp.isReadyToDecrypt()){
               Thread.sleep(500);
            }
            key = tmp.joinSecrets();
            return key;
        }
        return null;
    }

    private void addSecretToSecretManager(SecretManager secretManager,byte[] secretBytes){
        secretManager.addPart(secretBytes);
    }





}
