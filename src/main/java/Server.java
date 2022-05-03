import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.ServerSocket;
import java.net.Socket;
import java.rmi.server.ExportException;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private ServerSocket server = null;
    private static int N_THREADS = 10;
    private static int port = 10000;
    private DS ds;
    private ExecutorService threadPool = null;
    public Server(int port) {
        this.ds = DS.getInstance();
        this.threadPool = Executors.newFixedThreadPool(N_THREADS);
        port = port;
        try {
            this.server = new ServerSocket(port);
        }catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }
    public void startListening() {
        while(true) {
            try {
                Socket socket = this.server.accept();
                System.out.println("Client accepted");
                ServerWorker sw = new ServerWorker(socket);
                this.threadPool.submit(sw);

            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Server server = new Server(8000);
        server.startListening();
    }
}
