package servidor;

public class mainServer {
    
    public static void main(String args[]) throws Exception {
        IntegrityVerifierServer server = new IntegrityVerifierServer();
        server.runServer();
    }

}

