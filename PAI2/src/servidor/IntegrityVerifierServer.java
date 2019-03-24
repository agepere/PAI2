package servidor;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import utils.Utils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class IntegrityVerifierServer {
    private ServerSocket serverSocket;
    private Map<String, Integer> clientOffsets;
    private Map<String, String> clientKeys;
    private Double totalCalls;
    private Double correctCalls;

    // Constructor del Servidor
    public IntegrityVerifierServer() throws Exception {
        // ServerSocketFactory para construir los ServerSockets
        ServerSocketFactory socketFactory = ( ServerSocketFactory ) ServerSocketFactory.getDefault();
        // Creación de un objeto ServerSocket escuchando peticiones en el puerto 7070
        serverSocket = (ServerSocket ) socketFactory.createServerSocket(7070);
        clientOffsets = new HashMap<String, Integer>();
        clientKeys = Utils.getClientKeys();
        totalCalls = 0.;
        correctCalls = 0.;
        
    }
    // Ejecución del servidor para escuchar peticiones de los clientes
    public void runServer() throws NoSuchAlgorithmException, InvalidKeyException{
    	
        Mac mac = Mac.getInstance("HmacSHA512");
        
        while (true) {
            // Espera las peticiones del cliente para comprobar mensaje/MAC
            try {
                System.err.println( "Esperando conexiones de clientes...");
                Socket socket = (Socket) serverSocket.accept();
        		Integer lastOffset = -1;
                // Abre un BufferedReader para leer los datos del cliente
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                // Abre un PrintWriter para enviar datos al cliente
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream() ) );
                // Se lee del cliente el mensaje y el macdelMensajeEnviado
                String message = input.readLine();
                String clientId = message.split(",")[0];
                if(!clientKeys.containsKey(clientId)) {
                	System.err.println("El usuario no tiene su clave registrada en el sistema");
                	Utils.writeLog("El usuario"+clientId+" no tiene su clave registrada en el sistema");
                	continue;
                }
                SecretKey key = new SecretKeySpec(Utils.decodeHexString(clientKeys.get(clientId)), "HmacSHA512");
                mac.init(key);
                if (clientOffsets.containsKey(clientId)){
                 lastOffset = clientOffsets.get(clientId);
                }
                String offset = input.readLine();
                // A continuación habría que calcular el mac del MensajeEnviado que podría ser
                String macdelMensajeEnviado = input.readLine();
                //mac del MensajeCalculado
                mac.update((message+offset).getBytes("UTF-8"));
                byte[] bytesMac = mac.doFinal();
                String macDelMensajeCalculado=new String(bytesMac);
                if (Arrays.equals(macDelMensajeCalculado.getBytes(), macdelMensajeEnviado.getBytes()) && new Integer(offset) > lastOffset) {
                    output.println( "Mensaje enviado integro " );
                    clientOffsets.put(clientId, new Integer(offset));
                    correctCalls+=1.;
                    totalCalls+=1.;
                } else {
                    output.println( "Mensaje enviado no integro.");
                    Utils.writeLog("El mensaje :"+message+" ha sufrido un problema de integridad.");
                    totalCalls+=1.;
                }
                System.out.println("KPI: "+correctCalls/totalCalls);
                Utils.updateKpi(correctCalls/totalCalls);
                output.close();
                input.close();
                socket.close();
            }
            catch ( IOException ioException ) {
                ioException.printStackTrace(); }
        }
    }
}
