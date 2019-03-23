package servidor;

import javax.crypto.Mac;
import javax.net.ServerSocketFactory;
import javax.swing.JOptionPane;

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
    private Integer totalCalls;
    private Integer correctCalls;

    // Constructor del Servidor
    public IntegrityVerifierServer() throws Exception {
        // ServerSocketFactory para construir los ServerSockets
        ServerSocketFactory socketFactory = ( ServerSocketFactory ) ServerSocketFactory.getDefault();
        // Creación de un objeto ServerSocket escuchando peticiones en el puerto 7070
        serverSocket = (ServerSocket ) socketFactory.createServerSocket(7070);
        clientOffsets = new HashMap<String, Integer>();
        totalCalls = 0;
        correctCalls = 0;
        
    }
    // Ejecución del servidor para escuchar peticiones de los clientes
    public void runServer() throws NoSuchAlgorithmException, InvalidKeyException{
    	
        
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(Utils.getKey());
        
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
                    System.out.println(clientOffsets);
                    correctCalls+=1;
                    totalCalls+=1;
                } else {
                    output.println( "Mensaje enviado no integro. "+macdelMensajeEnviado+" - OTRO - "+macDelMensajeCalculado);
                    System.out.println(clientOffsets);
                    Utils.writeLog(message);
                    totalCalls+=1;
                }
                Utils.updateKpi((double) (correctCalls/totalCalls));
                output.close();
                input.close();
                socket.close();
            }
            catch ( IOException ioException ) {
                ioException.printStackTrace(); }
        }
    }
}
