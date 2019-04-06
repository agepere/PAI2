package servidor;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class IntegrityVerifierServer {
    private SSLServerSocket serverSocket;
    private Map<String, Integer> clientOffsets;
    private Map<String, String> clientKeys;
    private Double totalCalls;
    private Double correctCalls;

    // Constructor del Servidor
    public IntegrityVerifierServer() throws Exception {
        System.setProperty("https.protocols", "TLSv1.1,TLSv1.2,TLSv1.3");

        // ServerSocketFactory para construir los ServerSockets
        SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        // Creación de un objeto ServerSocket escuchando peticiones en el puerto 7070
        serverSocket = (SSLServerSocket) socketFactory.createServerSocket(7070);


        List<String> lista = new ArrayList<>();
        String[] array = new String[100];

        BufferedReader input = new BufferedReader(new FileReader("seguros.txt"));

        String line;

        while ((line = input.readLine()) != null) {
            lista.add(line.trim());
        }
        input.close();

        serverSocket.setEnabledCipherSuites(lista.toArray(new String[0]));


        String[] enabledCiphers = serverSocket.getEnabledCipherSuites();

        for (String enabledCipher : enabledCiphers) {
            System.out.println("Enabled Ciphers: " + enabledCipher);
        }

        clientOffsets = new HashMap<String, Integer>();
        clientKeys = this.getClientKeys();
        totalCalls = 0.;
        correctCalls = 0.;

    }

    public static void main(String args[]) throws Exception {
        IntegrityVerifierServer server = new IntegrityVerifierServer();
        server.runServer();
    }

    // Ejecución del servidor para escuchar peticiones de los clientes
    public void runServer() throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        Mac mac = Mac.getInstance("HmacSHA512");
        PrintWriter output = null;
        BufferedReader input = null;
        Socket socket = null;
        while (true) {
            // Espera las peticiones del cliente para comprobar mensaje/MAC
            try {
                System.err.println("Esperando conexiones de clientes...");
                socket = (Socket) serverSocket.accept();
                Integer lastOffset = -1;
                // Abre un BufferedReader para leer los datos del cliente
                input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                // Abre un PrintWriter para enviar datos al cliente
                output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
                // Se lee del cliente el mensaje y el macdelMensajeEnviado
                String message = input.readLine();
                String clientId = message.split(",")[0];
                if (!clientKeys.containsKey(clientId) || message.split(",").length != 3) {
                    System.err.println("El usuario no tiene su clave registrada en el sistema o el mensaje no se envío correctamente");
                    output.println("El mensaje no se envío correctamente.");
                    this.writeLog("El usuario " + clientId + " no tiene su clave registrada en el sistema o el mensaje no se envío correctamente");
                    continue;
                } else {
                    SecretKey key = new SecretKeySpec(this.decodeHexString(clientKeys.get(clientId)), "HmacSHA512");
                    mac.init(key);
                    if (clientOffsets.containsKey(clientId)) {
                        lastOffset = clientOffsets.get(clientId);
                    }
                    String offset = input.readLine();
                    // A continuación habría que calcular el mac del MensajeEnviado que podría ser
                    String macdelMensajeEnviado = input.readLine();
                    //mac del MensajeCalculado
                    mac.update((message + offset).getBytes("UTF-8"));
                    byte[] bytesMac = mac.doFinal();
                    String macDelMensajeCalculado = this.encodeHexString(bytesMac);
                    if (macDelMensajeCalculado.equals(macdelMensajeEnviado) && new Integer(offset).equals(lastOffset + 1)) {
                        output.println("Mensaje enviado integro ");
                        clientOffsets.put(clientId, new Integer(offset));
                        correctCalls += 1.;
                        totalCalls += 1.;
                    } else {
                        output.println("Mensaje enviado no integro.");
                        this.writeLog("El mensaje : " + message + " ha sufrido un problema de integridad.");
                        totalCalls += 1.;
                    }
                    System.out.println("KPI: " + correctCalls / totalCalls);
                    this.updateKpi(correctCalls / totalCalls);
                }

            } catch (SSLHandshakeException cipherException) {
                System.err.println("No cipher suites in common");
                output.println("No cipher suites in common");
            } catch (IOException ioException) {
                System.err.println("Oops! Hubo un problema de IO");
            } finally {
                if (output != null)
                    output.close();
                if (input != null)
                    input.close();
                if (socket != null)
                    socket.close();
            }
        }
    }

    // UTILS
    private void writeLog(String message) {
        try {
            File file = new File("logs.txt");
            file.createNewFile();
            BufferedWriter output = new BufferedWriter(new FileWriter("logs.txt", true));
            output.append("[" + new Date() + "]" + message + "\n");
            output.close();
        } catch (IOException e) {
            System.err.println("Hubo un problema escribiendo los logs.");
        }
    }

    private void updateKpi(Double ratio) {
        try {
            File file = new File("kpi.txt");
            file.createNewFile();
            BufferedWriter output = new BufferedWriter(new FileWriter("kpi.txt"));
            output.write(ratio.toString());
            output.close();
        } catch (IOException e) {
            System.err.println("Hubo un problema escribiendo el kpi.");
        }
    }

    private Map<String, String> getClientKeys() {
        Map<String, String> res = new HashMap<String, String>();
        try {
            File file = new File("clientKeys.txt");
            file.createNewFile();
            String line;
            BufferedReader input = new BufferedReader(new FileReader("clientKeys.txt"));
            while ((line = input.readLine()) != null) {
                res.put(line.split(",")[0], line.split(",")[1]);
            }
            input.close();
        } catch (IOException e) {
            System.err.println("Hubo un problema obteniendo las claves de los clientes.");
        }
        return res;
    }

    private String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    private String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    private byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    private byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if (digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: " + hexChar);
        }
        return digit;
    }

}
