package utils;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class Utils {

	public static SecretKey getKey() {
		FileReader fileReader;
		try {
			fileReader = new FileReader("key.txt");

			// Always wrap FileReader in BufferedReader.
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String line = bufferedReader.readLine();
//	        JOptionPane.showMessageDialog(null, Arrays.toString(Utils.decodeHexString(line)));
			bufferedReader.close();
			
			return new SecretKeySpec(Utils.decodeHexString(line), "HmacSHA512");
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String getOffset() {
		FileReader fileReader;
		try {
			File file = new File("offset.txt");
			file.createNewFile();

			fileReader = new FileReader("offset.txt");

			// Always wrap FileReader in BufferedReader.
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			String offset = bufferedReader.readLine();
			bufferedReader.close();
			return offset;
		} catch (IOException e) {
			System.err.println("Hubo un problema obteniendo los offsets.");
		}
		return null;
	}

	public static Integer setOffset(Integer offset) {
		try {

			PrintWriter writer = new PrintWriter("offset.txt");
			writer.print(offset.toString());
			writer.close();
			return offset;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public static void writeLog(String message) {
		try {
			File file = new File("logs.txt");
			file.createNewFile();
			BufferedWriter output = new BufferedWriter(new FileWriter("logs.txt", true));
			output.append("[" + new Date() + "]" + message +"\n");
			output.close();
		} catch (IOException e) {
			System.err.println("Hubo un problema escribiendo los logs.");
		}
	}

	public static void updateKpi(Double ratio) {
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

	public static Map<String, String> getClientKeys() {
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
	
	public static String byteToHex(byte num) {
	    char[] hexDigits = new char[2];
	    hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
	    hexDigits[1] = Character.forDigit((num & 0xF), 16);
	    return new String(hexDigits);
	}
	
	public static String encodeHexString(byte[] byteArray) {
	    StringBuffer hexStringBuffer = new StringBuffer();
	    for (int i = 0; i < byteArray.length; i++) {
	        hexStringBuffer.append(byteToHex(byteArray[i]));
	    }
	    return hexStringBuffer.toString();
	}
	
	public static byte[] decodeHexString(String hexString) {
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
	
	public static byte hexToByte(String hexString) {
	    int firstDigit = toDigit(hexString.charAt(0));
	    int secondDigit = toDigit(hexString.charAt(1));
	    return (byte) ((firstDigit << 4) + secondDigit);
	}
	 
	private static int toDigit(char hexChar) {
	    int digit = Character.digit(hexChar, 16);
	    if(digit == -1) {
	        throw new IllegalArgumentException(
	          "Invalid Hexadecimal Character: "+ hexChar);
	    }
	    return digit;
	}

}
