package utils;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;

import cliente.IntegrityVerifierClient;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Key {
	public static void main( String args[]) throws NoSuchAlgorithmException, FileNotFoundException, IOException{
		KeyGenerator kg;
		kg = KeyGenerator.getInstance("HmacSHA1");
//		try (FileOutputStream stream = new FileOutputStream("key.txt")) {
//		    stream.write(kg.generateKey().getEncoded());
//		}
		String res = "";
		byte[] key = kg.generateKey().getEncoded();
		System.out.println(Arrays.toString(key));
		res = encodeHexString(key);
		
		System.out.println(res);
		System.out.println(Arrays.toString(decodeHexString(res)));
		System.out.println(key.equals(decodeHexString(res)));
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
