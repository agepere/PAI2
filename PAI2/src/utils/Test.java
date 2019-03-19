package utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.swing.JOptionPane;

public class Test {

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
    	Mac mac = Mac.getInstance("HmacSHA512");
    	mac.init(Utils.getKey());
        while(true) {
        	mac.reset();
	        String message = JOptionPane.showInputDialog(null, "Introduzca su mensaje:");
	        System.out.println(message.getBytes());
	        System.out.println(new String(mac.doFinal(message.getBytes())));
        }
	}

}
