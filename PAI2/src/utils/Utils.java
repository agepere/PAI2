package utils;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

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
	        JOptionPane.showMessageDialog(null, line.getBytes());
	        bufferedReader.close();   
	        return new SecretKeySpec(line.getBytes(), 0, line.getBytes().length, "HmacSHA512");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return null;
    }
}
