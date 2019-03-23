package utils;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

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
//	        JOptionPane.showMessageDialog(null, line.getBytes());
	        bufferedReader.close();   
	        return new SecretKeySpec(line.getBytes(), 0, line.getBytes().length, "HmacSHA512");
		} catch (IOException e) {
			// TODO Auto-generated catch block
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
			// TODO Auto-generated catch block
			e.printStackTrace();
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
			output.append("["+new Date()+"] The message '"+message+"' has an integrity problem.\n");
			output.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
}
