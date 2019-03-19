package utils;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import cliente.IntegrityVerifierClient;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Key {
	public static void main( String args[]) throws NoSuchAlgorithmException, FileNotFoundException, IOException{
		KeyGenerator kg;
		kg = KeyGenerator.getInstance("HmacSHA1");
		try (FileOutputStream stream = new FileOutputStream("key.txt")) {
		    stream.write(kg.generateKey().getEncoded());
		}
		System.out.println(kg.generateKey().getEncoded());
	}
}
