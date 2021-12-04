/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encrypt1;

import encrypt.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author ASUS
 */
public class Encrypt implements Serializable{

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        // the bytes you want to encrypt
//		byte[] message = "Hello world!".getBytes();
//
//		// create a random key
//		SecretKey secretKey = AESUtils.generateKey();
//                String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
//                System.out.println("string: "+ encodedKey);
//	       System.out.println("secret key: "+ secretKey.getFormat());
//		// encrypt the message using the key that was generated
//		byte[] encrypted = AESUtils.encrypt(secretKey, message);
//
//		// decrypt the message by using the key again
//		byte[] decrypted = AESUtils.decrypt(secretKey, encrypted);
//
//		// results
//		System.out.println("original: " + new String(message));
//		System.out.println("encrypted: " + new String(encrypted));
//		System.out.println("decrypted: " + new String(decrypted));
// the bytes you want to encrypt
//		byte[] message = "Hello world!".getBytes();
////
//		// create a key by using your own password
//		SecretKey secretKey = AESUtils.createKey("password");
//                String encodedKey = convertSecretKeyToString(secretKey);
//               System.out.println("string: "+ encodedKey);
//		// encrypt the message using the key that was generated
//		byte[] encrypted = AESUtils.encrypt(secretKey, message);
//
//		// decrypt the message by entering a password
//		byte[] decrypted = AESUtils.decrypt("password", encrypted);
//
//		// results
//		System.out.println("original: " + new String(message));
//		System.out.println("encrypted: " + new String(encrypted));
//		System.out.println("decrypted: " + new String(decrypted));
//                byte[] data = "WvZkEfaUEZJN0JlzA8Z+bw==".getBytes();
        RSAUtils.generateKey("./public.key", "./private.key");
        PublicKey publicKey = RSAUtils.getPublicKey("./public.key");
////             
//               
//   
        PrivateKey privateKey = RSAUtils.getPrivateKey("./private.key");
        String pri = Encrypt.convertPrivateKeyToString(privateKey);
        PrivateKey keu = convertStringToPrivateKey(pri);
        byte[] data = "WvZkEfaUEZJN0JlzA8Z+bw==".getBytes();
        byte[] encrypted = RSAUtils.encrypt(publicKey, data);
        System.out.println("e: " + encrypted);
        byte[] h = RSAUtils.encrypt(publicKey, data);
        System.out.println("h: " + h);
        System.out.println("enc: ");
        System.out.println(new String(encrypted));
        System.out.println("private RSA: " + pri);
//                            byte[] decryptPri =textKeyPrivate.getBytes() ;
        byte[] decrypted = RSAUtils.decrypt(keu, encrypted);
        System.out.println("decrypt private key:" + new String(decrypted));

//		byte[] decrypted = RSAUtils.decrypt(privateKey, data);
//                System.out.println("decrypted: " + new String(decrypted));
//		byte[] encrypted = RSAUtils.encrypt(publicKey, data);	
//                System.out.println("enc: ");
//                System.out.println(new String(encrypted));
//                
//		PrivateKey privateKey = RSAUtils.getPrivateKey("./private.key");
//               
//		byte[] decrypted = RSAUtils.decrypt(privateKey, encrypted);
//                System.out.println("dec: "+ new String(decrypted));
//              
        System.out.println("original: " + new String(data));
        System.out.println("decrypt: ");
//		System.out.println( new String(encrypted));
//		System.out.println("decrypted: " + new String(decrypted));

    }

    public static SecretKey convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    public static String convertSecretKeyToString(SecretKey secretKey) throws NoSuchAlgorithmException {
        byte[] rawData = secretKey.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);
        return encodedKey;
    }

    public static String convertPublicKeyToString(PublicKey publicKey) {
        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return encodedKey;
    }

    public static PublicKey convertStringToPublicKey(String encodedKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] publicBytes = Base64.getDecoder().decode(encodedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //254514307525033576001193285232372949893071337925033456554037720857868219098745415141650072872931516145981910781716044057959270276351154879532536
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        return pubKey;
    }

        public static String convertPrivateKeyToString(PrivateKey privateKey) {
            String encodedKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            return encodedKey;
        }

    public static PrivateKey convertStringToPrivateKey(String encodedKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] encodedPv = Base64.getDecoder().decode(encodedKey);
        PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(encodedPv);
        PrivateKey privateKey = kf.generatePrivate(keySpecPv);
        return privateKey;
        
        
    }
}
