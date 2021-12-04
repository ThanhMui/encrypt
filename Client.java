/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encrypt1;

import encrypt.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author ASUS
 */
public class Client {
   
    public static String hostname = "localhost";
    static DatagramSocket clientSocket ;
    static Scanner sc ;
    public static  byte[] sendData ;
    InetAddress address;
    public static  byte[] receiveData;
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException, InterruptedException {
            Scanner stdIn = new Scanner(System.in);
            DatagramPacket receivePacket;
            InetAddress address;
            DatagramPacket sendPacket;
            String sendTmp = "hello";
            sendData = new byte[6553];
            receiveData = new byte[6553];
             
            try {
            clientSocket = new DatagramSocket();
            address = InetAddress.getByName("localhost");
            if (sendTmp.equalsIgnoreCase("bye")) {
                clientSocket.close();
                System.exit(0);
            }
            sendData = serialize(sendTmp.toString());
           
            sendPacket = new DatagramPacket(sendData, sendData.length, address, 3333);
            System.out.println("Client sent " + sendTmp + " to " + address.getHostAddress()
                    + " from port " + clientSocket.getLocalPort());
            clientSocket.send(sendPacket);
            // DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            receivePacket = new DatagramPacket(receiveData, receiveData.length);
            clientSocket.receive(receivePacket);
            PublicKey publicKey =(PublicKey) deserialize(receivePacket.getData());
            System.out.println("public key: "+ publicKey);
            // taok private key aes
            SecretKey secretKey = encrypt1.AESUtils.generateKey();
            System.out.println("serec key: " + encrypt.Encrypt.convertSecretKeyToString(secretKey));
            String encodedKey = encrypt.Encrypt.convertSecretKeyToString(secretKey);
//                            System.out.println("string: "+ encodedKey);
//                           System.out.println("secret key: "+ secretKey.getFormat());
            // emã hóa private key dùng public key vừa nhận dược từ server
            byte[] encrypted = encrypt1.RSAUtils.encrypt(publicKey, encodedKey.getBytes());
            sendData = serialize(encrypted);
           
            sendPacket = new DatagramPacket(sendData, sendData.length, address, 3333);
            System.out.println("Client sent " + sendTmp + " to " + address.getHostAddress()
                    + " from port " + clientSocket.getLocalPort());
            clientSocket.send(sendPacket);
            // bắt đầu gửi tin nhán đến client sau khi cả 2 bên đẫ nhận được serect key
            //send message to server
                while (true) {                    
                System.out.println("Nhập vào nội dung: ");
                String tmpMessage = stdIn.nextLine();
                byte[]tm= tmpMessage.getBytes();
                 byte[] encryptedMesage = encrypt1.AESUtils.encrypt(secretKey, tm);
                sendData = serialize(encryptedMesage);
           
            sendPacket = new DatagramPacket(sendData, sendData.length, address, 3333);
            System.out.println("Client sent " + sendData + " to " + address.getHostAddress()
                    + " from port " + clientSocket.getLocalPort());
            clientSocket.send(sendPacket);
            
            // receive message from server
            receivePacket = new DatagramPacket(receiveData, receiveData.length);
            clientSocket.receive(receivePacket);
            List<byte[]> messagesEncrypt =(ArrayList)deserialize(receivePacket.getData());
            for( byte[] message: messagesEncrypt){
                byte[] decryptMessage = AESUtils.decrypt(secretKey, message);
                System.out.println("decrypt message: "+ new String(decryptMessage));
            }
       
               
        }
//            System.out.println("Nhập vào nội dung: ");
//            String tmpMessage = stdIn.nextLine();
//            byte[]tm= tmpMessage.getBytes();
//             byte[] encryptedMesage = encrypt1.AESUtils.encrypt(secretKey, tm);
//            sendData = serialize(encryptedMesage);
//           
//            sendPacket = new DatagramPacket(sendData, sendData.length, address, 3333);
//            System.out.println("Client sent " + sendData + " to " + address.getHostAddress()
//                    + " from port " + clientSocket.getLocalPort());
//            clientSocket.send(sendPacket);
//            
//            // receive message from server
//            receivePacket = new DatagramPacket(receiveData, receiveData.length);
//            clientSocket.receive(receivePacket);
//            List<byte[]> messagesEncrypt =(ArrayList)deserialize(receivePacket.getData());
//            for( byte[] message: messagesEncrypt){
//                byte[] decryptMessage = AESUtils.decrypt(secretKey, message);
//                System.out.println("decrypt message: "+ new String(decryptMessage));
//            }
//        } catch (IOException ex) {
//            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
//        }
            
	} catch (SocketException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnknownHostException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }
            clientSocket.close();
        }
    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }
}
