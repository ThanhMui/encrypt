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
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.SecretKey;

/**
 *
 * @author ASUS
 */
public class Server {
    public static void main(String[] args) throws Exception {
        byte[] receiveData = new byte[6588];
        byte[] sendData = new byte[6588];
       // encrypt.RSAUtils.generateKey("./public.key", "./private.key");
        PublicKey publicKey = encrypt.RSAUtils.getPublicKey("./public.key");
        PrivateKey privateKey = encrypt.RSAUtils.getPrivateKey("./private.key");
        DatagramPacket receivePacket;
        DatagramSocket datagramSocket = null;
        InetAddress address;
        DatagramPacket sendPacket;
        try {
            datagramSocket = new DatagramSocket(3333);
            receivePacket = new DatagramPacket(receiveData, receiveData.length);
             datagramSocket.receive(receivePacket);
                String tmp = (String) deserialize(receivePacket.getData());
                System.out.println("Server received: " + tmp + " from "
                        + receivePacket.getAddress().getHostAddress() + " at port "
                        + datagramSocket.getLocalPort());
                // gửi public key qua client
               
                sendData = serialize(publicKey);
                sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
                datagramSocket.send(sendPacket);
                System.out.println("Server sent " + publicKey + " to " + receivePacket.getAddress()
                        + " from port " + datagramSocket.getLocalPort());
                // nhận chuỗi mã hóa key secret từ client
                receivePacket = new DatagramPacket(receiveData, receiveData.length);
                datagramSocket.receive(receivePacket);
                byte[] encrypt = (byte[]) deserialize(receivePacket.getData());
                System.out.println("public key: " + publicKey);
                System.out.println("Server received: " + encrypt + " from "
                        + receivePacket.getAddress().getHostAddress() + " at port "
                        + datagramSocket.getLocalPort());
                
                //giải mã key vừa nhận được 
                byte[] decrypted = encrypt1.RSAUtils.decrypt(privateKey, encrypt);
                String keySecret = new String(decrypted);
                SecretKey secretKey = Encrypt.convertStringToSecretKeyto(keySecret);
                System.out.println("decrypt: " + decrypted);
                System.out.println("decrypt private key:" + new String(decrypted));
                if( secretKey!= null){
                     while (true) {
                System.out.println("Server ");
// nhận chuỗi hello từ client để server nhận biết client nào để gửi message về 
//                datagramSocket.receive(receivePacket);
//                String tmp = (String) deserialize(receivePacket.getData());
//                System.out.println("Server received: " + tmp + " from "
//                        + receivePacket.getAddress().getHostAddress() + " at port "
//                        + datagramSocket.getLocalPort());
//                // gửi public key qua client
//               
//                sendData = serialize(publicKey);
//                sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
//                datagramSocket.send(sendPacket);
//                System.out.println("Server sent " + publicKey + " to " + receivePacket.getAddress()
//                        + " from port " + datagramSocket.getLocalPort());
//                // nhận chuỗi mã hóa key secret từ client
//                receivePacket = new DatagramPacket(receiveData, receiveData.length);
//                datagramSocket.receive(receivePacket);
//                byte[] encrypt = (byte[]) deserialize(receivePacket.getData());
//                System.out.println("public key: " + publicKey);
//                System.out.println("Server received: " + encrypt + " from "
//                        + receivePacket.getAddress().getHostAddress() + " at port "
//                        + datagramSocket.getLocalPort());
//                
//                //giải mã key vừa nhận được 
//                byte[] decrypted = encrypt1.RSAUtils.decrypt(privateKey, encrypt);
//                String keySecret = new String(decrypted);
//                SecretKey secretKey = Encrypt.convertStringToSecretKeyto(keySecret);
//                System.out.println("decrypt: " + decrypted);
//                System.out.println("decrypt private key:" + new String(decrypted));
                /// bắt đầu nhận tin nhăn từ client đã bị mã hóa
                receivePacket = new DatagramPacket(receiveData, receiveData.length);
                datagramSocket.receive(receivePacket);
                byte[] tmpEncrypt = (byte[]) deserialize(receivePacket.getData());
                System.out.println("public key: " + tmpEncrypt);
                System.out.println("Server received: " + tmpEncrypt + " from "
                        + receivePacket.getAddress().getHostAddress() + " at port "
                        + datagramSocket.getLocalPort());
                byte[] tmpDecrypt = AESUtils.decrypt(secretKey, tmpEncrypt);
                System.out.println("Server received message from client: " + new String(tmpDecrypt));
                List<String> listString = new ArrayList<>();
                List<byte[]> listEncrypt = new ArrayList<>();
                listString.add("ten1");
                listString.add("ten2");
                listString.add("ten3");
                listString.add("ten4");
                for (String str : listString) {
                    byte[] strEncrypt = AESUtils.encrypt(secretKey, str.getBytes());
                    listEncrypt.add(strEncrypt);
                }
                
                sendData = serialize(listEncrypt);
                sendPacket = new DatagramPacket(sendData, sendData.length,receivePacket.getAddress(), receivePacket.getPort());
                datagramSocket.send(sendPacket);
                System.out.println("Server sent " + listEncrypt.size() + " to " + receivePacket.getAddress()
                        + " from port " + datagramSocket.getLocalPort());
            }
                }
           
        } //         }
        catch (IOException e) {
            System.err.println(e.getStackTrace());
        }
        datagramSocket.close();
    }
// send data
    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
// receive data
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }

}
