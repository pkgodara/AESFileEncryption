/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package aesfileencryption;

/**
 *
 * @author pradeep
 */

import java.io.*;
import java.util.*;


import java.security.AlgorithmParameters;
import java.security.SecureRandom;

import java.security.spec.KeySpec;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;



public class AESFileEncryption {
    
    static Scanner sc = new Scanner(System.in);
    
    public static void main(String[] args) throws Exception
    {
        
        System.out.print("Enter File /path/fileName : ");
        String file = sc.next() ;
        /*
        System.out.println("Enter 1 : encrypt and 2 : decrypt");
        int ch = sc.nextInt() ;
        
        if( ch > 2 || ch < 1 )
        {
            System.out.println("Invalid choice : default 1");
            ch = 1;
        }
        
        if( ch == 1 )
        {
            encryptFile(file) ;
        }
        else if( ch == 2 )
        {
            decryptFile(file) ;
        }*/
        
        encryptFile(file) ;
    }
    
    public static void encryptFile(String file) throws Exception
    {
        
        FileInputStream inp = new FileInputStream(file);
        
        FileOutputStream out = new FileOutputStream(file+"-Encrypted") ;
        
        System.out.println("Encrypting file: "+file);
        
        System.out.print("Enter Password : ");
        String password = sc.next() ;
        
        //password , iv , salt should be transfered to other end in secure manner
        //salt is used for encoding.
        //salt should be transferred to the recipient securely for decryption
        byte[] salt = new byte[8] ;
        
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        
        FileOutputStream saltOut = new FileOutputStream("salt.enc") ;
        
        saltOut.write(salt);
        saltOut.close();
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        
        KeySpec keySpec = new PBEKeySpec(password.toCharArray() , salt , 65536 , 256 ) ;
        
        SecretKey secretKey = factory.generateSecret(keySpec) ;
        SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES") ;
        
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        
        AlgorithmParameters algoParams = cipher.getParameters() ;
        
        //iv adds randomness to text and just makes more secure
        //used while initialising cipher
        FileOutputStream ivOut = new FileOutputStream("iv.enc");
        byte[] iv = algoParams.getParameterSpec(IvParameterSpec.class).getIV() ;
        
        ivOut.write(iv);
        ivOut.close();
        
        
         ///////////////      File Encryption.
         
         
         byte[] input = new byte[64] ;
         int bytesRead ;
         
         while( (bytesRead = inp.read(input)) != -1 )
         {
             byte[] output = cipher.update(input,0,bytesRead) ;
             
             if( output != null )
             {
                 out.write(output);
             }
         }
         
         byte[] output = cipher.doFinal() ;
         
         if( output != null )
         {
             out.write(output);
         }
         
         inp.close();
         out.flush();
         out.close();
        
         System.out.println("File "+file+" Successfully Encrypted.");
         
         ////////////////////////////////////////////////////////
         
         System.out.print("\nDecrypt encrypted file : y/yes ");
         String ch = sc.next();
         ch = ch.toLowerCase() ;
         
         if( ch.equals("y") || ch.equals("yes") )
         {
             decryptFile(file+"-Encrypted" , password ) ;
         }
    }
    
    
    public static void decryptFile(String file , String password ) throws Exception
    {
        FileInputStream inp = new FileInputStream(file) ;
        
        FileOutputStream out = new FileOutputStream(file+"--Decrypted") ;
        
        System.out.println("Decrypting file : "+file);
        
        //reading salt file
        FileInputStream saltIn = new FileInputStream("salt.enc");
        byte[] salt = new byte[8] ;
        
        saltIn.read(salt) ;
        saltIn.close();
        
        //reading iv file
        FileInputStream ivIn = new FileInputStream("iv.enc");
        byte[] iv = new byte[16];
        
        ivIn.read(iv);
        ivIn.close();
        
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1") ;
        
        KeySpec keySpec = new PBEKeySpec(password.toCharArray() , salt , 65536 , 256);
        
        SecretKey secretKey = factory.generateSecret(keySpec) ;
        
        SecretKey secret = new SecretKeySpec(secretKey.getEncoded() , "AES") ;
        
        
        /////////////   File decryption.
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding") ;
        cipher.init(Cipher.DECRYPT_MODE, secret , new IvParameterSpec(iv) );
        
        byte[] in = new byte[64] ;
        int read ;
        
        while( (read = inp.read(in)) != -1 )
        {
            byte[] output = cipher.update(in ,0 , read);
            
            if( output != null )
            {
                out.write(output);
            }
        }
        
        byte[] output = cipher.doFinal() ;
        
        if( output != null )
        {
            out.write(output);
        }
        
        inp.close();
        out.flush();
        out.close();
        
        System.out.println("File : "+ file +" successfully Decrypted");
    }
    
}