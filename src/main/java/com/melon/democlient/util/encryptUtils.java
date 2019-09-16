package com.melon.democlient.util;


import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.*;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class encryptUtils {


    public static String src = "Hello world";

    public static void jdkBase64(){
        try {
            BASE64Encoder encoder=new BASE64Encoder();
            String encode = encoder.encode(src.getBytes());
            System.out.println("encode: "+encode);

            BASE64Decoder decoder=new BASE64Decoder();
            String decode=new String(decoder.decodeBuffer(encode));
            System.out.println("decode: "+decode);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void jdkMD5(){
        try {
            MessageDigest md=MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(src.getBytes());
            System.out.println("JDK MD5: "+ Hex.encodeHexString(digest));
            //使用的是cc中带的Hex需要转换为十六进制
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    public static void jdkSHA1(){
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA");
            digest.update(src.getBytes());
            System.out.println("JDK SHA1: "+Hex.encodeHexString(digest.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void jdkHmacMD5(){
        try {
            KeyGenerator keyGenerator= KeyGenerator.getInstance("HmacMD5");  //初始化KeyGenerator
            SecretKey secretKey=keyGenerator.generateKey(); //产生密钥
            //byte[] key=secretKey.getEncoded();     //获得密钥(默认生成)

            byte[] key=Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a','a','a'});  //手动生成密钥(十位)

            SecretKey secretKey2=new SecretKeySpec(key, "HmacMD5"); //还原密钥
            Mac mac= Mac.getInstance(secretKey2.getAlgorithm());  //实例化mac
            //初始化mac
            mac.init(secretKey2);
            byte[] hmacMD5Bytes=mac.doFinal(src.getBytes());
            System.out.println("jdk hmacMD5: "+Hex.encodeHexString(hmacMD5Bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdkDES(){
        try {
            //生成key
            KeyGenerator keyGenerator=KeyGenerator.getInstance("DES");
            keyGenerator.init(56);      //指定key长度，同时也是密钥长度(56位)
            SecretKey secretKey = keyGenerator.generateKey(); //生成key的材料
            byte[] key = secretKey.getEncoded();  //生成key

            //key转换成密钥
            DESKeySpec desKeySpec=new DESKeySpec(key);
            SecretKeyFactory factory=SecretKeyFactory.getInstance("DES");
            SecretKey key2 = factory.generateSecret(desKeySpec);      //转换后的密钥

            //加密
            Cipher cipher= Cipher.getInstance("DES/ECB/PKCS5Padding");  //算法类型/工作方式/填充方式
            cipher.init(Cipher.ENCRYPT_MODE, key2);   //指定为加密模式
            byte[] result=cipher.doFinal(src.getBytes());
            System.out.println("jdkDES加密: "+Hex.encodeHexString(result));  //转换为十六进制

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key2);  //相同密钥，指定为解密模式
            result = cipher.doFinal(result);   //根据加密内容解密
            System.out.println("jdkDES解密: "+new String(result));  //转换字符串

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdkDESede(){
        try {
            //生成key
            KeyGenerator keyGenerator=KeyGenerator.getInstance("DESede");
            //keyGenerator.init(112);      //3DES需要112 or 168位
            keyGenerator.init(new SecureRandom());   //或者使用这种方式默认长度，无需指定长度
            SecretKey secretKey = keyGenerator.generateKey(); //生成key的材料
            byte[] key = secretKey.getEncoded();  //生成key

            //key转换成密钥
            DESedeKeySpec desKeySpec=new DESedeKeySpec(key);
            SecretKeyFactory factory=SecretKeyFactory.getInstance("DESede");
            SecretKey key2 = factory.generateSecret(desKeySpec);      //转换后的密钥

            //加密
            Cipher cipher=Cipher.getInstance("DESede/ECB/PKCS5Padding");  //算法类型/工作方式/填充方式
            cipher.init(Cipher.ENCRYPT_MODE, key2);   //指定为加密模式
            byte[] result=cipher.doFinal(src.getBytes());
            System.out.println("jdk3DES加密: "+Hex.encodeHexString(result));  //转换为十六进制

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key2);  //相同密钥，指定为解密模式
            result = cipher.doFinal(result);   //根据加密内容解密
            System.out.println("jdk3DES解密: "+new String(result));  //转换字符串

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdkAES(){
        try {
            //生成key
            KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] key1 = secretKey.getEncoded();

            //key转换为密钥
            Key key2 = new SecretKeySpec(key1, "AES");

            //加密
            Cipher cipher=Cipher.getInstance("AES/ECB/PKCS5padding");
            cipher.init(Cipher.ENCRYPT_MODE, key2);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdkAES加密: "+Hex.encodeHexString(result));  //转换为十六进制

            //解密
            cipher.init(Cipher.DECRYPT_MODE, key2);
            result = cipher.doFinal(result);
            System.out.println("jdkAES解密: "+new String(result));  //转换字符串
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdkPBE(){
        try {
            //初始化盐
            SecureRandom random=new SecureRandom();
            byte[] salt = random.generateSeed(8);   //指定为8位的盐 （盐就是干扰码，通过添加干扰码增加安全）

            //口令和密钥
            String password="lynu";              //口令
            PBEKeySpec pbeKeySpec=new PBEKeySpec(password.toCharArray());
            SecretKeyFactory factory=SecretKeyFactory.getInstance("PBEWITHMD5andDES");
            Key key=factory.generateSecret(pbeKeySpec);  //密钥

            //加密
            PBEParameterSpec pbeParameterSpec=new PBEParameterSpec(salt, 100);   //参数规范，第一个参数是盐，第二个是迭代次数（经过散列函数多次迭代）
            Cipher cipher=Cipher.getInstance("PBEWITHMD5andDES");
            cipher.init(Cipher.ENCRYPT_MODE, key,pbeParameterSpec);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk PBE加密: "+ Base64.encodeBase64String(result));


            //解密
            cipher.init(Cipher.DECRYPT_MODE, key,pbeParameterSpec);
            result = cipher.doFinal(result);
            System.out.println("jdk PBE解密: "+new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void jdkDH(){
        try {
            //初始化发送方密钥
            KeyPairGenerator senderKeyPairGenerator=KeyPairGenerator.getInstance("DH");
            senderKeyPairGenerator.initialize(512);   //密钥长度
            KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
            byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();  //发送方key,需传递给接收方（网络，文件）

            //初始化接收方密钥
            KeyFactory factory=KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(senderPublicKeyEnc);  //根据从发送方得到的key解析
            PublicKey receiverPublicKey=factory.generatePublic(x509EncodedKeySpec);
            DHParameterSpec dhParameterSpec=((DHPublicKey)receiverPublicKey).getParams();
            KeyPairGenerator receiverKeyPairGenerator=KeyPairGenerator.getInstance("DH");
            receiverKeyPairGenerator.initialize(dhParameterSpec);
            KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
            PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
            byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();

            //密钥构建
            KeyAgreement receiverKeyAgreement=KeyAgreement.getInstance("DH");
            receiverKeyAgreement.init(receiverPrivateKey);
            receiverKeyAgreement.doPhase(receiverPublicKey, true);
            SecretKey receiverDESKey=receiverKeyAgreement.generateSecret("DES");  //发送发密钥(公钥)
            KeyFactory senderKeyFactory=KeyFactory.getInstance("DH");
            x509EncodedKeySpec=new X509EncodedKeySpec(receiverPublicKeyEnc);
            PublicKey senderPublicKey=senderKeyFactory.generatePublic(x509EncodedKeySpec);
            KeyAgreement senderKeyAgreement=KeyAgreement.getInstance("DH");
            senderKeyAgreement.init(senderKeyPair.getPrivate());
            senderKeyAgreement.doPhase(senderPublicKey, true);
            SecretKey senderDESKey=senderKeyAgreement.generateSecret("DES");        //接收方密钥(私钥)
            if(Objects.equals(receiverDESKey, senderDESKey)){
                System.out.println("双方密钥相同");
            }
            //加密
            Cipher cipher=Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, senderDESKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("jdk DH加密: "+org.apache.commons.codec.binary.Base64.encodeBase64String(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE, receiverDESKey);
            result=cipher.doFinal(result);
            System.out.println("jdk DH解密: "+new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void jdkRSA(){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey=(RSAPublicKey) keyPair.getPublic();           //公钥
            RSAPrivateKey rsaPrivateKey=(RSAPrivateKey) keyPair.getPrivate();       //私钥
            System.out.println("public key:"+Base64.encodeBase64String(rsaPublicKey.getEncoded()));
            System.out.println("private key:"+Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

            //私钥加密，公钥解密--加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory=KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("RSA私钥加密，公钥解密--加密:"+Base64.encodeBase64String(result));

            //私钥加密，公钥解密--解密
            X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            result = cipher.doFinal(result);
            System.out.println("RSA私钥加密，公钥解密--解密:"+new String(result));

            //公钥加密，私钥解密--加密
            x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            result = cipher.doFinal(src.getBytes());
            System.out.println("RSA公钥加密，私钥解密--加密:"+Base64.encodeBase64String(result));

            //公钥加密，私钥解密--解密
            pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            privateKey =keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result=cipher.doFinal(result);
            System.out.println("RSA公钥加密，私钥解密--解密:"+new String(result));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bcELGamal(){
        try {
            //加载provider
            Security.addProvider(new BouncyCastleProvider());

            //初始化密钥
            AlgorithmParameterGenerator algorithmParameterGenerator=AlgorithmParameterGenerator.getInstance("ELGamal");
            algorithmParameterGenerator.init(256);
            AlgorithmParameters algorithmParameters=algorithmParameterGenerator.generateParameters();
            DHParameterSpec dhParameterSpec=(DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
            KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("ELGamal");
            keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
            KeyPair keyPair=keyPairGenerator.generateKeyPair();
            PublicKey elGamalPublicKey=keyPair.getPublic();        //公钥
            PrivateKey elGamalPrivateKey=keyPair.getPrivate();     //私钥
            System.out.println("public key:"+Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
            System.out.println("private key:"+Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));

            //公钥加密，私钥解密--加密
            X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
            KeyFactory keyFactory=KeyFactory.getInstance("ELGamal");
            PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            Cipher cipher=Cipher.getInstance("ELGamal");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("ELGamal加密:"+Base64.encodeBase64String(result));

            //公钥加密，私钥解密--解密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
            keyFactory=KeyFactory.getInstance("ELGamal");
            PrivateKey privateKey =keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher=Cipher.getInstance("ELGamal");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result=cipher.doFinal(result);
            System.out.println("ElGamal解密:"+new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {

        jdkAES();
        jdkBase64();
        jdkDES();
        jdkDESede();
        jdkDH();
        jdkHmacMD5();
        jdkMD5();
        jdkPBE();
        jdkRSA();
        jdkSHA1();
    }
}
