package io.netty.example.discard;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.Security;
import java.util.Arrays;


public class AESUtil {

    private static final String ENCODE_TYPE = "UTF-8";
    private static Key key;
    private static Cipher cipher;

    private static void init(byte[] keyBytes) {
        int base = 16;
        if (keyBytes.length % base != 0) {
            int groups = keyBytes.length / base + (keyBytes.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp, (byte)0);
            System.arraycopy(keyBytes, 0, temp, 0, keyBytes.length);
            keyBytes = temp;
        }

        Security.addProvider(new BouncyCastleProvider());
        key = new SecretKeySpec(keyBytes, "AES");

        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (Exception var4) {
            var4.printStackTrace();
        }

    }

    public static String encrypt(String content, String key, String iv) throws UnsupportedEncodingException {
        return new String(org.bouncycastle.util.encoders.Base64.encode(encrypt(content.getBytes("UTF-8"), key.getBytes("UTF-8"), iv)), "UTF-8");
    }

    private static byte[] encrypt(byte[] content, byte[] keyBytes, String iv) {
        byte[] encryptedText = null;
        init(keyBytes);

        try {
            cipher.init(1, key, new IvParameterSpec(iv.getBytes("UTF-8")));
            encryptedText = cipher.doFinal(content);
        } catch (Exception var5) {
            var5.printStackTrace();
        }

        return encryptedText;
    }

    public static String decrypt(String content, String key, String iv)  {
        try {
            return new String(decrypt(org.bouncycastle.util.encoders.Base64.decode(content), key.getBytes("UTF-8"), iv), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] decrypt(byte[] encryptedData, byte[] keyBytes, String iv) {
        byte[] encryptedText = null;
        init(keyBytes);

        try {
            cipher.init(2, key, new IvParameterSpec(iv.getBytes("UTF-8")));
            encryptedText = cipher.doFinal(encryptedData);
        } catch (Exception var5) {
            var5.printStackTrace();
        }

        return encryptedText;
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        String content = "ABCD-ERFC-3556-IJBG";
        String aesKey = "2104f6fe-9e43-4aae-a68b-a6beb4879809".substring(0, 16);
        System.out.println(aesKey);
        String result = AESUtil.encrypt(content, aesKey, aesKey);
        System.out.println("加密 ：" + result);
        System.out.println(AESUtil.decrypt(result, aesKey, aesKey));
    }

}