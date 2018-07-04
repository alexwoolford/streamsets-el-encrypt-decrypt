package io.woolford;

import com.streamsets.pipeline.api.ElDef;
import com.streamsets.pipeline.api.ElFunction;
import com.streamsets.pipeline.api.ElParam;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@ElDef
public class EncryptEL {

    private static final Logger LOG = LoggerFactory.getLogger(EncryptEL.class);

    @ElFunction(
            prefix = "encrypt",
            name = "encryptString",
            description = "Returns encrypted version of the string argument.")
    public static String encryptString(
            @ElParam("key") String key, @ElParam("initVector") String initVector, @ElParam("string") String string) {
        return encrypt(key, initVector, string);
    }


    @ElFunction(
            prefix = "encrypt",
            name = "decryptString",
            description = "Returns a decrypted string from a key, an init vector, and a string")
    public static String decryptString(@ElParam("key") String key, @ElParam("initVector") String initVector, @ElParam("string") String string) {
        return decrypt(key, initVector, string);
    }

    private static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            LOG.info("encrypted string: " + Base64.encodeBase64String(encrypted));

            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            LOG.error(ex.getMessage());
        }

        return null;
    }

    private static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
            LOG.info("original: " + original);
            return new String(original);
        } catch (Exception ex) {
            LOG.error(ex.getMessage());
        }

        return null;
    }

}
