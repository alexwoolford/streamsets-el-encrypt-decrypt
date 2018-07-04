package io.woolford;

import org.junit.Assert;
import org.junit.Test;

public class TestEncryptEL {

    private final String unencrypted = "p@ssw0rd";
    private final String encrypted = "UoeNbVltv/7oRgOq4PoFBA==";

    private final String key = "Foo12345Bar12345";
    private final String initVector = "RandomInitVector";

    @Test
    public void testEncrypt() {
        Assert.assertEquals(encrypted, EncryptEL.encryptString(key, initVector, unencrypted));
    }

    @Test
    public void testDecrypt() {
        Assert.assertEquals(unencrypted, EncryptEL.decryptString(key, initVector, encrypted));
    }

}
