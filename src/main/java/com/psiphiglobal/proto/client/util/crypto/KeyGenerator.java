package com.psiphiglobal.proto.client.util.crypto;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

public final class KeyGenerator
{
    public static Map<String, byte[]> generateKeys() throws NoSuchAlgorithmException
    {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, byte[]> keys = new HashMap<>();
        keys.put("public_key", publicKey.getEncoded());
        keys.put("private_key", privateKey.getEncoded());
        return keys;
    }

    private KeyGenerator()
    {
    }
}
