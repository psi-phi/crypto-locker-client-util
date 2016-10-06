package com.psiphiglobal.proto.client;

import com.psiphiglobal.proto.client.util.GsonProvider;
import com.psiphiglobal.proto.client.util.crypto.AsymmetricCryptoUtil;
import com.psiphiglobal.proto.client.util.crypto.KeyGenerator;
import com.psiphiglobal.proto.client.util.crypto.SymmetricCryptoUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class Main
{
    private static final String OPTION_REGISTER = "--register";
    private static final String OPTION_UPLOAD = "--upload";
    private static final String OPTION_SHARE = "--share";
    private static final String OPTION_RETRIVE = "--retrieve";

    public static void main(String[] args) throws Exception
    {
        run(args);
    }

    public static void run(String[] args) throws Exception
    {
        if (args.length == 0)
        {
            System.out.println("Enter a valid option");
            System.exit(1);
        }

        String option = args[0];
        switch (option)
        {
            case OPTION_REGISTER:
                if (args.length < 4)
                {
                    System.out.println("username, name and email required");
                    System.out.println("Use: --register \"<username>\" \"<name>\" \"<email>\"");
                    System.exit(1);
                }
                else
                {
                    register(args[1].replaceAll("\"", "").replaceAll("\'", ""), args[2].replaceAll("\"", "").replaceAll("\'", ""), args[3].replaceAll("\"", "").replaceAll("\'", ""));
                }
                break;

            case OPTION_UPLOAD:
                if (args.length < 5)
                {
                    System.out.println("username, document path, secret key, key path required");
                    System.out.println("Use: --upload \"<username>\" \"<document path>\" \"<secret key>\" \"<key path>\"");
                    System.exit(1);
                }
                else
                {
                    upload(args[1].replaceAll("\"", "").replaceAll("\'", ""), args[2].replaceAll("\"", "").replaceAll("\'", ""),
                            args[3].replaceAll("\"", "").replaceAll("\'", ""), args[4].replaceAll("\"", "").replaceAll("\'", ""));
                }
                break;

            case OPTION_SHARE:
                if (args.length < 7)
                {
                    System.out.println("document id, encrypted key, from username, to username, public key, key path required");
                    System.out.println("Use: --share \"<document id>\" \"<encrypted key>\" \"<from username>\" \"<to username>\" \"<public key>\" \"<key path>\"");
                    System.exit(1);
                }
                else
                {
                    share(args[1].replaceAll("\"", "").replaceAll("\'", ""), args[2].replaceAll("\"", "").replaceAll("\'", ""),
                            args[3].replaceAll("\"", "").replaceAll("\'", ""), args[4].replaceAll("\"", "").replaceAll("\'", ""),
                            args[5].replaceAll("\"", "").replaceAll("\'", ""), args[6].replaceAll("\"", "").replaceAll("\'", ""));
                }
                break;

            case OPTION_RETRIVE:
                if (args.length < 6)
                {
                    System.out.println("filename, encrypted content, encrypted key, username, key path required");
                    System.out.println("Use: --retrieve \"<filename>\" \"<encrypted content>\" \"<encrypted key>\" \"<username>\" \"<key path>\"");
                    System.exit(1);
                }
                else
                {
                    retrieve(args[1].replaceAll("\"", "").replaceAll("\'", ""), args[2].replaceAll("\"", "").replaceAll("\'", ""),
                            args[3].replaceAll("\"", "").replaceAll("\'", ""), args[4].replaceAll("\"", "").replaceAll("\'", ""),
                            args[5].replaceAll("\"", "").replaceAll("\'", ""));
                }
                break;

            default:
                System.out.println("Enter a valid option");
                System.exit(1);
        }
    }

    private static void register(String username, String name, String email) throws Exception
    {
        Map<String, byte[]> keys = KeyGenerator.generateKeys();
        File publicKeyFile = new File("./" + username + ".public");
        File privateKeyFile = new File("./" + username + ".private");

        String raw = username + "|" + name + "|" + email;
        String signature = Base64.encodeBase64String(AsymmetricCryptoUtil.sign(keys.get("private_key"), raw.getBytes()));

        FileUtils.writeByteArrayToFile(publicKeyFile, new X509EncodedKeySpec(keys.get("public_key")).getEncoded());
        FileUtils.writeByteArrayToFile(privateKeyFile, new PKCS8EncodedKeySpec(keys.get("private_key")).getEncoded());

        Map<String, String> user = new HashMap<>();
        user.put("username", username);
        user.put("name", name);
        user.put("email", email);
        user.put("public_key", Base64.encodeBase64String(keys.get("public_key")));
        user.put("signature", signature);
        System.out.println(GsonProvider.get().toJson(user));
        System.out.println("\nPS: Keypair created and saved as " + username + ".public and " + username + ".private");
    }

    private static void upload(String username, String fileName, String secretKey, String keyPath) throws Exception
    {
        File file = new File(fileName);
        byte[] data = FileUtils.readFileToByteArray(file);
        String documentName = file.getName();
        String encryptedContent = Base64.encodeBase64String(SymmetricCryptoUtil.encrypt(secretKey, data));

        File publicKeyFile = new File(keyPath + "/" + username + ".public");
        byte[] publicKeyBytes = FileUtils.readFileToByteArray(publicKeyFile);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        String encryptedKey = Base64.encodeBase64String(AsymmetricCryptoUtil.encryptWithPublicKey(publicKey.getEncoded(), secretKey.getBytes()));

        File privateKeyFile = new File(keyPath + "/" + username + ".private");
        byte[] privateKeyBytes = FileUtils.readFileToByteArray(privateKeyFile);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        String raw = documentName + "|" + username + "|" + encryptedContent;
        String signature = Base64.encodeBase64String(AsymmetricCryptoUtil.sign(privateKey.getEncoded(), raw.getBytes()));

        Map<String, String> request = new HashMap<>();
        request.put("name", documentName);
        request.put("creator", username);
        request.put("encrypted_content", encryptedContent);
        request.put("encrypted_key", encryptedKey);
        request.put("signature", signature);
        System.out.println(GsonProvider.get().toJson(request));
    }

    private static void share(String documentId, String encryptedKey, String fromUsername, String toUserName, String toPublicKey, String keyPath) throws Exception
    {
        File privateKeyFile = new File(keyPath + "/" + fromUsername + ".private");
        byte[] privateKeyBytes = FileUtils.readFileToByteArray(privateKeyFile);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] secretKey = AsymmetricCryptoUtil.decryptWithPrivateKey(privateKey.getEncoded(), Base64.decodeBase64(encryptedKey));

        byte[] toPublicKeyBytes = Base64.decodeBase64(toPublicKey);
        String newEncryptedKey = Base64.encodeBase64String(AsymmetricCryptoUtil.encryptWithPublicKey(toPublicKeyBytes, secretKey));

        String raw = toUserName + "|" + documentId + "|" + newEncryptedKey;
        String signature = Base64.encodeBase64String(AsymmetricCryptoUtil.sign(privateKey.getEncoded(), raw.getBytes()));

        Map<String, String> request = new HashMap<>();
        request.put("to", toUserName);
        request.put("document_id", documentId);
        request.put("encrypted_key", newEncryptedKey);
        request.put("signature", signature);
        System.out.println(GsonProvider.get().toJson(request));
    }

    private static void retrieve(String fileName, String encryptedContent, String encryptedKey, String username, String keyPath) throws Exception
    {
        File privateKeyFile = new File(keyPath + "/" + username + ".private");
        byte[] privateKeyBytes = FileUtils.readFileToByteArray(privateKeyFile);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        byte[] decryptedKey = AsymmetricCryptoUtil.decryptWithPrivateKey(privateKey.getEncoded(), Base64.decodeBase64(encryptedKey));
        byte[] decryptedContent = SymmetricCryptoUtil.decrypt(new String(decryptedKey), Base64.decodeBase64(encryptedContent));

        File file = new File("./" + fileName);
        FileUtils.writeByteArrayToFile(file, decryptedContent);

        System.out.println("Contentent decrypted and saved as " + fileName);
    }
}
