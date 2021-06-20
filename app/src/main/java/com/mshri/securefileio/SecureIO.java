package com.mshri.securefileio;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;

public class SecureIO {

    public static String getKeySecretFromKeyVault(String keySecretName) {
        return "qwerty12345";
    }
    
    public static PGPSecretKey readSecretKey(String secretKeyPath, long keyId) throws IOException, PGPException {
        var in = PGPUtil.getDecoderStream(new FileInputStream(new File(secretKeyPath)));
        
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPSecretKey key = pgpSec.getSecretKey(keyId);

        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    @SuppressWarnings("rawtypes")
    public static PGPPublicKey readPublicKey(String publicKeyPath) throws IOException, PGPException {
        var in = PGPUtil.getDecoderStream(new FileInputStream(new File(publicKeyPath)));
        
        PGPPublicKeyRingCollection pgpKeyRingCollection = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPPublicKey key = null;
        Iterator iterKeyRings = pgpKeyRingCollection.getKeyRings();
        while (key == null && iterKeyRings.hasNext()) {
            PGPPublicKeyRing pgpKeyRing = (PGPPublicKeyRing) iterKeyRings.next();
            Iterator iterPublicKeys = pgpKeyRing.getPublicKeys();
            while (key == null && iterPublicKeys.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) iterPublicKeys.next();
                if (k.isEncryptionKey()) {
                    key = k;
                }
            }
        }
        if (key == null) {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }

    public static byte[] readEncryptedFile(String filePath, String secretKeyPath, String secretKeyPassword) throws IOException, PGPException, InvalidCipherTextException {
        Security.addProvider(new BouncyCastleProvider());

        var in = PGPUtil.getDecoderStream(new FileInputStream(new File(filePath)));

        JcaPGPObjectFactory jcaPgpObjectFact;
        PGPObjectFactory pgpObjectFact = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        Object pgpObj = pgpObjectFact.nextObject();

        PGPEncryptedDataList encDataList;
        if (pgpObj instanceof PGPEncryptedDataList) {
            encDataList = (PGPEncryptedDataList) pgpObj;
        } else {
            encDataList = (PGPEncryptedDataList) pgpObjectFact.nextObject();
        }

        Iterator<?> iterEncDataObjs = encDataList.getEncryptedDataObjects();
        PGPSecretKey secretKey = null;
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncData = null;
        while (privateKey == null && iterEncDataObjs.hasNext()) {
            publicKeyEncData = (PGPPublicKeyEncryptedData) iterEncDataObjs.next();
            secretKey = readSecretKey(secretKeyPath, publicKeyEncData.getKeyID());
            privateKey = secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(secretKeyPassword.toCharArray()));
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        InputStream dataStream = publicKeyEncData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
        jcaPgpObjectFact = new JcaPGPObjectFactory(dataStream);

        PGPCompressedData compressedData = (PGPCompressedData) jcaPgpObjectFact.nextObject();
        jcaPgpObjectFact = new JcaPGPObjectFactory(compressedData.getDataStream());

        PGPLiteralData literalData = (PGPLiteralData) jcaPgpObjectFact.nextObject();
        ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
        InputStream inputStream = literalData.getDataStream();

        int ch;
        while ((ch = inputStream.read()) >= 0) {
            byteOutStream.write(ch);
        }

        return byteOutStream.toByteArray();
    }

    public static void writeEncryptedFile(String filePath, byte[] data, String publicKeyPath) throws IOException, NoSuchProviderException, PGPException {
        Security.addProvider(new BouncyCastleProvider());

        FileOutputStream fileOutStream = new FileOutputStream(new File(filePath));
        ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();

        PGPCompressedDataGenerator compressedDataGen = new PGPCompressedDataGenerator(
            PGPCompressedDataGenerator.ZIP
        );
        OutputStream compressedOutStream = compressedDataGen.open(byteOutStream);
        
        PGPLiteralDataGenerator literalDataGen = new PGPLiteralDataGenerator();
        OutputStream literalOutStream = literalDataGen.open(
            compressedOutStream, PGPLiteralData.TEXT, "Report.csv", data.length, new Date()
        );
        literalOutStream.write(data);

        literalDataGen.close();
        compressedDataGen.close();

        PGPEncryptedDataGenerator encDataGen = new PGPEncryptedDataGenerator(
            new BcPGPDataEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256
            ).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
        );
        encDataGen.addMethod(
            new BcPublicKeyKeyEncryptionMethodGenerator(
                readPublicKey(publicKeyPath)
            )
        );

        byte[] bytes = byteOutStream.toByteArray();
        OutputStream encOutStream = encDataGen.open(fileOutStream, bytes.length);
        encOutStream.write(bytes);
        encOutStream.close();
    }

    public static void decryptFile(String inputFilePath, String outputFilePath, String secretKeyPath, String secretKeyPassword) {
        try {
            System.out.println("Reading and decrypting " + inputFilePath);
            byte[] plainData = readEncryptedFile(inputFilePath, secretKeyPath, secretKeyPassword);
            System.out.println("Done. Now writing...");
            FileOutputStream fileOutStream = new FileOutputStream(new File(outputFilePath));
            fileOutStream.write(plainData);
            System.out.println("Written to " + outputFilePath);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static void encryptFile(String inputFilePath, String outputFilePath, String publicKeyPath) {
        try {
            System.out.println("Readin " + inputFilePath);
            FileInputStream fileInStream= new FileInputStream(new File(inputFilePath));
            byte[] encryptedData = fileInStream.readAllBytes();
            System.out.println("Read. Now encrypting and writing...");
            writeEncryptedFile(outputFilePath, encryptedData, publicKeyPath);
            System.out.println("Written to " + outputFilePath);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static List<String> readSecureFileAsStrList(String filePath, String secretKeyPath, String keySecretName) throws InvalidCipherTextException, IOException, PGPException {
        
        String secretKeyPassword = getKeySecretFromKeyVault(keySecretName);
        byte[] bytes = readEncryptedFile(filePath, secretKeyPath, secretKeyPassword);
        
        List<String> lines = new ArrayList<String>();

        if (bytes == null) {
            return lines;
        }

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(new ByteArrayInputStream(bytes))
        );
        for (String line = reader.readLine(); line != null; line = reader.readLine()) {
            lines.add(line);
        }
        reader.close();
        return lines;
    }

    public static void writeStrListToSecureFile(String filePath, String publicKeyPath, List<String> strList) throws IOException, NoSuchProviderException, PGPException {
        ByteArrayOutputStream byteOutStrem = new ByteArrayOutputStream();
        DataOutputStream dataOutStream = new DataOutputStream(byteOutStrem);
        for (String item : strList) {
            dataOutStream.writeUTF(item + System.lineSeparator());
        }
        byte[] bytes = byteOutStrem.toByteArray();
        writeEncryptedFile(filePath, bytes, publicKeyPath);
    }
}
