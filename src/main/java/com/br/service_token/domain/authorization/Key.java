package com.br.service_token.domain.authorization;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

@Component
public class Key {

    public SecretKey generateKeyAes() throws NoSuchAlgorithmException {
        // Geração da chave secreta AES de 128 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Tamanho da chave
        return keyGen.generateKey();
    }

    public byte[] generateIV(){
        // Geração do IV (Initialization Vector) de 12 bytes para GCM
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        return iv;
    }

    public String base64EncodeSecretKey(SecretKey aesKey) {
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }

    // Método para gerar um par de chaves RSA
    public KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Tamanho da chave RSA
        return keyPairGenerator.generateKeyPair();
    }

}
