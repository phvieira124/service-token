package com.br.service_token.domain.authorization;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class Encryption {

    private final JsonWebEncryption jsonWebEncryption;

    public Encryption(JsonWebEncryption jsonWebEncryption) {
        this.jsonWebEncryption = jsonWebEncryption;
    }


    public String encryptAuthDataAes(SecretKey aesKey, byte[] iv, String authData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // Tag length de 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Criptografa o authData
        byte[] encryptedBytes = cipher.doFinal(authData.getBytes());

        // Retorna o authData criptografado em base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descriptografar o authData
    public String decryptAuthDataAes(SecretKey aesKey, byte[] iv, String encryptedAuthData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);  // Tamanho do tag de autenticação é 128 bits
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Decodifica o valor criptografado de base64 e realiza a descriptografia
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedAuthData);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Retorna o authData descriptografado como string
        return new String(decryptedBytes);
    }

    // Método para descriptografar o JWE e acessar o campo authData
    public String decryptJweAes(String jweString, SecretKey aesKey) throws InvalidJwtException, JoseException {
        // Configura o JWE para descriptografia
        jsonWebEncryption.setCompactSerialization(jweString);  // Define o JWE a ser descriptografado
        jsonWebEncryption.setKey(aesKey);  // Define a chave para descriptografar

        // Descriptografa e obtém o payload (JWT Claims)
        String payload = jsonWebEncryption.getPayload();

        // Parseia as claims do JWT
        JwtClaims claims = JwtClaims.parse(payload);

        // Acessa o campo "authData"
        String authData = (String) claims.getClaimValue("authData");

        return authData;
    }

    // Método para criptografar authData com chave pública (RSA)
    public String encryptAuthDataRSA(PublicKey publicKey, String authData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Criptografa o authData
        byte[] encryptedBytes = cipher.doFinal(authData.getBytes());

        // Retorna o authData criptografado em base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descriptografar authData com chave privada (RSA)
    public String decryptAuthDataRSA(PrivateKey privateKey, String encryptedAuthData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decodifica o valor criptografado de base64 e realiza a descriptografia
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedAuthData);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Retorna o authData descriptografado como string
        return new String(decryptedBytes);
    }

    public String decryptJweRsa(String jweString, PrivateKey privateKey) throws JoseException {
        jsonWebEncryption.setCompactSerialization(jweString);

        // Define a chave privada RSA para descriptografar o JWE
        jsonWebEncryption.setKey(privateKey);

        return jsonWebEncryption.getPayload(); // Retorna o payload descriptografado
    }

    private String toBase64(byte[] keyBytes) {
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public Map<String, String> showKeys(KeyPair keyPair){
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        Map<String, String> keys = new HashMap<>();
        keys.put("public", toBase64(publicKeyBytes));
        keys.put("private", toBase64(privateKeyBytes));

        return keys;
    }

}
