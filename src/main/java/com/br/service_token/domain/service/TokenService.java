package com.br.service_token.domain.service;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class TokenService {

    public String generateJws() throws Exception {
        // Geração da chave secreta AES de 128 bits
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Tamanho da chave
        SecretKey aesKey = keyGen.generateKey();

        // Geração do IV (Initialization Vector) de 12 bytes para GCM
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Campo authData com o CPF
        String authData = """
                {"cpf":"1234"}
                """;

        // Criptografar o authData com AES GCM
        String encryptedAuthData = encryptAuthData(aesKey, iv, authData);

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora

        claims.setClaim("authData", encryptedAuthData);  // Inclui o campo authData

        String decript = decryptAuthData(aesKey, iv, encryptedAuthData);

        System.out.println(decript); //print dado decriptado

        // Chave secreta para assinatura do JWS
        String secretKey = "sua-chave-secreta-deve-ser-muito-segura-e-ter-256-bits";
        byte[] key = secretKey.getBytes();

        // Cria o JWS e assina
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256); // Algoritmo de assinatura HS256
        jws.setKey(new HmacKey(key));  // Define a chave para assinatura
        jws.setDoKeyValidation(false); // Desabilita validação de tamanho da chave

        // Gera o JWS
        String jwsString = jws.getCompactSerialization();

        return jwsString;
    }

    private static String encryptAuthData(SecretKey aesKey, byte[] iv, String authData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // Tag length de 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Criptografa o authData
        byte[] encryptedBytes = cipher.doFinal(authData.getBytes());

        // Retorna o authData criptografado em base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Método para descriptografar o authData
    private static String decryptAuthData(SecretKey aesKey, byte[] iv, String encryptedAuthData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);  // Tamanho do tag de autenticação é 128 bits
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Decodifica o valor criptografado de base64 e realiza a descriptografia
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedAuthData);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Retorna o authData descriptografado como string
        return new String(decryptedBytes);
    }

}
