package com.br.service_token.domain.service;

import com.br.service_token.domain.authorization.Encrypt;
import com.br.service_token.domain.authorization.JWT;
import com.br.service_token.domain.authorization.Key;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.sql.SQLOutput;
import java.util.Base64;

@Service
public class TokenService {

    private final Key key;

    private final Encrypt encrypt;

    private final JWT jwt;

    public TokenService(Key key, Encrypt encrypt, JsonWebSignature jsonWebSignature, JWT jwt) {
        this.key = key;
        this.encrypt = encrypt;
        this.jwt = jwt;
    }

    public String generateJws(String authData) throws Exception {

        SecretKey secretKeyAes = key.generateKeyAes();
        byte[] iv = key.generateIV();

        System.out.println(key.base64EncodeSecretKey(secretKeyAes));

        // Criptografar o authData com AES GCM
        String encryptedAuthData = encrypt.encryptAuthData(secretKeyAes, iv, authData);

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora

        claims.setClaim("authData", encryptedAuthData);

        return jwt.buildJws(claims);
    }

    public String generateJwe(String authData) throws Exception {

        SecretKey secretKeyAes = key.generateKeyAes();
        byte[] iv = key.generateIV();

        System.out.println(key.base64EncodeSecretKey(secretKeyAes));

        // Criptografar o authData com AES GCM
        String encryptedAuthData = encrypt.encryptAuthData(secretKeyAes, iv, authData);

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", encryptedAuthData);  // Inclui o campo authData

        return jwt.buildJwe(secretKeyAes, claims);
    }

    public String generateJwsRSA(String authData) throws Exception {
        // Gera um par de chaves RSA (pública e privada)
        KeyPair keyPair = key.generateRsaKeyPair();

        // Criptografar o authData com a chave pública (RSA)
        String encryptedAuthData = encrypt.encryptAuthDataRSA(keyPair.getPublic(), authData);

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", encryptedAuthData);  // Inclui o campo authData

        // Descriptografar o authData com a chave privada (RSA)
        String decryptedAuthData = encrypt.decryptAuthDataRSA(keyPair.getPrivate(), encryptedAuthData);
        System.out.println("AuthData decriptado: " + decryptedAuthData); // Exibe o conteúdo de authData decriptado

        return jwt.buildJws(claims);
    }

    public String generateJweRSA(String authData) throws Exception {
        // Gerar o par de chaves RSA (chave pública e privada)
        KeyPair rsaKeyPair = key.generateRsaKeyPair();
        PublicKey publicKey = rsaKeyPair.getPublic();

        // Geração de uma chave AES simétrica para criptografar o conteúdo
        SecretKey aesKey = key.generateKeyAes();

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", authData);  // Inclui o campo authData

        return jwt.buildJwe(publicKey, claims);
    }
}
