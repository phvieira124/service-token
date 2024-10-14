package com.br.service_token.domain.service;

import com.br.service_token.domain.authorization.Encryption;
import com.br.service_token.domain.authorization.JsonWebToken;
import com.br.service_token.domain.authorization.Key;
import com.br.service_token.domain.model.TokenResponse;
import com.br.service_token.port.input.GenerateTokenUseCase;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.*;

@Service
public class TokenService implements GenerateTokenUseCase {

    private final Key key;

    private final Encryption encryption;

    private final JsonWebToken jsonWebToken;

    public TokenService(Key key, Encryption encryption, JsonWebSignature jsonWebSignature, JsonWebToken jsonWebToken) {
        this.key = key;
        this.encryption = encryption;
        this.jsonWebToken = jsonWebToken;
    }

    public TokenResponse generateTokenJwsAes(String authData) {

        SecretKey secretKeyAes = null;
        try {
            secretKeyAes = key.generateKeyAes();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] iv = key.generateIV();

        System.out.println(key.base64EncodeSecretKey(secretKeyAes));

        // Criptografar o authData com AES GCM
        String encryptedAuthData = null;
        try {
            encryptedAuthData = encryption.encryptAuthDataAes(secretKeyAes, iv, authData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora

        claims.setClaim("authData", encryptedAuthData);

        try {
            return new TokenResponse(jsonWebToken.buildJwsAes(claims));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public TokenResponse generateTokenJweAes(String authData) {

        SecretKey secretKeyAes = null;
        try {
            secretKeyAes = key.generateKeyAes();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] iv = key.generateIV();

        System.out.println(key.base64EncodeSecretKey(secretKeyAes));

        // Criptografar o authData com AES GCM
        String encryptedAuthData = null;
        try {
            encryptedAuthData = encryption.encryptAuthDataAes(secretKeyAes, iv, authData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", encryptedAuthData);  // Inclui o campo authData

        try {
            return new TokenResponse(jsonWebToken.buildJweAes(secretKeyAes, claims));
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    public TokenResponse generateTokenJwsRsa(String authData) {
        // Gera um par de chaves RSA (pública e privada)
        KeyPair keyPair = null;
        try {
            keyPair = key.generateRsaKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Criptografar o authData com a chave pública (RSA)
        String encryptedAuthData = null;
        try {
            encryptedAuthData = encryption.encryptAuthDataRSA(keyPair.getPublic(), authData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", encryptedAuthData);  // Inclui o campo authData

        // Descriptografar o authData com a chave privada (RSA)
        String decryptedAuthData = null;
        try {
            decryptedAuthData = encryption.decryptAuthDataRSA(keyPair.getPrivate(), encryptedAuthData);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("AuthData decriptado: " + decryptedAuthData); // Exibe o conteúdo de authData decriptado

        try {
            return new TokenResponse(jsonWebToken.buildJwsAes(claims));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public TokenResponse generateTokenJweRsa(String authData) {
        // Gerar o par de chaves RSA (chave pública e privada)
        KeyPair rsaKeyPair = null;
        try {
            rsaKeyPair = key.generateRsaKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        PublicKey publicKey = rsaKeyPair.getPublic();

        // Claims principais do JWT (iss, sub, etc.)
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("seu-issuer-aqui"); // Campo iss
        claims.setSubject("phv");            // Campo sub
        claims.setIssuedAtToNow();           // Data de emissão
        claims.setExpirationTimeMinutesInTheFuture(60);  // Expira em 1 hora
        claims.setClaim("authData", authData);  // Inclui o campo authData

        String jweRsa = null;
        try {
            jweRsa = jsonWebToken.buildJweRsa(publicKey, claims);
            System.out.println(encryption.decryptJweRsa(jweRsa, rsaKeyPair.getPrivate()));
            return new TokenResponse(jweRsa);
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }
}
