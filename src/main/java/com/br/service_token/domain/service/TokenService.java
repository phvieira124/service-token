package com.br.service_token.domain.service;

import com.br.service_token.domain.authorization.Encryption;
import com.br.service_token.domain.authorization.JsonWebToken;
import com.br.service_token.domain.authorization.JwtTokenValidator;
import com.br.service_token.domain.authorization.Key;
import com.br.service_token.domain.model.TokenResponseAes;
import com.br.service_token.domain.model.TokenResponseRsa;
import com.br.service_token.domain.model.TokenResponseRsaJwe;
import com.br.service_token.domain.model.ValidationResponse;
import com.br.service_token.port.input.GenerateTokenUseCase;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Service
public class TokenService implements GenerateTokenUseCase {

    private final Key key;

    private final Encryption encryption;

    private final JsonWebToken jsonWebToken;

    private final JwtTokenValidator jwtTokenValidator;

    public TokenService(Key key, Encryption encryption, JsonWebSignature jsonWebSignature, JsonWebToken jsonWebToken, JwtTokenValidator jwtTokenValidator) {
        this.key = key;
        this.encryption = encryption;
        this.jsonWebToken = jsonWebToken;
        this.jwtTokenValidator = jwtTokenValidator;
    }

    @Override
    public TokenResponseAes generateTokenJwsAes(String authData) {

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
            return new TokenResponseAes(jsonWebToken.buildJwsAes(claims));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public TokenResponseAes generateTokenJweAes(String authData) {

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
            return new TokenResponseAes(jsonWebToken.buildJweAes(secretKeyAes, claims));
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public TokenResponseRsa generateTokenJwsRsa(String authData) {
        // Gera um par de chaves RSA (pública e privada)
        KeyPair keyPair = null;
        try {
            keyPair = key.generateRsaKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Map<String, String> keys = encryption.showKeys(keyPair);

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
            return new TokenResponseRsa(jsonWebToken.buildJwsRsa(claims, keyPair.getPrivate()), keys.get("public"), keys.get("private"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public TokenResponseRsaJwe generateTokenJweRsa(String authData) {
        // Gerar o par de chaves RSA (chave pública e privada)
        KeyPair keyPair = null;
        try {
            keyPair = key.generateRsaKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        Map<String, String> keys = encryption.showKeys(keyPair);
        PublicKey publicKey = keyPair.getPublic();

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
            return new TokenResponseRsaJwe(jweRsa, keys.get("public"), keys.get("private"), encryption.decryptJweRsa(jweRsa, keyPair.getPrivate()));
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ValidationResponse validationTokenRsa() {
        TokenResponseRsa tokenResponseAesRsa = generateTokenJwsRsa("""
                {
                    "cpf": 1234
                }""");

        // Converte a string Base64 em uma instância de PublicKey
        PublicKey publicKey = null;
        try {
            publicKey = key.getPublicKeyFromBase64(tokenResponseAesRsa.base64PublicKey());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new ValidationResponse(tokenResponseAesRsa.token(), jwtTokenValidator.validateJwt(tokenResponseAesRsa.token(), publicKey));
    }

    @Override
    public TokenResponseRsa updateJws(){
        TokenResponseRsa tokenResponseRsa = generateTokenJwsRsa("""
                {
                    "cpf": 1234
                }""");

        var token = jsonWebToken.updateToken(tokenResponseRsa.base64PublicKey(),tokenResponseRsa.base64PrivateKey(), tokenResponseRsa.token());
        return new TokenResponseRsa(token, tokenResponseRsa.base64PrivateKey(), tokenResponseRsa.base64PublicKey());
    }
}
