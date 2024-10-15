package com.br.service_token.domain.authorization;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

@Component
public class JsonWebToken {

    private final JsonWebSignature jsonWebSignature;
    private final JsonWebEncryption jsonWebEncryption;

    public JsonWebToken(JsonWebSignature jsonWebSignature, JsonWebEncryption jsonWebEncryption) {
        this.jsonWebSignature = jsonWebSignature;
        this.jsonWebEncryption = jsonWebEncryption;
    }

    public String buildJwsAes(JwtClaims jwtClaims) throws Exception {
        // Chave secreta para assinatura do JWS
        String secretKey = "sua-chave-secreta-deve-ser-muito-segura-e-ter-256-bits";
        byte[] key = secretKey.getBytes();

        // Cria o JWS e assina
        jsonWebSignature.setPayload(jwtClaims.toJson());
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256); // Algoritmo de assinatura HS256
        jsonWebSignature.setKey(new HmacKey(key));  // Define a chave para assinatura
        jsonWebSignature.setDoKeyValidation(false); // Desabilita validação de tamanho da chave

        return jsonWebSignature.getCompactSerialization();
    }

    public String buildJweAes(SecretKey aesKey, JwtClaims jwtClaims) throws JoseException {
        // Cria o JWE e define os parâmetros
        jsonWebEncryption.setPayload(jwtClaims.toJson());
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW); // Algoritmo de gerenciamento de chave (AES Key Wrap)
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM); // Algoritmo de criptografia (AES GCM)
        jsonWebEncryption.setKey(aesKey);

        return jsonWebEncryption.getCompactSerialization();
    }

    public String buildJwsRsa(JwtClaims jwtClaims, PrivateKey privateKey) throws Exception {
        jsonWebSignature.setPayload(jwtClaims.toJson());
        // Define o algoritmo RS256 (RSA com SHA-256)
        jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        // Define a chave privada RSA para assinar o JWS
        jsonWebSignature.setKey(privateKey);
        // Gera a representação compacta do JWS (a string final do JWT assinado)
        return jsonWebSignature.getCompactSerialization();
    }

    public String buildJweRsa(PublicKey aesKey, JwtClaims jwtClaims) throws JoseException {
        // Cria o JWE e define os parâmetros
        jsonWebEncryption.setPayload(jwtClaims.toJson());
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256); // Algoritmo de gerenciamento de chave (AES Key Wrap)
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM); // Algoritmo de criptografia (AES GCM)
        jsonWebEncryption.setKey(aesKey);

        return jsonWebEncryption.getCompactSerialization();
    }
}
