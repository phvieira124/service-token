package com.br.service_token.domain.authorization;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

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

    public String buildJweRsaSigned(JwtClaims jwtClaims, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        String signedJwt = buildJwsRsa(jwtClaims, privateKey);

        jsonWebEncryption.setPayload(signedJwt); // O payload do JWE é o JWS (token assinado)
        jsonWebEncryption.setKey(publicKey); // Chave pública usada para criptografar
        jsonWebEncryption.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256); // Algoritmo de criptografia de chave
        jsonWebEncryption.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM); // Algoritmo de criptografia do conteúdo (payload)

        return jsonWebEncryption.getCompactSerialization();
    }

    public String updateToken(String publicKeyPem, String privateKeyPem, String jwsCompactSerialization){

        // Carregar a chave pública no formato correto
        PublicKey publicKey = null;
        try {
            publicKey = getPublicKeyFromPem(publicKeyPem);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // Verificar o JWS
        boolean isValid = false;
        try {
            isValid = verifyJws(jwsCompactSerialization, publicKey);
        } catch (JoseException e) {
            throw new RuntimeException(e);
        }

        JwtClaims jwtClaims = null;
        try {
            jwtClaims = getJwtClaims(jwsCompactSerialization, publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if (isValid) {
            System.out.println("A assinatura do JWS é válida!");
            if (jwtClaims != null) {
                // Passo 2: Modificar as claims (adicionar novas claims ou atualizar a expiração)
                jwtClaims.setExpirationTimeMinutesInTheFuture(60); // Atualizar expiração para 60 minutos a partir de agora
                jwtClaims.setClaim("novaClaim", "valorDaNovaClaim"); // Adicionar nova claim
                jwtClaims.setClaim("authData", "valorDaNovaClaimUpdate");

                // Passo 3: Assinar e gerar um novo JWS com as claims modificadas
                PrivateKey privateKey = null;
                try {
                    privateKey = getPrivateKeyFromPem(privateKeyPem);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                String newJws = null;
                try {
                    newJws = buildJwsRsa(jwtClaims, privateKey);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

               return newJws;
            } else {
                System.out.println("A verificação falhou. JWS inválido.");
            }
        } else {
            System.out.println("A assinatura do JWS é inválida!");
        }
        return "";
    }

    // Método para verificar o JWS
    public static boolean verifyJws(String jwsCompactSerialization, PublicKey publicKey) throws JoseException {
        // Criar uma instância do JWS para descompactar
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        jws.setKey(publicKey); // Usar a chave pública

        // Verificar se o JWS é válido
        return jws.verifySignature();
    }

    // Método para carregar a chave pública RSA do formato PEM
    public static PublicKey getPublicKeyFromPem(String pem) throws Exception {
        // Remover os cabeçalhos e rodapés PEM
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // Remover todos os espaços

        // Decodificar a chave pública
        byte[] encoded = Base64.getDecoder().decode(pem);

        // Converter os bytes para uma chave pública
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    // Método para verificar o JWS e obter as claims
    public static JwtClaims getJwtClaims(String jwsCompactSerialization, PublicKey publicKey) throws Exception {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // O token deve expirar
                .setVerificationKey(publicKey) // Usar a chave pública para verificar a assinatura
                .build();

        try {
            // Verifica e retorna as claims
            return jwtConsumer.processToClaims(jwsCompactSerialization);
        } catch (Exception e) {
            System.out.println("Erro ao verificar o JWS: " + e.getMessage());
            return null;
        }
    }

    // Método para carregar a chave privada do formato PEM
    public static PrivateKey getPrivateKeyFromPem(String pem) throws Exception {
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(pem);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }
}
