package com.br.service_token.domain.authorization;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Component;

import java.security.AlgorithmConstraints;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.jose4j.jws.*;

@Component
public class JwtTokenValidator {

    private final JsonWebEncryption jsonWebEncryption;

    public JwtTokenValidator(JsonWebEncryption jsonWebEncryption) {
        this.jsonWebEncryption = jsonWebEncryption;
    }

    // Método para validar o JWT recebido
    public boolean validateJwt(String jwt, PublicKey publicKey) {
        try {
            // Configura o JwtConsumer para validar a assinatura e as claims do JWT
            JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime()               // O JWT deve ter um tempo de expiração
                    .setVerificationKey(publicKey)            // Usa a chave pública para verificar a assinatura
                    .setExpectedSubject("phv")  // Verifica se o 'subject' é esperado
                    .build();

            // Processa o JWT e valida
            JwtClaims claims = jwtConsumer.processToClaims(jwt);

            // Verifique as claims, como os escopos ou outras regras de negócio
            if (claims.getIssuer() != null && claims.getStringListClaimValue("scopes") != null) {
                // JWT válido
                return true;
            }
        } catch (InvalidJwtException | MalformedClaimException e) {
            // JWT inválido ou não pôde ser verificado
            System.out.println("Invalid JWT: " + e.getMessage());
            return false;
        }

        return false;
    }

    // Método para validar o JWE e JWS (assinado e criptografado)
    public boolean validateJweJws(String jweToken, PrivateKey privateKey, PublicKey publicKey) throws InvalidJwtException, JoseException {
        // Extrair o cabeçalho do JWE para obter o "kid" (isso pode variar conforme implementação)
        String kid = getKidFromJweHeader(jweToken);
        System.out.println("KID encontrado: " + kid);

        jsonWebEncryption.setCompactSerialization(jweToken);
        jsonWebEncryption.setKey(privateKey);

        // Obter o payload que é o JWS (token assinado)
        String signedJwt = jsonWebEncryption.getPlaintextString();

        System.out.println("Token assinado (JWS) extraído do JWE: " + signedJwt);

        return validateJwt(signedJwt, publicKey);
    }

    // Método para extrair o "kid" do cabeçalho do JWE
    public String getKidFromJweHeader(String jwe) {
        // Lógica para extrair o cabeçalho e obter o KID
        String[] parts = jwe.split("\\.");
        String encodedHeader = parts[0];
        // Decodificar o cabeçalho e analisar como JSON
        // ...
        return "kid-value"; // Simulação - retornar o "kid" extraído
    }
}
