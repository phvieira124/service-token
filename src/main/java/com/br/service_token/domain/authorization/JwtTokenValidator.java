package com.br.service_token.domain.authorization;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

@Component
public class JwtTokenValidator {
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
}
