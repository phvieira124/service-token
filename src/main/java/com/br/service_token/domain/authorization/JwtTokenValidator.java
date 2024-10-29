package com.br.service_token.domain.authorization;

import com.br.service_token.domain.exception.JwtException;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

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

    // Método para descriptografar o JWE e acessar as claims
    public boolean validateJwe(String jweToken, PrivateKey privateKey) throws JoseException, InvalidJwtException, MalformedClaimException {
        // Inicializar o JsonWebEncryption com o token
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jweToken);

        // Definir a chave privada para descriptografar
        jwe.setKey(privateKey);

        // Obter o payload descriptografado, que neste caso será um JWT
        String decryptedPayload = jwe.getPlaintextString();

        // Parsear as claims do JWT descriptografado
        JwtClaims claims = JwtClaims.parse(decryptedPayload);

        try{
            // Validação manual das claims
            validateStandardClaims(claims);
            // Validação de claims personalizadas (adapte conforme seu cenário)
            validateCustomClaims(claims);
        }catch (JwtException e){
            return false;
        }
        return true;
    }

    // Método para validar claims padrão como expiração, emissor, assunto, etc.
    private void validateStandardClaims(JwtClaims claims) throws InvalidJwtException, MalformedClaimException {
        // Verificar se o token expirou

        NumericDate issuedAt = claims.getIssuedAt();

        if (issuedAt == null) {
            throw new JwtException("Claim 'iat' (Issued At) está ausente no token.");
        }

        // Obter o tempo atual em segundos desde o Epoch
        long currentTimeInSeconds = Instant.now().getEpochSecond();

        // Tempo em segundos que o token foi emitido
        long issuedAtTimeInSeconds = issuedAt.getValue();

        // Diferença de tempo entre agora e o momento em que o token foi emitido
        long differenceInSeconds = currentTimeInSeconds - issuedAtTimeInSeconds;

        // Validar se o token foi gerado exatamente há 10 segundos
        if (differenceInSeconds > 10) {
            throw new JwtException("Token expirado");
        }

        // Verificar o emissor (iss)
        String expectedIssuer = "phv";
        String issuer = claims.getIssuer();
        if (!expectedIssuer.equals(issuer)) {
            throw new JwtException("Emissor inválido. Esperado: " + expectedIssuer);
        }

        // Verificar o subject (sub)
        String expectedSubject = "phv-token";
        String subject = claims.getSubject();
        if (!expectedSubject.equals(subject)) {
            throw new JwtException("Subject inválido. Esperado: " + expectedSubject);
        }

        // Exemplo de verificar uma audiência (aud)
        String audience = claims.getAudience().get(0);
        if (!"service-token".equals(audience)) {
            throw new JwtException("Audiência inválida.");
        }
    }

    // Método para validar claims personalizadas (adapte conforme suas necessidades)
    private void validateCustomClaims(JwtClaims claims) throws InvalidJwtException, MalformedClaimException {
        // Validar uma claim de tipo numérico
        String userId = claims.getClaimValue("userId").toString();
        if (!userId.equals("123123")) {
            throw new JwtException("User ID inválido.");
        }
    }

    // Método para carregar uma PrivateKey a partir de uma string PEM
    public static PrivateKey getPrivateKeyFromPEM(String pem) throws Exception {
        // Remover cabeçalhos e rodapés do PEM e decodificar a base64
        String privateKeyPEM = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        // Gerar chave privada a partir da especificação PKCS8
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }
}
