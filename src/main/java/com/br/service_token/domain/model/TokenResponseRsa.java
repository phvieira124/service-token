package com.br.service_token.domain.model;

public record TokenResponseRsa (String token, String base64PublicKey, String base64PrivateKey) {
}
