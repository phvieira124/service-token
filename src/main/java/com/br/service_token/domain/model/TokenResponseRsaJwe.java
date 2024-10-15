package com.br.service_token.domain.model;

public record TokenResponseRsaJwe(String token, String base64PublicKey, String base64PrivateKey, String jwt) {
}
