package com.br.service_token.port.input;

import com.br.service_token.domain.model.TokenResponse;

public interface GenerateTokenUseCase {

    TokenResponse generateTokenJwsAes();

    TokenResponse generateTokenJweAes();

    TokenResponse generateTokenJwsRsa();

    TokenResponse generateTokenJweRsa();
}
