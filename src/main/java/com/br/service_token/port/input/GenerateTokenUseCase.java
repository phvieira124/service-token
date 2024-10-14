package com.br.service_token.port.input;

import com.br.service_token.domain.model.TokenResponse;

public interface GenerateTokenUseCase {

    TokenResponse generateTokenJwsAes(String authData);

    TokenResponse generateTokenJweAes(String authData);

    TokenResponse generateTokenJwsRsa(String authData);

    TokenResponse generateTokenJweRsa(String authData);
}
