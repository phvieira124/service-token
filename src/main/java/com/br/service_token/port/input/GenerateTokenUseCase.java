package com.br.service_token.port.input;

import com.br.service_token.domain.model.TokenResponseAes;
import com.br.service_token.domain.model.TokenResponseRsa;
import com.br.service_token.domain.model.TokenResponseRsaJwe;
import com.br.service_token.domain.model.ValidationResponse;

public interface GenerateTokenUseCase {

    TokenResponseAes generateTokenJwsAes(String authData);

    TokenResponseAes generateTokenJweAes(String authData);

    TokenResponseRsa generateTokenJwsRsa(String authData);

    TokenResponseRsaJwe generateTokenJweRsa(String authData);

    ValidationResponse validationTokenRsa();

    TokenResponseRsa updateJws();

}
