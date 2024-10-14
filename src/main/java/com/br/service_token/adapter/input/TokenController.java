package com.br.service_token.adapter.input;

import com.br.service_token.domain.model.TokenResponse;
import com.br.service_token.domain.service.TokenService;
import com.br.service_token.port.input.GenerateTokenUseCase;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1")
public class TokenController {

    private final GenerateTokenUseCase generateTokenUseCase;

    public TokenController(GenerateTokenUseCase generateTokenUseCase) {
        this.generateTokenUseCase = generateTokenUseCase;
    }

    @GetMapping(value = "/token/jws")
    public ResponseEntity<TokenResponse> generateTokenJWS(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJwsAes(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe")
    public ResponseEntity<TokenResponse> generateTokenJWE(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJweAes(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jws/rsa")
    public ResponseEntity<TokenResponse> generateTokenJwsRsa(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJwsRsa(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe/rsa")
    public ResponseEntity<TokenResponse> generateToken(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJweRsa(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

}
