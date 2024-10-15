package com.br.service_token.adapter.input;

import com.br.service_token.domain.model.TokenResponseAes;
import com.br.service_token.domain.model.TokenResponseRsa;
import com.br.service_token.domain.model.TokenResponseRsaJwe;
import com.br.service_token.domain.model.ValidationResponse;
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
    public ResponseEntity<TokenResponseAes> generateTokenJWS(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJwsAes(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe")
    public ResponseEntity<TokenResponseAes> generateTokenJWE(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJweAes(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jws/rsa")
    public ResponseEntity<TokenResponseRsa> generateTokenJwsRsa(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJwsRsa(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe/rsa")
    public ResponseEntity<TokenResponseRsaJwe> generateToken(@RequestBody String authData) {
        var token = generateTokenUseCase.generateTokenJweRsa(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/validation")
    public ResponseEntity<ValidationResponse> validationToken(){
        var token = generateTokenUseCase.validationTokenRsa();
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

}
