package com.br.service_token.adapter.input;

import com.br.service_token.domain.service.TokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1")
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping(value = "/token/jws")
    public ResponseEntity<?> generateTokenJWS(@RequestBody String authData) throws Exception {
        String token = tokenService.generateJws(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe")
    public ResponseEntity<?> generateTokenJWE(@RequestBody String authData) throws Exception {
        String token = tokenService.generateJwe(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jws/rsa")
    public ResponseEntity<?> generateTokenJwsRsa(@RequestBody String authData) throws Exception {
        String token = tokenService.generateJwsRSA(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

    @GetMapping(value = "/token/jwe/rsa")
    public ResponseEntity<?> generateToken(@RequestBody String authData) throws Exception {
        String token = tokenService.generateJweRSA(authData);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }

}
