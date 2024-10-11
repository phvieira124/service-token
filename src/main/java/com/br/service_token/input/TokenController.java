package com.br.service_token.input;

import com.br.service_token.domain.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1")
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping(value = "/token")
    public ResponseEntity<?> generateToken() throws Exception {
        String token = tokenService.generateJws();
        return ResponseEntity.status(200).body(token);
    }

}
