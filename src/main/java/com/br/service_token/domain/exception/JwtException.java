package com.br.service_token.domain.exception;

public class JwtException extends RuntimeException{

    public JwtException(String message){
        super(message);
    }

}
