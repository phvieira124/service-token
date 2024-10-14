package com.br.service_token.configuration;

import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JsonWebConfig {

    @Bean
    public JsonWebSignature jsonWebSignature(){
        return new JsonWebSignature();
    }

    @Bean
    public JsonWebEncryption jsonWebEncryption(){
        return new JsonWebEncryption();
    }
}
