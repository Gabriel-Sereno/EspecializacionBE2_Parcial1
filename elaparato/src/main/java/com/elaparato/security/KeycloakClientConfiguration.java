package com.elaparato.security;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakClientConfiguration {

    @Value("${el-aparato-sereno.keycloak.serverUrl}")
    private String serverUrl;

    @Value("${el-aparato-sereno.keycloak.realm}")
    private String realm;

    @Value("${el-aparato-sereno.keycloak.clientId}")
    private String clientId;

    @Value("${el-aparato-sereno.keycloak.clientSecret}")
    private String clientSecret;

    @Bean
    public Keycloak getInstance() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

}
