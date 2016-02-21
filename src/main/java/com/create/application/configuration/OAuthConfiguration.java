/*
 * Copyright 2016 Sebastian Gil.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.create.application.configuration;

import com.create.security.oauth2.provider.token.SpringCacheTokenStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import static com.create.security.access.Roles.ROLE_ADMIN;

/**
 * OAuth2 {@link Configuration}.
 */
@Configuration
@EnableResourceServer
@EnableAuthorizationServer
public class OAuthConfiguration extends AuthorizationServerConfigurerAdapter {
    public static final String RESOURCE_NAME = "persons";
    @Autowired
    private SpringCacheTokenStore tokenStore;

    @Autowired
    private TokenEnhancer tokenEnhancer;

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("postman")
                .authorities(ROLE_ADMIN)
                .secret("password")
//                .refreshTokenValiditySeconds()
//                .accessTokenValiditySeconds()
                .resourceIds(RESOURCE_NAME)
                .scopes("read", "write")
                .authorizedGrantTypes("client_credentials")
                .secret("password")
                .and()
                .withClient("web")
                .redirectUris("http://github.com/create1st/")
                .resourceIds(RESOURCE_NAME)
                .scopes("read")
                .authorizedGrantTypes("implicit");
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore)
                .tokenEnhancer(tokenEnhancer);
    }


//        <property name="supportRefreshToken" value="true"/>
//        <property name="accessTokenValiditySeconds" value="1200"/>
}
