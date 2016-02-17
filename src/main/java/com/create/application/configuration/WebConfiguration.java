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

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


/**
 * Web configuration.
 */
@Configuration
@ComponentScan(basePackages = "com.create.controller")
@EnableWebSecurity
public class WebConfiguration {
//    @Configuration
//    @EnableAuthorizationServer
//    public static class OAuth2Config extends AuthorizationServerConfigurerAdapter {
//        @Autowired
//        private TokenStore tokenStore;
//
//        @Autowired
//        private TokenEnhancer tokenEnhancer;
//
//        @Autowired
//        private AuthenticationManager authenticationManager;
//
//        @Override
//        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//            endpoints
//                    .authenticationManager(authenticationManager)
//                    .tokenStore(tokenStore)
//                    .tokenEnhancer(tokenEnhancer);
//        }
//
//        @Override
//        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//            clients.inMemory()
//                    .withClient("acme")
//                    .secret("acmesecret")
//                    .authorizedGrantTypes("authorization_code", "refresh_token",
//                            "password").scopes("openid");
//        }
////        <property name="supportRefreshToken" value="true"/>
////        <property name="accessTokenValiditySeconds" value="1200"/>
//    }
}
