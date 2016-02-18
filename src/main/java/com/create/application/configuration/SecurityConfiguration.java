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

import com.create.security.oauth2.provider.token.AuthenticatedUserTokenEnhancer;
import com.create.security.oauth2.provider.token.SpringCacheTokenStore;
import com.create.security.oauth2.provider.token.SpringCacheTokenStoreImpl;
import com.create.security.oauth2.repository.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * Security configuration.
 */
@Configuration
public class SecurityConfiguration {
    @Bean
    public SpringCacheTokenStore tokenStore(final TokenRepository tokenRepository) {
        return new SpringCacheTokenStoreImpl(tokenRepository, new DefaultAuthenticationKeyGenerator());
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new AuthenticatedUserTokenEnhancer();
    }

    @Autowired
    private CacheManager cacheManager;


    //    @Configuration
//    protected static class OAuth2Config {
//
//        @Autowired
//        private ClientDetailsService clientDetailsService;
//
//        @Bean
//        public DefaultTokenServices tokenServices(final TokenStore tokenStore) {
//            DefaultTokenServices services = new DefaultTokenServices();
//            services.setClientDetailsService(clientDetailsService);
//            services.setSupportRefreshToken(true);
//            services.setTokenStore(tokenStore);
//            return services;
//        }
//
//        @Bean
//        public WhitelabelErrorEndpoint oauth2ErrorEndpoint() {
//            return new WhitelabelErrorEndpoint();
//        }
//
//        @Bean
//        public WhitelabelApprovalEndpoint oauth2ApprovalEndpoint() {
//            return new WhitelabelApprovalEndpoint();
//        }
//
//    }
}
