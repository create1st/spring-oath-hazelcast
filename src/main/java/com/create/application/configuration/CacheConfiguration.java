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

import com.create.security.oauth2.provider.token.ApprovalKeyGenerator;
import com.create.security.oauth2.provider.token.OAuth2AccessTokenKeyGenerator;
import com.create.security.oauth2.provider.token.OAuth2AuthenticationKeyGenerator;
import com.create.security.oauth2.provider.token.OAuth2RefreshTokenKeyGenerator;
import com.create.security.oauth2.provider.token.SpringCacheTokenStoreImpl;
import com.create.security.oauth2.repository.TokenRepository;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

/**
 * Cache configuration.
 */
@Configuration
@EnableCaching
public class CacheConfiguration {
    @Bean
    public TokenRepository tokenRepository() {
        return new TokenRepository();
    }

    @Bean(name = SpringCacheTokenStoreImpl.APPROVAL_KEY_GENERATOR)
    public ApprovalKeyGenerator approvalKeyGenerator() {
        return new ApprovalKeyGenerator();
    }

    @Bean(name = SpringCacheTokenStoreImpl.OAUTH2_ACCESS_TOKEN_KEY_GENERATOR)
    public OAuth2AccessTokenKeyGenerator oauth2AccessTokenKeyGenerator() {
        return new OAuth2AccessTokenKeyGenerator();
    }

    @Bean(name = SpringCacheTokenStoreImpl.OAUTH2_AUTHENTICATION_KEY_GENERATOR)
    public OAuth2AuthenticationKeyGenerator oauth2AuthenticationKeyGenerator() {
        return new OAuth2AuthenticationKeyGenerator(new DefaultAuthenticationKeyGenerator());
    }

    @Bean(name = SpringCacheTokenStoreImpl.OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public OAuth2RefreshTokenKeyGenerator oauth2RefreshTokenKeyGenerator() {
        return new OAuth2RefreshTokenKeyGenerator();
    }
}
