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

package com.create.security.oauth2.repository;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Collection;
import java.util.HashSet;

public class TokenRepository {
    public static final String OAUTH2_ACCESS_TOKEN_KEY_GENERATOR = "oauth2AccessTokenKeyGenerator";
    public static final String OAUTH2_REFRESH_TOKEN_KEY_GENERATOR = "oauth2RefreshTokenKeyGenerator";
    public static final String OAUTH2_AUTHENTICATION_KEY_GENERATOR = "oauth2AuthenticationKeyGenerator";
    public static final String ACCESS_TOKEN_CACHE = "accessTokenStore";
    public static final String ACCESS_TOKEN_TO_REFRESH_TOKEN_CACHE = "accessTokenToRefreshTokenStore";
    public static final String REFRESH_TOKEN_CACHE = "refreshTokenStore";
    public static final String REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE = "refreshTokenToAccessTokenStore";
    public static final String REFRESH_TOKEN_AUTHENTICATION_CACHE = "refreshTokenAuthenticationStore";
    public static final String AUTHENTICATION_CACHE = "authenticationStore";
    public static final String AUTHENTICATION_TO_ACCESS_TOKEN_CACHE = "authenticationToAccessTokenStore";
    public static final String CLIENT_ID_TO_ACCESS_TOKEN_CACHE = "clientIdToAccessTokenStore";
    public static final String USER_NAME_TO_ACCESS_TOKEN_CACHE = "userNameToAccessTokenStore";
    public static final String NOT_CACHED = "#result == null";
    public static final String APPROVAL_KEY_GENERATOR = "approvalKeyGenerator";

    @CacheEvict(value = ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_ACCESS_TOKEN_KEY_GENERATOR, beforeInvocation = true)
    @Cacheable(value = ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_ACCESS_TOKEN_KEY_GENERATOR)
    public OAuth2AccessToken storeAccessToken(final OAuth2AccessToken token) {
        return token;
    }

    @CacheEvict(value = AUTHENTICATION_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR, beforeInvocation = true)
    @Cacheable(value = AUTHENTICATION_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR)
    public OAuth2AccessToken storeAuthenticationToAccessToken(final String clientIt,
                                                              final String userName,
                                                              final OAuth2AccessToken token) {
        return token;
    }

    @CacheEvict(value = USER_NAME_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR)
    public void removeUserNameToAccessToken(final String clientId, String name) {
    }

    @CacheEvict(value = CLIENT_ID_TO_ACCESS_TOKEN_CACHE, key = "#root.args[0]")
    public void removeClientIdToAccessToken(final String clientId) {
    }

    @CacheEvict(value = AUTHENTICATION_TO_ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_AUTHENTICATION_KEY_GENERATOR)
    public void removeAuthenticationToAccessToken(final OAuth2Authentication authentication) {
    }

    @Cacheable(value = ACCESS_TOKEN_CACHE, key = "#root.args[0]", unless = NOT_CACHED)
    public OAuth2AccessToken findAccessToken(final String tokenValue) {
        return null;
    }

    @CacheEvict(value = REFRESH_TOKEN_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR, beforeInvocation = true)
    @Cacheable(value = REFRESH_TOKEN_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public OAuth2RefreshToken storeRefreshToken(final OAuth2RefreshToken refreshToken) {
        return refreshToken;
    }

    @CacheEvict(value = REFRESH_TOKEN_AUTHENTICATION_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR, beforeInvocation = true)
    @Cacheable(value = REFRESH_TOKEN_AUTHENTICATION_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public OAuth2Authentication storeRefreshTokenAuthentication(final OAuth2RefreshToken refreshToken,
                                                                final OAuth2Authentication authentication) {
        return authentication;
    }

    @CacheEvict(value = CLIENT_ID_TO_ACCESS_TOKEN_CACHE, key = "#root.args[0]", beforeInvocation = true)
    @Cacheable(value = CLIENT_ID_TO_ACCESS_TOKEN_CACHE, key = "#root.args[0]")
    public Collection<OAuth2AccessToken> storeTokensByClientId(final String clientId,
                                                               final Collection<OAuth2AccessToken> accessTokens) {
        return accessTokens;
    }

    @CacheEvict(value = USER_NAME_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR, beforeInvocation = true)
    @Cacheable(value = USER_NAME_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR)
    public Collection<OAuth2AccessToken> storeTokensByClientIdAndUserName(final String clientId,
                                                                          final String userName,
                                                                          final Collection<OAuth2AccessToken> accessTokens) {
        return accessTokens;
    }

    @Cacheable(value = REFRESH_TOKEN_CACHE, key = "#root.args[0]", unless = NOT_CACHED)
    public OAuth2RefreshToken findRefreshToken(final String tokenValue) {
        return null;
    }

    @CacheEvict(value = {REFRESH_TOKEN_CACHE, REFRESH_TOKEN_AUTHENTICATION_CACHE, REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE}, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public void removeRefreshToken(final OAuth2RefreshToken refreshToken) {
    }

    @CacheEvict(value = REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR, beforeInvocation = false)
    @Cacheable(value = REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE, unless = NOT_CACHED, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public String removeRefreshTokenToAccessToken(final OAuth2RefreshToken refreshToken) {
        return null;
    }

    @Cacheable(value = USER_NAME_TO_ACCESS_TOKEN_CACHE, keyGenerator = APPROVAL_KEY_GENERATOR)
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(final String clientId, final String userName) {
        return new HashSet<>();
    }

    @Cacheable(value = CLIENT_ID_TO_ACCESS_TOKEN_CACHE, key = "#root.args[0]")
    public Collection<OAuth2AccessToken> findTokensByClientId(final String clientId) {
        return new HashSet<>();
    }

    @CacheEvict(value = ACCESS_TOKEN_CACHE, key = "#root.args[0]", beforeInvocation = false)
    @Cacheable(value = ACCESS_TOKEN_CACHE, key = "#root.args[0]", unless = NOT_CACHED)
    public OAuth2AccessToken removeAccessToken(String tokenValue) {
        return null;
    }

    @CacheEvict(value = ACCESS_TOKEN_TO_REFRESH_TOKEN_CACHE)
    public void removeAccessTokenToRefreshToken(final String tokenValue) {
    }

    @CacheEvict(value = AUTHENTICATION_CACHE, key = "#root.args[0]", beforeInvocation = false)
    @Cacheable(cacheNames = AUTHENTICATION_CACHE, key = "#root.args[0]", unless = NOT_CACHED)
    public OAuth2Authentication removeAuthentication(String tokenValue) {
        return null;
    }

    @Cacheable(cacheNames = AUTHENTICATION_CACHE, unless = NOT_CACHED, keyGenerator = OAUTH2_ACCESS_TOKEN_KEY_GENERATOR)
    public OAuth2Authentication findAuthentication(final OAuth2AccessToken token) {
        return null;
    }

    @Cacheable(cacheNames = AUTHENTICATION_CACHE, key = "#root.args[0]", unless = NOT_CACHED)
    public OAuth2Authentication findAuthentication(final String tokenValue) {
        return null;
    }

    @Cacheable(cacheNames = REFRESH_TOKEN_AUTHENTICATION_CACHE, unless = NOT_CACHED, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public OAuth2Authentication findAuthenticationForRefreshToken(final OAuth2RefreshToken token) {
        return null;
    }

    @Cacheable(value = AUTHENTICATION_CACHE, keyGenerator = OAUTH2_ACCESS_TOKEN_KEY_GENERATOR)
    public OAuth2Authentication storeAuthentication(final OAuth2AccessToken token, final OAuth2Authentication authentication) {
        return authentication;
    }

    @Cacheable(value = AUTHENTICATION_TO_ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_AUTHENTICATION_KEY_GENERATOR)
    public OAuth2AccessToken storeAuthenticationToAccessToken(final OAuth2Authentication authentication, final OAuth2AccessToken token) {
        return token;
    }

    @Cacheable(value = REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
    public String storeRefreshTokenToAccessToken(final OAuth2RefreshToken refreshToken, final String token) {
        return token;
    }

    @Cacheable(value = ACCESS_TOKEN_TO_REFRESH_TOKEN_CACHE, keyGenerator = OAUTH2_ACCESS_TOKEN_KEY_GENERATOR)
    public String storeAccessTokenToRefreshToken(final OAuth2AccessToken accessToken, final String token) {
        return token;
    }

    @Cacheable(cacheNames = AUTHENTICATION_TO_ACCESS_TOKEN_CACHE, unless = NOT_CACHED, keyGenerator = OAUTH2_AUTHENTICATION_KEY_GENERATOR)
    public OAuth2AccessToken findTokenByAuthentication(final OAuth2Authentication authentication) {
        return null;
    }
}
