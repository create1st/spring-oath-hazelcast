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

package com.create.security.oauth2.provider.token;

import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Spring Cache based {@link TokenStore} interface.
 */
public interface SpringCacheTokenStore extends TokenStore {
    String OAUTH2_ACCESS_TOKEN_KEY_GENERATOR = "oauth2AccessTokenKeyGenerator";
    String OAUTH2_REFRESH_TOKEN_KEY_GENERATOR = "oauth2RefreshTokenKeyGenerator";
    String OAUTH2_AUTHENTICATION_KEY_GENERATOR = "oauth2AuthenticationKeyGenerator";
    String ACCESS_TOKEN_CACHE = "accessTokenStore";
    String REFRESH_TOKEN_CACHE = "refreshTokenStore";
    String REFRESH_TOKEN_AUTHENTICATION_CACHE = "refreshTokenAuthenticationStore";
    String AUTHENTICATION_CACHE = "authenticationStore";
    String AUTHENTICATION_TO_ACCESS_TOKEN_CACHE = "authenticationToAccessTokenStore";
    String CLIENT_ID_TO_ACCESS_TOKEN_CACHE = "clientIdToAccessTokenStore";
    String USER_NAME_TO_ACCESS_TOKEN_CACHE = "userNameToAccessTokenStore";
    String NOT_CACHED = "#result == null";
    String APPROVAL_KEY_GENERATOR = "approvalKeyGenerator";

    void removeAccessToken(String tokenValue);

}