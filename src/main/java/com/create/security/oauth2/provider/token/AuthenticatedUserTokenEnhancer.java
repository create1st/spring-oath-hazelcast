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

import com.create.security.oauth2.model.AuthenticatedUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * {@link TokenEnhancer} for {@link AuthenticatedUser}
 */
public class AuthenticatedUserTokenEnhancer implements TokenEnhancer {

    public static final String AUTHENTICATED_USER = "authenticatedUser";

    @Override
    public OAuth2AccessToken enhance(final OAuth2AccessToken accessToken,
                                     final OAuth2Authentication authentication) {
        final DefaultOAuth2AccessToken enhancedAccessToken = new DefaultOAuth2AccessToken(accessToken);
        final AuthenticatedUser authenticatedUser = (AuthenticatedUser) authentication.getPrincipal();
        enhancedAccessToken.getAdditionalInformation().put(AUTHENTICATED_USER, authenticatedUser);
        return enhancedAccessToken;
    }
}
