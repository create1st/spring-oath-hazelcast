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

import com.create.application.Application;
import com.create.security.oauth2.repository.TokenRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Collection;
import java.util.Collections;

import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsCollectionContaining.hasItem;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
public class SpringCacheTokenStoreImplTest {
    public static final String CLIENT_ID = "CLIENT_ID";
    public static final String ACCESS_TOKEN = "ACCESS TOKEN";
    public static final String REFRESH_TOKEN = "REFRESH TOKEN";
    public static final String USER_NAME = "USER";
    public static final String PASSWORD = "password";

    @Autowired
    private SpringCacheTokenStore store;

    @Autowired
    private TokenRepository tokenRepository;

    @Before
    public void setup() {
        clearStore();
    }

    @Test
    public void testGetAccessTokenNotSet() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        final OAuth2AccessToken accessToken = store.getAccessToken(authentication);

        // then
        assertThat(accessToken, nullValue());
    }

    @Test
    public void testGetAccessToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final OAuth2AccessToken accessToken = store.getAccessToken(authentication);

        // then
        assertThat(accessToken, is(token));
    }

    @Test
    public void testReadAccessTokenNotSet() throws Exception {
        // given
        // when
        final OAuth2AccessToken accessToken = store.readAccessToken(ACCESS_TOKEN);

        // then
        assertThat(accessToken, nullValue());
    }

    @Test
    public void testReadAccessToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final OAuth2AccessToken accessToken = store.readAccessToken(ACCESS_TOKEN);

        // then
        assertThat(accessToken, is(token));
    }


    @Test
    public void testReadRefreshTokenNotSet() throws Exception {
        // given

        // when
        final OAuth2RefreshToken refreshToken = store.readRefreshToken(REFRESH_TOKEN);

        // then
        assertThat(refreshToken, nullValue());
    }


    @Test
    public void testReadRefreshToken() throws Exception {
// given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2RefreshToken token = createOAuth2RefreshToken();

        // when
        store.storeRefreshToken(token, authentication);
        final OAuth2RefreshToken refreshToken = store.readRefreshToken(REFRESH_TOKEN);

        // then
        assertThat(refreshToken, is(token));
    }


    @Test
    public void testFindTokensByClientIdAndUserName() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final Collection<OAuth2AccessToken> accessTokens = store.findTokensByClientIdAndUserName(CLIENT_ID, USER_NAME);

        // then
        assertThat(accessTokens, hasItem(token));
    }

    @Test
    public void testFindTokensByClientId() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final Collection<OAuth2AccessToken> accessTokens = store.findTokensByClientId(CLIENT_ID);

        // then
        assertThat(accessTokens, hasItem(token));
    }


    @Test
    public void testReadAuthentication() throws Exception {

    }

    @Test
    public void testReadAuthentication1() throws Exception {

    }

    @Test
    public void testReadAuthenticationForRefreshToken() throws Exception {

    }

    @Test
    public void testStoreAccessToken() throws Exception {

    }

    @Test
    public void testRemoveAccessToken() throws Exception {

    }

    @Test
    public void testRemoveAccessToken1() throws Exception {

    }

    @Test
    public void testStoreRefreshToken() throws Exception {

    }


    @Test
    public void testRemoveRefreshToken() throws Exception {

    }

    @Test
    public void testRemoveAccessTokenUsingRefreshToken() throws Exception {

    }


    private void clearStore() {
        store.removeAccessToken(ACCESS_TOKEN);
        store.removeRefreshToken(createOAuth2RefreshToken());
    }

    private OAuth2AccessToken createOAuth2AccessToken() {
        return new DefaultOAuth2AccessToken(ACCESS_TOKEN);
    }

    private OAuth2RefreshToken createOAuth2RefreshToken() {
        return new DefaultOAuth2RefreshToken(REFRESH_TOKEN);
    }

    private OAuth2Authentication createOAuth2Authentication() {
        final OAuth2Request storedRequest = new OAuth2Request(Collections.emptyMap(), CLIENT_ID, Collections.EMPTY_LIST,
                true, Collections.EMPTY_SET, Collections.EMPTY_SET, null, Collections.EMPTY_SET, Collections.EMPTY_MAP);
        final User userDetails = new User(USER_NAME, PASSWORD, Collections.EMPTY_SET);
        final Authentication userAuthentication = new UsernamePasswordAuthenticationToken(userDetails, null);
        return new OAuth2Authentication(storedRequest, userAuthentication);
    }
}