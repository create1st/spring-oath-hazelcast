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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.Serializable;
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

    @Before
    public void setup() {
        clearStore();
    }

    private void clearStore() {
        store.removeAccessToken(ACCESS_TOKEN);
        store.removeRefreshToken(createOAuth2RefreshToken());
    }

    private OAuth2RefreshToken createOAuth2RefreshToken() {
        return new DefaultOAuth2RefreshToken(REFRESH_TOKEN);
    }

    @Test
    public void testGetAccessTokenNotSet() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();

        // when
        final OAuth2AccessToken accessToken = store.getAccessToken(authentication);

        // then
        assertThat(accessToken, nullValue());
    }

    private OAuth2Authentication createOAuth2Authentication() {
        final OAuth2Request storedRequest = new OAuth2Request(Collections.emptyMap(), CLIENT_ID, Collections.<GrantedAuthority>emptyList(),
                true, Collections.<String>emptySet(), Collections.<String>emptySet(), null, Collections.<String>emptySet(), Collections.<String, Serializable>emptyMap());
        final User userDetails = new User(USER_NAME, PASSWORD, Collections.EMPTY_SET);
        final Authentication userAuthentication = new UsernamePasswordAuthenticationToken(userDetails, null);
        return new OAuth2Authentication(storedRequest, userAuthentication);
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

    private OAuth2AccessToken createOAuth2AccessToken() {
        final DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken(ACCESS_TOKEN);
        accessToken.setRefreshToken(createOAuth2RefreshToken());
        return accessToken;
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
    public void testReadAuthenticationNotSet() throws Exception {
        // given

        // when
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(ACCESS_TOKEN);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testReadAuthentication() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(ACCESS_TOKEN);

        // then
        assertThat(oAuth2Authentication, is(authentication));
    }

    @Test
    public void testReadAuthenticationForTokenNotSet() throws Exception {
        // given
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(token);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testReadAuthenticationForToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(token);

        // then
        assertThat(oAuth2Authentication, is(authentication));
    }

    @Test
    public void testReadAuthenticationForRefreshTokenNotSet() throws Exception {
        // given
        final OAuth2RefreshToken token = createOAuth2RefreshToken();

        // when
        final OAuth2Authentication oAuth2Authentication = store.readAuthenticationForRefreshToken(token);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testReadAuthenticationForRefreshToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2RefreshToken token = createOAuth2RefreshToken();

        // when
        store.storeRefreshToken(token, authentication);
        final OAuth2Authentication oAuth2Authentication = store.readAuthenticationForRefreshToken(token);

        // then
        assertThat(oAuth2Authentication, is(authentication));
    }

    @Test
    public void testRemoveAccessToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        store.removeAccessToken(token);
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(token);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testRemoveAccessTokenForToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        store.removeAccessToken(ACCESS_TOKEN);
        final OAuth2Authentication oAuth2Authentication = store.readAuthentication(token);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testRemoveRefreshToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2RefreshToken token = createOAuth2RefreshToken();

        // when
        store.storeRefreshToken(token, authentication);
        store.removeRefreshToken(token);
        final OAuth2Authentication oAuth2Authentication = store.readAuthenticationForRefreshToken(token);

        // then
        assertThat(oAuth2Authentication, nullValue());
    }

    @Test
    public void testRemoveAccessTokenUsingRefreshToken() throws Exception {
        // given
        final OAuth2Authentication authentication = createOAuth2Authentication();
        final OAuth2AccessToken token = createOAuth2AccessToken();

        // when
        store.storeAccessToken(token, authentication);
        store.removeAccessTokenUsingRefreshToken(token.getRefreshToken());
        final OAuth2AccessToken accessToken = store.readAccessToken(ACCESS_TOKEN);

        // then
        assertThat(accessToken, nullValue());
    }
}