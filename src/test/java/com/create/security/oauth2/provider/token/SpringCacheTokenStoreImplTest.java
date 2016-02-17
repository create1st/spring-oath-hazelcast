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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.mockito.Mockito.mock;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
public class SpringCacheTokenStoreImplTest {

    @Autowired
    private SpringCacheTokenStore store;

    @Test
    public void testGetAccessToken() throws Exception {
        // given
        final OAuth2Authentication authenticaton = mock(OAuth2Authentication.class);

        // when
        final OAuth2AccessToken accessToken = store.getAccessToken(authenticaton);

        // then

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
    public void testReadAccessToken() throws Exception {

    }

    @Test
    public void testRemoveAccessToken1() throws Exception {

    }

    @Test
    public void testStoreRefreshToken() throws Exception {

    }

    @Test
    public void testReadRefreshToken() throws Exception {

    }

    @Test
    public void testRemoveRefreshToken() throws Exception {

    }

    @Test
    public void testRemoveAccessTokenUsingRefreshToken() throws Exception {

    }

    @Test
    public void testFindTokensByClientIdAndUserName() throws Exception {

    }

    @Test
    public void testFindTokensByClientId() throws Exception {

    }
}