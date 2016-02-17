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

import com.create.security.oauth2.provider.token.OAuth2AuthenticationKeyGenerator;
import com.create.security.oauth2.provider.token.SpringCacheTokenStore;
import com.hazelcast.core.IMap;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

class SampleClient {

    private static final List<String> SAMPLE_COUNTRY_CODES = Arrays.asList("AF", "ZW", "PL");

    private final SpringCacheTokenStore tokenStore;

    private CacheManager cacheManager;

    private final Random random;

    public SampleClient(SpringCacheTokenStore tokenStore, CacheManager cacheManager) {
        this.tokenStore = tokenStore;
        this.random = new Random();
        this.cacheManager = cacheManager;
    }

    @Scheduled(fixedDelay = 500)
    public void retrieveCountry() {
//        String randomCode = SAMPLE_COUNTRY_CODES
//                .get(this.random.nextInt(SAMPLE_COUNTRY_CODES.size()));
//        System.out.println("Looking for country with code '" + randomCode + "'");
//        this.tokenStore.findByCode(randomCode);
        OAuth2Request storedRequest = new OAuth2Request(Collections.emptyMap(), "CLIENT_ID", Collections.EMPTY_LIST,
                true, Collections.EMPTY_SET, Collections.EMPTY_SET, null, Collections.EMPTY_SET, Collections.EMPTY_MAP);
        OAuth2Authentication authentication = new OAuth2Authentication(storedRequest, null);
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("TEST");
        System.out.println(token + " ++++++++ " + authentication);
        tokenStore.storeAccessToken(token, authentication);
        //tokenStore.storeAccessToken(token);
//        System.out.println("Looking for country with code PL");
//        tokenStore.findByCode("PL");
//        System.out.println("Looking for country with code PL");
//        tokenStore.findByCode("PL");
        cacheManager.getCacheNames().stream().forEach(cacheName -> {
            System.out.println(cacheName);
            ((IMap) cacheManager.getCache(cacheName).getNativeCache()).entrySet().stream().forEach(entry -> {
                System.out.println(((Map.Entry) entry).getKey() + " = " + ((Map.Entry) entry).getValue());
            });
        });
        System.out.println(tokenStore.readAuthentication(token));
        System.out.println(new OAuth2AuthenticationKeyGenerator(new DefaultAuthenticationKeyGenerator()).generate(null, null, authentication));
        System.out.println(tokenStore.getAccessToken(authentication));
    }

}
