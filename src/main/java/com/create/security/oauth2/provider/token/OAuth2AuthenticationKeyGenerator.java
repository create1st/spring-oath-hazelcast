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

import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;

import java.lang.reflect.Method;

/**
 * Spring cache {@link KeyGenerator} for {@link OAuth2Authentication}
 */
public class OAuth2AuthenticationKeyGenerator implements KeyGenerator {
    private final AuthenticationKeyGenerator authenticationKeyGenerator;

    public OAuth2AuthenticationKeyGenerator(final AuthenticationKeyGenerator authenticationKeyGenerator) {
        this.authenticationKeyGenerator = authenticationKeyGenerator;
    }

    @Override
    public Object generate(final Object target, final Method method, final Object... params) {
        return authenticationKeyGenerator.extractKey((OAuth2Authentication) params[0]);
    }
}
