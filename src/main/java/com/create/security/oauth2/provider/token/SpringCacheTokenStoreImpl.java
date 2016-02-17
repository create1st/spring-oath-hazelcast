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

import com.create.security.oauth2.repository.TokenRepository;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * Spring cache based implementation of {@link TokenStore}.
 */
public class SpringCacheTokenStoreImpl implements SpringCacheTokenStore {

    private final TokenRepository tokenRepository;

    /**
     * Creates new {@link SpringCacheTokenStoreImpl}
     *
     * @param tokenRepository must not be {@literal null}
     */
    public SpringCacheTokenStoreImpl(final TokenRepository tokenRepository) {
        Assert.notNull(tokenRepository);
        this.tokenRepository = tokenRepository;
    }

    //TODO Put actual
    //@Override
    @Override
    public OAuth2AccessToken getAccessToken(final OAuth2Authentication authentication) {
        final OAuth2AccessToken accessToken = tokenRepository.findTokenByAuthentication(authentication);
//        if (accessToken != null
//                && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
//            // Keep the stores consistent (maybe the same user is represented by this authentication but the details
//            // have changed)
//            storeAccessToken(accessToken, authentication);
//        }
//        return accessToken;
        return null;
    }

    @Override
    public OAuth2Authentication readAuthentication(final OAuth2AccessToken token) {
        return tokenRepository.findAuthentication(token);
    }

    @Override
    public OAuth2Authentication readAuthentication(final String token) {
        return tokenRepository.findAuthentication(token);
    }

    @Override
    public OAuth2Authentication readAuthenticationForRefreshToken(final OAuth2RefreshToken token) {
        return tokenRepository.findAuthenticationForRefreshToken(token);
    }

    @Override
    public void storeAccessToken(final OAuth2AccessToken token,
                                 final OAuth2Authentication authentication) {
        tokenRepository.storeAccessToken(token);
        tokenRepository.storeAuthentication(token, authentication);
        tokenRepository.storeAuthenticationToAccessToken(authentication, token);
        if (!authentication.isClientOnly()) {
            final String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
            addToCollection(tokenRepository.findTokensByClientIdAndUserName(authentication.getOAuth2Request().getClientId(), userName), token);
        }
        addToCollection(tokenRepository.findTokensByClientId(authentication.getOAuth2Request().getClientId()), token);
        if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
            tokenRepository.storeRefreshTokenToAccessToken(token.getRefreshToken(), token.getValue());
            tokenRepository.storeAccessTokenToRefreshToken(token, token.getRefreshToken().getValue());
        }

//        if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
//            flush();
//            this.flushCounter.set(0);
//        }
//        this.accessTokenStore.put(token.getValue(), token);
//        this.authenticationStore.put(token.getValue(), authentication);
//        this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
//        if (!authentication.isClientOnly()) {
//            addToCollection(this.userNameToAccessTokenStore, getApprovalKey(authentication), token);
//        }
//        addToCollection(this.clientIdToAccessTokenStore, authentication.getOAuth2Request().getClientId(), token);
//        if (token.getExpiration() != null) {
//            TokenExpiry expiry = new TokenExpiry(token.getValue(), token.getExpiration());
//            // Remove existing expiry for this token if present
//            expiryQueue.remove(expiryMap.put(token.getValue(), expiry));
//            this.expiryQueue.put(expiry);
//        }
//        if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
//            this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
//            this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
//        }
    }


//    @Cacheable(value = REFRESH_TOKEN_TO_ACCESS_TOKEN_CACHE, keyGenerator = OAUTH2_REFRESH_TOKEN_KEY_GENERATOR)
//    public OAuth2AccessToken storeRefreshToken(final OAuth2AccessToken token) {
//        return token;
//    }

//    private String getApprovalKey(OAuth2Authentication authentication) {
//        String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication()
//                .getName();
//        return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
//    }


//    private String getApprovalKey(final String clientId, final String userName) {
//        return clientId + (userName==null ? "" : ":" + userName);
//    }

    private void addToCollection(final Collection<OAuth2AccessToken> store,
                                 final OAuth2AccessToken token) {
        store.add(token);
    }

    @Override
    public void removeAccessToken(final OAuth2AccessToken accessToken) {
        removeAccessToken(accessToken.getValue());
    }


    @Override
    public OAuth2AccessToken readAccessToken(final String tokenValue) {
        //return this.accessTokenStore.get(tokenValue);
        return tokenRepository.findAccessToken(tokenValue);
    }

    @Override
    public void removeAccessToken(final String tokenValue) {
        final OAuth2AccessToken removed = //tokenRepository.findAccessToken(tokenValue);
                tokenRepository.removeAccessToken(tokenValue);
        tokenRepository.removeAccessTokenToRefreshToken(tokenValue);
        final OAuth2Authentication authentication = //tokenRepository.findAuthentication(tokenValue);
                tokenRepository.removeAuthentication(tokenValue);
        if (authentication != null) {
            tokenRepository.removeAuthenticationToAccessToken(authentication);
            Collection<OAuth2AccessToken> tokens;
            String clientId = authentication.getOAuth2Request().getClientId();
            tokens = tokenRepository.findTokensByClientIdAndUserName(clientId, authentication.getName());
            if (tokens != null) {
                tokens.remove(removed);
            }
            tokens = tokenRepository.findTokensByClientId(clientId);
            if (tokens != null) {
                tokens.remove(removed);
            }
            tokenRepository.removeAuthenticationToAccessToken(authentication);
        }


//        OAuth2AccessToken removed =  this.accessTokenStore.remove(tokenValue);
//        this.accessTokenToRefreshTokenStore.remove(tokenValue);
//        // Don't remove the refresh token - it's up to the caller to do that
//        OAuth2Authentication authentication = this.authenticationStore.remove(tokenValue);
//        if (authentication != null) {
//            this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
//            Collection<OAuth2AccessToken> tokens;
//            String clientId = authentication.getOAuth2Request().getClientId();
//            tokens = this.userNameToAccessTokenStore.get(getApprovalKey(clientId, authentication.getName()));
//            if (tokens != null) {
//                tokens.remove(removed);
//            }
//            tokens = this.clientIdToAccessTokenStore.get(clientId);
//            if (tokens != null) {
//                tokens.remove(removed);
//            }
//            this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
//        }
    }

    @Override
    public void storeRefreshToken(final OAuth2RefreshToken refreshToken, final OAuth2Authentication authentication) {
//        this.refreshTokenStore.put(refreshToken.getValue(), refreshToken);
//        this.refreshTokenAuthenticationStore.put(refreshToken.getValue(), authentication);
        tokenRepository.storeRefreshToken(refreshToken);
        tokenRepository.storeRefreshTokenAuthentication(refreshToken, authentication);
    }

    @Override
    public OAuth2RefreshToken readRefreshToken(final String tokenValue) {
//        return this.refreshTokenStore.get(tokenValue);
        return tokenRepository.findRefreshToken(tokenValue);
    }

    @Override
    public void removeRefreshToken(final OAuth2RefreshToken refreshToken) {
        tokenRepository.removeRefreshToken(refreshToken);
//        removeRefreshToken(refreshToken.getValue());
    }

    //    public void removeRefreshToken(String tokenValue) {
//        this.refreshTokenStore.remove(tokenValue);
//        this.refreshTokenAuthenticationStore.remove(tokenValue);
//        this.refreshTokenToAccessTokenStore.remove(tokenValue);
//    }
    @Override
    public void removeAccessTokenUsingRefreshToken(final OAuth2RefreshToken refreshToken) {
        final String accessToken =
                //tokenRepository.findAccessToken(refreshToken);
                tokenRepository.removeRefreshTokenToAccessToken(refreshToken);
        if (accessToken != null) {
            removeAccessToken(accessToken);
        }
//        removeAccessTokenUsingRefreshToken(refreshToken.getValue());
    }

//    private void removeAccessTokenUsingRefreshToken(String refreshToken) {
//        String accessToken = this.refreshTokenToAccessTokenStore.remove(refreshToken);
//        if (accessToken != null) {
//            removeAccessToken(accessToken);
//        }
//    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(final String clientId, final String userName) {
        return tokenRepository.findTokensByClientIdAndUserName(clientId, userName);
//        Collection<OAuth2AccessToken> result = userNameToAccessTokenStore.get(getApprovalKey(clientId, userName));
//        return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : Collections
//                .<OAuth2AccessToken> emptySet();
//        return Collections.<OAuth2AccessToken>emptySet();
    }

    @Override
    public Collection<OAuth2AccessToken> findTokensByClientId(final String clientId) {
        return tokenRepository.findTokensByClientId(clientId);
//        Collection<OAuth2AccessToken> result = clientIdToAccessTokenStore.get(clientId);
//        return result != null ? Collections.<OAuth2AccessToken> unmodifiableCollection(result) : Collections
//                .<OAuth2AccessToken> emptySet();
        //return Collections.<OAuth2AccessToken>emptySet();
    }

    //    private void flush() {
//        TokenExpiry expiry = expiryQueue.poll();
//        while (expiry != null) {
//            removeAccessToken(expiry.getValue());
//            expiry = expiryQueue.poll();
//        }
//    }
//
//    private static class TokenExpiry implements Delayed {
//
//        private final long expiry;
//
//        private final String value;
//
//        public TokenExpiry(String value, Date date) {
//            this.value = value;
//            this.expiry = date.getTime();
//        }
//
//        public int compareTo(Delayed other) {
//            if (this == other) {
//                return 0;
//            }
//            long diff = getDelay(TimeUnit.MILLISECONDS) - other.getDelay(TimeUnit.MILLISECONDS);
//            return (diff == 0 ? 0 : ((diff < 0) ? -1 : 1));
//        }
//
//
//        public long getDelay(TimeUnit unit) {
//            return expiry - System.currentTimeMillis();
//        }
//
//        public String getValue() {
//            return value;
//        }
//
//    }

}
