/**
 * Copyright 2019 ForgeRock AS.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.forgerock.openbanking.auth.services;

import com.forgerock.cert.SubjectHash;
import com.forgerock.openbanking.am.gateway.AMGateway;
import com.forgerock.openbanking.analytics.model.entries.SessionCounterType;
import com.forgerock.openbanking.analytics.services.SessionCountersKPIService;
import com.forgerock.openbanking.constants.OpenBankingConstants;
import com.forgerock.openbanking.exceptions.OBErrorAuthenticationException;
import com.forgerock.openbanking.exceptions.OBErrorException;
import com.forgerock.openbanking.exceptions.OIDCException;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.jwt.services.CryptoApiClient;
import com.forgerock.openbanking.model.OBRIRole;
import com.forgerock.openbanking.model.UserContext;
import com.forgerock.openbanking.model.UserGroup;
import com.forgerock.openbanking.model.error.OBRIErrorType;
import com.forgerock.openbanking.model.oidc.AccessTokenResponse;
import com.forgerock.openbanking.oidc.services.OpenIdService;
import com.google.common.collect.Sets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.forgerock.openbanking.constants.OpenBankingConstants.SSOClaim.MTLS_SUBJECT_HASH;

@Service
@Slf4j
public class SessionService {

    private CryptoApiClient cryptoApiClient;
    private String issuerId;
    private Integer sessionLifeTime;
    private SessionCountersKPIService sessionCountersKPIService;
    private OpenIdService openIdService;

    SessionService(@Autowired CryptoApiClient cryptApiClient,
                   @Value("${ob.auth.session.issuer-id}") String issuerId,
                   @Value("${ob.auth.session.token-lifetime}") Integer sessionLifeTime,
                   @Autowired SessionCountersKPIService sessionCountersKPIService,
                   @Autowired OpenIdService openIdService){
        this.cryptoApiClient = cryptApiClient;
        this.issuerId = issuerId;
        this.sessionLifeTime = sessionLifeTime;
        this.sessionCountersKPIService = sessionCountersKPIService;
        this.openIdService = openIdService;
    }


    /**
     * Get an expired session, useful for logout a user
     * @return a user token with an expiration negatives
     */
    public String expiredSessionContext() throws JOSEException {
        JWTClaimsSet.Builder sessionClaims  = new JWTClaimsSet.Builder()
                .issuer(issuerId)
                .audience(issuerId)
                .expirationTime(new Date(0));

        return cryptoApiClient.signAndEncryptJwtForOBApp(sessionClaims.build(), issuerId);
    }

    /**
     * Generate a session with a specific lifetime
     * @param userContext
     * @return a  session with the corresponding lifetime
     */
    public String generateSessionContextJwt(UserContext userContext) throws CertificateEncodingException, JOSEException {
        JWTClaimsSet.Builder sessionClaims  = new JWTClaimsSet.Builder(userContext.getSessionClaims())
                .issuer(issuerId)
                .audience(issuerId)
                .subject(userContext.getUsername())
                .expirationTime(new Date(new Date().getTime() + Duration.ofDays(sessionLifeTime).toMillis()))
                .claim(OpenBankingConstants.SSOClaim.AUTHORITIES, userContext.getAuthorities());

        Optional<String> certHashcode = SubjectHash.hash(userContext.getCertificatesChain());
        certHashcode.ifPresent(hash -> sessionClaims.claim(MTLS_SUBJECT_HASH, hash));
        return cryptoApiClient.signAndEncryptJwtForOBApp(sessionClaims.build(), issuerId);
    }

    /**
     * Get the user context from a session
     * @param sessionJwtSerialised session as a JWE(JWS)
     * @return the user context
     * @throws ParseException
     */
    public UserContext getUserContext(String sessionJwtSerialised) throws ParseException, JOSEException {
        SignedJWT sessionJws = cryptoApiClient.decryptJwe(issuerId, sessionJwtSerialised);
        if (sessionJws.getJWTClaimsSet().getExpirationTime().before(new Date())) {
            log.debug("Token {} as expired {}", sessionJws.serialize(), sessionJws.getJWTClaimsSet().getExpirationTime());
            throw new OBErrorAuthenticationException(OBRIErrorType.SESSION_TOKEN_EXPIRED);
        }
        String username = sessionJws.getJWTClaimsSet().getSubject();
        Set<GrantedAuthority> roles = new HashSet<>();
        for (String authority : sessionJws.getJWTClaimsSet().getStringListClaim(OpenBankingConstants.SSOClaim.AUTHORITIES)) {
            try {
                roles.add(OBRIRole.valueOf(authority));
                continue;
            } catch (IllegalArgumentException e) {
            }
            try {
                roles.add(UserGroup.valueOf(authority));
                continue;
            } catch (IllegalArgumentException ignored) {
            }
            log.warn("Couldn't de-serialised authority '{}' to OBRI role or group", authority);

        }
        roles.add(OBRIRole.ROLE_USER);

        return UserContext.createOIDCClient(username, new ArrayList<>(roles), sessionJws.getJWTClaimsSet());
    }


    /**
     * Authenticate with password grant flow
     * @param sessionType which type of session is being created
     * @param amGateway AM gateway for auth or bank realm
     * @param amAccessTokenEndpoint
     * @param certificateChain
     * @param user
     * @return Session token mean't for the end user
     * @throws OIDCException password grant flow fails
     */
    public String authenticate(@RequestParam("username") String username, @RequestParam("password") String password,
                               Authentication principal, SessionCounterType sessionType, AMGateway amGateway,
                               String amAccessTokenEndpoint, X509Certificate[] certificateChain, User user) throws OIDCException, OBErrorException {
        try {
            AccessTokenResponse accessTokenResponse = openIdService.passwordGrantFlow(amGateway, amAccessTokenEndpoint, username, password);
            log.info("The access token response : {}", accessTokenResponse);
            UserContext userContext = openIdService.fromIdToken(accessTokenResponse.getIdToken(), certificateChain);

            sessionCountersKPIService.incrementSessionCounter(sessionType);
            List<GrantedAuthority> mergedAuthorities = Stream.concat(userContext.getAuthorities().stream(), user.getAuthorities().stream())
                    .distinct()
                    .collect(Collectors.toList());
            return generateSessionContextJwt(UserContext.createOIDCClient(userContext.getUsername(),
                    mergedAuthorities, userContext.getSessionClaims(), userContext.getCertificatesChain()));
        } catch (HttpClientErrorException e) {
            log.error("AM exception: {}", e.getResponseBodyAsString(), e);
        } catch (ParseException e) {
            log.error("Can't parse ID token", e);
        } catch (InvalidTokenException e) {
            log.error("ID Token is invalid", e);
        } catch (CertificateEncodingException e) {
            log.error("Certificate exception", e);
        } catch (JOSEException e) {
            log.error("JOSE exception", e);
        } catch (IOException e) {
            log.error("IO exception", e);
        }
        throw new OBErrorException(OBRIErrorType.SERVER_ERROR, "Couldn't authenticate the user");
    }
}
