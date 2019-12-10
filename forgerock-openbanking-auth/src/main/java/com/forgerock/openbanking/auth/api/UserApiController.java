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
package com.forgerock.openbanking.auth.api;


import com.forgerock.openbanking.auth.conditional.ConditionalOnOIDCClientProperties;
import com.forgerock.openbanking.auth.model.AuthorisationResponse;
import com.forgerock.openbanking.auth.model.ExchangeCodeResponse;
import com.forgerock.openbanking.auth.model.User;
import com.forgerock.openbanking.auth.services.UserAuthService;
import com.forgerock.openbanking.auth.services.UserProvider;
import com.forgerock.openbanking.exceptions.OIDCException;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.nimbusds.jose.JOSEException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;

import static com.forgerock.openbanking.auth.services.CookieService.OIDC_ORIGIN_URI_CONTEXT_COOKIE_NAME;

@ConditionalOnOIDCClientProperties
@RestController
@Slf4j
public class UserApiController implements UserApi {
    private final String redirectUri;
    private final UserAuthService userAuthService;
    private UserProvider userProvider;

    @Autowired
    public UserApiController(@Value("${ob.auth.oidc.client.redirect-uri}") String redirectUri,
                             UserAuthService userAuthService,
                             UserProvider userProvider) {
        this.redirectUri = redirectUri;
        this.userAuthService = userAuthService;
        this.userProvider = userProvider;
    }

    @Override
    public ResponseEntity<String> startAuthorisationCodeFlow(
            @RequestParam(value = "originUrl") String originUrl,
            HttpServletResponse response
    ) {
        log.debug("Attempt to start authorisation code flow from origin: {}", originUrl);
        return ResponseEntity.ok(userAuthService.createAuthorisationRequest(originUrl, redirectUri, response));
    }

    @Override
    public ResponseEntity<ExchangeCodeResponse> login(
            @CookieValue(value = OIDC_ORIGIN_URI_CONTEXT_COOKIE_NAME) String originURL,
            @RequestBody AuthorisationResponse authorisationResponse,
            HttpServletResponse response,
            Principal principal
    ) throws OIDCException, InvalidTokenException, CertificateEncodingException {
        log.debug("Attempt login for principal: {}", principal);
        ExchangeCodeResponse exchangeCodeResponse = userAuthService.loginUserWithCode(authorisationResponse.getCode(), originURL, redirectUri, response);
        return ResponseEntity.ok(exchangeCodeResponse);
    }

    @Override
    public ResponseEntity logout(
            HttpServletResponse response,
            Principal principal
    ) {
        log.debug("Attempt logout for principal: {}", principal);
        try {
            return ResponseEntity.ok(userAuthService.logout(principal, response));
        } catch (JOSEException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Couldn't delete the user session," +
                    " please contact an administrator.");
        }
    }

    @Override
    public ResponseEntity getUser(
            HttpServletResponse response,
            Authentication authentication
    ) throws CertificateEncodingException {
        log.debug("Attempt to get user: {}", authentication);
        return ResponseEntity.ok(userProvider.getUser(authentication));
    }
}

