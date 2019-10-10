/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.auth.api;


import com.forgerock.openbanking.analytics.model.entries.SessionCounterType;
import com.forgerock.openbanking.analytics.services.SessionCountersKPIService;
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
    private SessionCountersKPIService sessionCountersKPIService;
    private UserProvider userProvider;

    @Autowired
    public UserApiController(@Value("${ob.auth.oidc.client.redirect-uri}") String redirectUri,
                             UserAuthService userAuthService,
                             SessionCountersKPIService sessionCountersKPIService,
                             UserProvider userProvider) {
        this.redirectUri = redirectUri;
        this.userAuthService = userAuthService;
        this.sessionCountersKPIService = sessionCountersKPIService;
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
        sessionCountersKPIService.incrementSessionCounter(SessionCounterType.METRIC);
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

