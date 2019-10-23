/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.auth.services;

import com.forgerock.openbanking.am.gateway.AMAuthGateway;
import com.forgerock.openbanking.auth.model.ExchangeCodeResponse;
import com.forgerock.openbanking.exceptions.OIDCException;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import com.forgerock.openbanking.model.UserContext;
import com.forgerock.openbanking.model.oidc.AccessTokenResponse;
import com.forgerock.openbanking.oidc.services.OpenIdService;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.JOSEException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static com.forgerock.openbanking.auth.services.CookieService.OIDC_ORIGIN_URI_CONTEXT_COOKIE_NAME;

@Service
@Slf4j
public class UserAuthService {
    private static final List<String> AUTH_SCOPES = ImmutableList.of("openid", "group", "authority");

    private final OpenIdService openIdService;
    private final SessionService sessionService;
    private final CookieService cookieService;
    private final String amAccessTokenEndpoint;
    private final AMAuthGateway amGateway;

    @Autowired
    public UserAuthService(OpenIdService openIdService, SessionService sessionService, CookieService cookieService, @Value("${am.internal.oidc.endpoint.accesstoken}") String amAccessTokenEndpoint, AMAuthGateway amGateway) {
        this.openIdService = openIdService;
        this.sessionService = sessionService;
        this.cookieService = cookieService;
        this.amAccessTokenEndpoint = amAccessTokenEndpoint;
        this.amGateway = amGateway;
    }

    /**
     * Create a new authorisation request URI for the auth server to initiate auth process
     * @param originUrl Auth origin URL
     * @param redirectUri URI to redirect after auth
     * @param httpResponse HTTP Response (for cookie)
     * @return Auth request URI
     */
    public String createAuthorisationRequest(String originUrl, String redirectUri, HttpServletResponse httpResponse) {
        log.info("startAuthorisationCodeFlow  originUrl: {}", originUrl);
        final String authorisationRequest = openIdService.generateAuthorisationRequest(UUID.randomUUID().toString(), redirectUri, AUTH_SCOPES, Collections.emptyList());
        cookieService.createCookie(httpResponse, OIDC_ORIGIN_URI_CONTEXT_COOKIE_NAME, originUrl);
        return authorisationRequest;
    }

    /**
     * Login a user with a code provided from the Auth Server
     * @param authorisationCode Auth code
     * @param originURL Origin URL of auth attempt
     * @param redirectUri Redirect URI after auth
     * @param response HTTP Response (for session)
     * @return Auth response
     * @throws OIDCException Code exchange failed
     * @throws InvalidTokenException Token from exchange was not valid to get a user
     */
    public ExchangeCodeResponse loginUserWithCode(String authorisationCode, String originURL, String redirectUri, HttpServletResponse response) throws OIDCException, InvalidTokenException, CertificateEncodingException {
        Preconditions.checkArgument(!StringUtils.isEmpty(authorisationCode), "Cannot login with an empty authorisation code");
        log.debug("Try to login user with a code, origin URL: {}, redirectUri: {}", originURL, redirectUri);
        AccessTokenResponse accessTokenResponse = openIdService.exchangeCode(amGateway, redirectUri, amAccessTokenEndpoint, authorisationCode);
        log.debug("Exchanged code for access token type: {}", accessTokenResponse.getToken_type());

        UserContext userContext;
        try {
            userContext = openIdService.fromIdToken(accessTokenResponse.getIdToken());
            log.debug("Got user context for login: {} from id token.", userContext.getUsername());
        } catch (ParseException | IOException e) {
            throw new InvalidTokenException("Unable to parse id token", e);
        }

        try {
            String sessionContextJwt = sessionService.generateSessionContextJwt(userContext);
            cookieService.createSessionCookie(response, sessionContextJwt);
            log.debug("Created session cookie with JWT: {}", sessionContextJwt);
            return ExchangeCodeResponse.builder()
                    .originalRequest(originURL)
                    .build();
        } catch (JOSEException e) {
            throw new OIDCException("Couldn't create session", e);
        }
    }

    /**
     *
     * @param principal Logged in user
     * @param response HTTP response (for session)
     * @return True if logged out
     */
    public boolean logout(Principal principal, HttpServletResponse response) throws JOSEException {
        log.debug("logout: {}", principal.getName());
        cookieService.deleteSessionCookie(response, sessionService.expiredSessionContext());
        log.debug("Deleted session cookie");
        return true;
    }
}
