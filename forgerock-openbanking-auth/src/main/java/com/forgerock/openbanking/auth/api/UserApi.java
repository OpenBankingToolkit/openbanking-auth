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
import com.forgerock.openbanking.exceptions.OIDCException;
import com.forgerock.openbanking.jwt.exceptions.InvalidTokenException;
import io.swagger.annotations.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;

@Api(
        tags = "Users",
        description = "manage users"
)
@ConditionalOnOIDCClientProperties
@RequestMapping("/api/user")
public interface UserApi {

    @ApiOperation(value = "initiateLogin")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The user", response = String.class),
    })
    @RequestMapping(value = "/initiate-login", method = RequestMethod.GET)
    ResponseEntity<String> startAuthorisationCodeFlow(
            @RequestParam(value = "originUrl") String originUrl,
            HttpServletResponse response
    );

    @ApiOperation(value = "Login by exchange ID token to session")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The user", response = User.class),
    })
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    ResponseEntity<ExchangeCodeResponse> login(
            @CookieValue(value = "OIDC_ORIGIN_URL") String originURL,
            @RequestBody AuthorisationResponse authorisationResponse,
            HttpServletResponse response,
            Principal principal
    ) throws OIDCException, ParseException, InvalidTokenException, CertificateEncodingException;

    @ApiOperation(value = "logout the user")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "True is logout with success", response = Boolean.class),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_USER')")
    @RequestMapping(value = "/logout", method = RequestMethod.DELETE)
    ResponseEntity<Boolean> logout(
            HttpServletResponse response,
            Principal principal
    );

    @ApiOperation(value = "Get the user profile",
            authorizations = {
                    @Authorization(value = "Bearer token", scopes = {
                            @AuthorizationScope(scope = "role", description = "Needs to be authenticated")
                    })
            })
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "The user", response = User.class),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_FORGEROCK_INTERNAL_APP')")
    @RequestMapping(value = "/", method = RequestMethod.GET)
    ResponseEntity<User> getUser(
            HttpServletResponse response,
            Authentication principal
    ) throws CertificateEncodingException;
}

