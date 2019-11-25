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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.util.List;

import static java.lang.Math.toIntExact;

@Service
public class CookieService {

    public static final String SESSION_CONTEXT_COOKIE_NAME = "obri-session";
    public static final String OIDC_ORIGIN_URI_CONTEXT_COOKIE_NAME = "OIDC_ORIGIN_URL";

    @Value("${ob.auth.session.cookie.domains}")
    private List<String> domains;
    @Value("${ob.auth.session.token-lifetime}")
    private Integer sessionLifeTime;

    public void createSessionCookie(HttpServletResponse response, String sessionJwt) {
        createCookie(response, CookieService.SESSION_CONTEXT_COOKIE_NAME, sessionJwt);
    }

    public void deleteSessionCookie(HttpServletResponse response, String sessionJwt) {
        deleteCookie(response, CookieService.SESSION_CONTEXT_COOKIE_NAME, sessionJwt);
    }

    public void createCookie(HttpServletResponse response, String cookieName, String sessionJwt) {
        for(String domain: domains) {
            createCookie(response, cookieName, sessionJwt, domain);
        }
    }

    public void deleteCookie(HttpServletResponse response, String cookieName, String sessionJwt) {
        for(String domain: domains) {
            deleteCookie(response, cookieName, sessionJwt, domain);
        }
    }

    public void createCookie(HttpServletResponse response, String cookieName, String sessionJwt, String domain) {
        createCookie(response, cookieName, sessionJwt, domain, toIntExact(Duration.ofDays(sessionLifeTime).getSeconds()));
    }

    public void deleteCookie(HttpServletResponse response, String cookieName, String sessionJwt, String domain) {
        createCookie(response, cookieName, sessionJwt, domain, 0);
    }

    private void createCookie(HttpServletResponse response, String cookieName, String sessionJwt, String domain, int duration) {
        Cookie cookie = new Cookie(cookieName, sessionJwt);

        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setDomain(domain);
        cookie.setMaxAge(duration);

        response.addCookie(cookie);
    }
}
