/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
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
