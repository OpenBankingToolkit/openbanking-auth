/**
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package com.forgerock.openbanking.auth.services;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class DefaultUserProvider implements UserProvider {

    @Override
    public Object getUser(Authentication authentication) {
        return authentication.getDetails();
    }
}
