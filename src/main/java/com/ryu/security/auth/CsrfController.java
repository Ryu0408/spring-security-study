package com.ryu.security.auth;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {

    @GetMapping("/api/csrf-token")
    public CsrfToken csrf(CsrfToken token) {
        // token.getToken(), token.getHeaderName(), token.getParameterName()
        return token;
    }
}
