package com.ryu.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryu.security.auth.AuthErrorCode;
import com.ryu.security.common.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Value("${frontend.url}")
    private String frontendUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        AuthErrorCode errorCode = resolveErrorCode(exception);

        // 1) API 요청이면 JSON (선택)
        if (isApiRequest(request)) {
            ErrorResponse body = ErrorResponse.of(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "UNAUTHORIZED",
                    errorCode.getCode(),
                    request.getRequestURI()
            );

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), body);
            return;
        }

        // 2) 화면(Form 로그인) 요청이면 프론트 로그인 페이지로 리다이렉트
        String redirectUrl = UriComponentsBuilder
                .fromHttpUrl(frontendUrl + "/custom-login")
                .queryParam("error", errorCode.getCode())
                .build()
                .toUriString();

        response.sendRedirect(redirectUrl);
    }

    private AuthErrorCode resolveErrorCode(AuthenticationException exception) {

        if (exception instanceof BadCredentialsException) {
            return AuthErrorCode.BAD_CREDENTIALS;
        } else if (exception instanceof LockedException) {
            return AuthErrorCode.LOCKED;
        } else if (exception instanceof DisabledException) {
            return AuthErrorCode.DISABLED;
        } else if (exception instanceof CredentialsExpiredException) {
            return AuthErrorCode.CREDENTIALS_EXPIRED;
        } else if (exception instanceof AccountExpiredException) {
            return AuthErrorCode.ACCOUNT_EXPIRED;
        } else {
            return AuthErrorCode.UNKNOWN;
        }
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String accept = request.getHeader("Accept");
        String xhr = request.getHeader("X-Requested-With");

        return uri.startsWith("/api/")
                || (accept != null && accept.contains("application/json"))
                || "XMLHttpRequest".equalsIgnoreCase(xhr);
    }
}
