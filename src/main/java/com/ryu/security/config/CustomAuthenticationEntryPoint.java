package com.ryu.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryu.security.common.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        String uri = request.getRequestURI();

        // API 요청이면 JSON
        if (uri.startsWith("/api/")) {
            ErrorResponse body = ErrorResponse.of(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "로그인이 필요합니다.",
                    uri
            );

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), body);
            return;
        }

        // 화면 요청이면 프론트 로그인 페이지로
        String redirectUrl = frontendUrl + "/custom-login?error=unauthorized";
        response.sendRedirect(redirectUrl);
    }
}
