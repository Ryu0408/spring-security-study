package com.ryu.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryu.security.common.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${frontend.url}")
    private String frontendUrl;

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        String uri = request.getRequestURI();

        // API 요청이면 JSON
        if (uri.startsWith("/api/")) {
            ErrorResponse body = ErrorResponse.of(
                    HttpServletResponse.SC_FORBIDDEN,
                    "FORBIDDEN",
                    "접근 권한이 없습니다.",
                    uri
            );

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), body);
            return;
        }

        // 화면 요청이면 프론트의 권한없음 페이지로
        String redirectUrl = frontendUrl + "/access-denied";
        response.sendRedirect(redirectUrl);
    }
}
