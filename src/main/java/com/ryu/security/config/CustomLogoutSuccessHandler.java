package com.ryu.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ryu.security.common.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Value("${frontend.url}")
    private String frontendUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException {

        String uri = request.getRequestURI();
        String accept = request.getHeader("Accept");

        // 1) API 요청(JSON)인 경우
        if (uri.startsWith("/api/") || (accept != null && accept.contains("application/json"))) {
            ErrorResponse body = ErrorResponse.of(
                    HttpServletResponse.SC_OK,
                    "OK",
                    "LOGOUT_SUCCESS",
                    uri
            );

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), body);
            return;
        }

        // 2) 일반 화면 요청인 경우 – 프론트 홈으로 이동
        response.sendRedirect(frontendUrl + "/");
    }
}
