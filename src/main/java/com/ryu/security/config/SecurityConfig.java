package com.ryu.security.config;

import com.ryu.security.user.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${frontend.url}")
    private String frontendUrl;

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint,
                          CustomAccessDeniedHandler customAccessDeniedHandler, CustomAuthenticationFailureHandler customAuthenticationFailureHandler, CustomLogoutSuccessHandler customLogoutSuccessHandler) {
        this.customUserDetailsService = customUserDetailsService;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
        this.customAccessDeniedHandler = customAccessDeniedHandler;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
        this.customLogoutSuccessHandler = customLogoutSuccessHandler;
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(
                                CookieCsrfTokenRepository.withHttpOnlyFalse()
                        )
                        // REST API는 JWT로 갈 때 보통 별도 처리하지만,
                        // 지금은 학습용으로 /api/** 정도는 제외해도 됨
                        .ignoringRequestMatchers("/api/**")
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public", "/api/signup", "/api/csrf-token").permitAll()
                        .requestMatchers("/api/me").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )

                .formLogin(login -> login
                        .loginPage(frontendUrl + "/custom-login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/hello")
                        .failureHandler(customAuthenticationFailureHandler)   // ★ 추가
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")                 // 기본: POST /logout
                        .logoutSuccessHandler(customLogoutSuccessHandler)
                        .invalidateHttpSession(true)         // 세션 무효화
                        .deleteCookies("JSESSIONID", "remember-me") // 세션쿠키 + remember-me 쿠키 삭제
                )

                // ★ 예외 처리: 401 / 403 커스터마이징
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )

                // ★ 세션 관리 (동시접속, 세션고정방지 등)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::migrateSession)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .expiredUrl("/public?expired=true")
                )

                // ★ Remember-Me
                .rememberMe(remember -> remember
                        .key("change-this-remember-me-key")
                        .tokenValiditySeconds(60 * 60 * 24 * 14)
                        .rememberMeCookieName("remember-me")
                        .useSecureCookie(true)   // HTTPS 환경에서
                );

        return http.build();
    }
}
