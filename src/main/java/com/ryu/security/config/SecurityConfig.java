package com.ryu.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration                        // 스프링 설정 클래스임을 의미
@EnableWebSecurity                    // 시큐리티 기능을 활성화
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                // CSRF 보호 기능을 끔 (POST 요청에도 토큰 검사 안 함)
                // 이건 빠르게 테스트할 때만 끄고 실제 서비스에서는 케이스에 맞게 유지/비활성 결정해야 함
                .csrf(csrf -> csrf.disable())

                // URL 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // /public 은 인증 없이 접근 허용
                        .requestMatchers("/public").permitAll()

                        // 나머지 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                )

                // Form 기반 로그인 설정
                .formLogin(login -> login
                        // 로그인 페이지 URL (기본 /login 말고 커스텀 페이지 사용)
                        .loginPage("/custom-login")

                        // 로그인 폼에서 submit하는 URL (스프링이 인증 처리함)
                        // 예: <form action="/login" method="post">
                        .loginProcessingUrl("/login")

                        // 로그인 성공 후 이동할 기본 경로
                        .defaultSuccessUrl("/hello")

                        // 로그인 페이지는 누구나 접근 가능하도록 설정
                        .permitAll()
                )

                // 로그아웃 설정
                .logout(logout -> logout
                        // 로그아웃 요청 URL (스프링이 처리함)
                        .logoutUrl("/logout")

                        // 로그아웃 성공 시 이동할 URL
                        .logoutSuccessUrl("/public")
                );

        // 구성된 SecurityFilterChain 객체 생성
        return http.build();
    }
}
