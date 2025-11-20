package com.ryu.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${frontend.url}")
    private String frontendUrl;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)

                // URL 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        // 회원가입, public 페이지는 누구나 접근 허용
                        .requestMatchers("/public", "/api/signup").permitAll()

                        // 관리자 전용 URL
                        .requestMatchers("/admin/**").hasRole("ADMIN") // ROLE_ADMIN

                        // USER, ADMIN 공통 URL
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")

                        // 나머지는 로그인만 되어 있으면 허용
                        .anyRequest().authenticated()
                )

                .formLogin(login -> login
                        .loginPage(frontendUrl + "/custom-login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/hello")
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/public")
                );

        return http.build();
    }
}
