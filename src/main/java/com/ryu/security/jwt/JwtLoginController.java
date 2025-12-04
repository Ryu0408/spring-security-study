package com.ryu.security.jwt;

import com.ryu.security.common.ErrorResponse;
import com.ryu.security.user.CustomUserDetails;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/jwt")
public class JwtLoginController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public JwtLoginController(AuthenticationManager authenticationManager,
                              JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public static class LoginRequest {
        @NotBlank
        public String username;

        @NotBlank
        public String password;
    }

    public static class LoginResponse {
        public String accessToken;
        public String tokenType = "Bearer";
        public long expiresIn; // 초

        public LoginResponse(String accessToken, long expiresIn) {
            this.accessToken = accessToken;
            this.expiresIn = expiresIn;
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username, request.password)
            );

            CustomUserDetails principal = (CustomUserDetails) authentication.getPrincipal();

            String token = jwtTokenProvider.createAccessToken(
                    principal.getUsername(),
                    principal.getRole()
            );

            // 설정값과 동일한 만료시간을 내려주고 싶으면 JwtTokenProvider에 getter 추가해도 됨
            long expiresIn = 3600L;

            return ResponseEntity.ok(new LoginResponse(token, expiresIn));

        } catch (BadCredentialsException e) {
            return ResponseEntity
                    .status(401)
                    .body(ErrorResponse.of(
                            401,
                            "UNAUTHORIZED",
                            "bad_credentials",
                            "/api/jwt/login"
                    ));
        }
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails principal)) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        return ResponseEntity.ok("Hello JWT " + principal.getUsername());
    }
}
