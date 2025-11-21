package com.ryu.security.auth;

import com.ryu.security.auth.dto.MeResponse;
import com.ryu.security.user.CustomUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class MeController {

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(Authentication authentication) {

        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails principal)) {
            // SecurityConfig에서 AuthenticationEntryPoint가 처리하므로,
            // 여기까지 오면 거의 없음. 그래도 방어 코드.
            return ResponseEntity.status(401).build();
        }

        MeResponse response = new MeResponse(
                principal.getUsername(),
                principal.getRole()    // "ROLE_USER", "ROLE_ADMIN"
        );

        return ResponseEntity.ok(response);
    }
}
