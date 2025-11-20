package com.ryu.security.auth;

import com.ryu.security.auth.dto.SignupRequest;
import com.ryu.security.user.UserEntity;
import com.ryu.security.user.UserRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 회원가입 API: /api/signup
    @PostMapping("/api/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {

        // 이미 존재하는 username 체크
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body("이미 사용 중인 아이디입니다.");
        }

        // 새 사용자 생성
        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword())); // 반드시 암호화
        user.setRole("ROLE_USER"); // 기본은 일반 사용자

        userRepository.save(user);

        return ResponseEntity.ok("회원가입 완료");
    }
}
