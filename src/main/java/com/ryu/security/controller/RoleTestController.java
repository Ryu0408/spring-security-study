package com.ryu.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RoleTestController {

    @GetMapping("/user/me")
    public String userMe() {
        return "USER 또는 ADMIN 권한이면 볼 수 있는 정보입니다.";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard() {
        return "ADMIN 전용 대시보드입니다.";
    }
}
