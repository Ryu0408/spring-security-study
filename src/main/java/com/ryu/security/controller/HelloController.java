package com.ryu.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello Secure World!";
    }

    @GetMapping("/public")
    public String publicPage() {
        return "This is public page";
    }
}
