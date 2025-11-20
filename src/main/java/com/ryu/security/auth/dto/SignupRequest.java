package com.ryu.security.auth.dto;

public class SignupRequest {

    private String username;
    private String password;

    // 기본 생성자
    public SignupRequest() {}

    public SignupRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // getter / setter
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
