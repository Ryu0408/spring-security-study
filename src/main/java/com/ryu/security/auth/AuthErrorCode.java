package com.ryu.security.auth;

public enum AuthErrorCode {

    BAD_CREDENTIALS("bad_credentials", "아이디 또는 비밀번호가 올바르지 않습니다."),
    LOCKED("locked", "계정이 잠겨 있습니다."),
    DISABLED("disabled", "비활성화된 계정입니다."),
    CREDENTIALS_EXPIRED("credentials_expired", "비밀번호 유효기간이 만료되었습니다."),
    ACCOUNT_EXPIRED("account_expired", "계정 유효기간이 만료되었습니다."),
    UNKNOWN("unknown", "로그인에 실패했습니다.");

    private final String code;
    private final String defaultMessage;

    AuthErrorCode(String code, String defaultMessage) {
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    public String getCode() {
        return code;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
