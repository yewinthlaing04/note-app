package com.ye.backend.service;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface ITotpService {
    GoogleAuthenticatorKey generateSecret();

    String getQrCodeUrl(GoogleAuthenticatorKey key, String username);

    boolean verifyCode(String secret, int code);
}
