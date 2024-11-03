package com.ye.backend.service.impl;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.ye.backend.service.ITotpService;
import org.springframework.stereotype.Service;

@Service
public class TotpService implements ITotpService {
  private final GoogleAuthenticator gAuth;

    public TotpService(GoogleAuthenticator gAuth) {
        this.gAuth = gAuth;
    }

    public TotpService() {
        this.gAuth = new GoogleAuthenticator();
    }

    @Override
    public GoogleAuthenticatorKey generateSecret(){
        return gAuth.createCredentials();
    }

    @Override
    public String getQrCodeUrl(GoogleAuthenticatorKey secret, String username){
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("Secure Notes Application", username, secret);
    }

    @Override
    public boolean verifyCode(String secret, int code){
        return gAuth.authorize(secret, code);
    }
}
