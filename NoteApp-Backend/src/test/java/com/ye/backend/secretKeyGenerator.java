package com.ye.backend;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Base64;

public class secretKeyGenerator {
    public static void main(String[] args) {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256); // Generates a 256-bit key
        String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Base64 Encoded Secret Key: " + base64Key);
    }
}
