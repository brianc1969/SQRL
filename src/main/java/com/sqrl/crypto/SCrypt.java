package com.sqrl.crypto;

import java.security.GeneralSecurityException;
import java.text.DecimalFormat;

import com.sqrl.SQRLPasswordParameters;

public class SCrypt {
    private static final DecimalFormat df = new DecimalFormat("#.##");
    
    public static byte[] scrypt(String password, byte[] passwordSalt, SQRLPasswordParameters passwordParameters) {
        if ( passwordSalt == null ) throw new IllegalArgumentException("password salt is null");
        if ( passwordParameters == null ) throw new IllegalArgumentException("password parameters are null");
        int scryptN = (1 << passwordParameters.getHashN());
        try {
            long startTime = System.currentTimeMillis();
            byte[] scryptResult = com.lambdaworks.crypto.SCrypt.scrypt(password.getBytes(), 
                                               passwordSalt, scryptN, passwordParameters.getHashR(), 
                                               passwordParameters.getHashP(), passwordParameters.getHashLength());
            long elapsedTime = System.currentTimeMillis() - startTime;
//            System.out.println("SCrypt (N = " + scryptN + ") took " + df.format(elapsedTime/1000.0) + " seconds.");
            return scryptResult;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }
}
