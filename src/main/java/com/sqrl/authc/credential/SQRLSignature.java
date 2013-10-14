package com.sqrl.authc.credential;

/**
 * A signature and challenge to be verified for an authentication request.
 */
public class SQRLSignature {
    /**
     * Entire site URL that this authentication object was generated for. (E.g.
     * "www.example.com/sqrl?KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz")
     */
    private String siteURL;

    /**
     * The crypto signature of the siteURL (512-bits) aka identityAuthentication
     */
    private byte[] sqrlsig;

    public SQRLSignature(String siteUrl, byte[] signature) {
        this.sqrlsig = signature;
    }

    public String getSiteURL() {
        return siteURL;
    }

    public byte[] getSignature() {
        return sqrlsig;
    }
}
