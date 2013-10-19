package com.sqrl;

import com.sqrl.authc.credential.SQRLPublicKeyId;
import com.sqrl.authc.credential.SQRLSignature;
import com.sqrl.utils.Base64Url;

public class SQRLAuthentication {

    /**
     * The crypto signature of the siteURL (512-bits) and the signed payload
     */
    private SQRLSignature identityAuthentication;

    /**
     * The user identification for this site
     */
    private final SQRLPublicKeyId sqrlAnonymousId;

    public SQRLAuthentication(String sqrlRealm, String siteURL, byte[] identityAuthentication, byte[] identityPublicKey) {
        this.sqrlAnonymousId = new SQRLPublicKeyId(sqrlRealm,identityPublicKey);
        this.identityAuthentication = new SQRLSignature(siteURL,identityAuthentication);
    }

    public String getSiteURL() {
        return identityAuthentication.getSiteURL();
    }

    public byte[] getSignature() {
        return identityAuthentication.getSignature();
    }

    public byte[] getPublicKey() {
        return sqrlAnonymousId.getKey();
    }

    @Override
    public String toString() {
        return "SQRLAuthentication [siteURL=" + getSiteURL() + ", signature="
                + Base64Url.encode(getSignature()) + ", publicKey="
                + Base64Url.encode(getPublicKey()) + "]";
    }
}
