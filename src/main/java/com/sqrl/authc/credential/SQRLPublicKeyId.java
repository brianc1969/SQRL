package com.sqrl.authc.credential;

/**
 * A SQRL public key id. This is bound to a specific domain name. It is appropriate to use this as the primary key for
 * a user's identity on a single site.
 */
public class SQRLPublicKeyId {
    /**
     * The scheme + TLD + path fraction which corresponds to this SQRL Id
     */
    final String sqrlRealm;

    /**
     * The public key correstponding to the token signature. This will allow the site
     * to verify the identityAuthentication inside the credentials.
     */
    final byte[] sqrlkey;

    public SQRLPublicKeyId(String realm, byte[] key) {
        this.sqrlRealm = realm;
        this.sqrlkey = key;
    }

    public String getRealm() {
        return sqrlRealm;
    }

    public byte[] getKey() {
        return sqrlkey;
    }
}
