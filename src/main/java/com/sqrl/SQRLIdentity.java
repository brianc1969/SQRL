package com.sqrl;

import com.sun.org.apache.xml.internal.security.utils.Base64;

/**
 * Represents a SQRL identity.
 * 
 * This class is immutable, actions like password updates will cause the master
 * identity key and password salt to also change, so a new SQRL Idenity should
 * be created.
 */
public class SQRLIdentity {

    /** Optional identity name / identifier */
    private String identityName = "";

    /**
     * Private Master Identity Key (256-bits)
     * 
     * This key is XORed with the result of the password strengthening to create
     * the original master key
     */
    private byte[] masterIdentityKey;

    /**
     * Password Verify Value (128-bits)
     * 
     * This is the first 128-bits of SHA256(scrypt_result) and is used to verify
     * the password was entered correctly.
     */
    private byte[] passwordVerify;

    /**
     * Password Salt (64-bits)
     * 
     * This is a randomly generated salt value generated when the password is
     * first set. Whenever the password changes, this also should change.
     */
    private byte[] passwordSalt;

    public SQRLIdentity(String identityName, byte[] masterIdentityKey, byte[] passwordVerify, byte[] passwordSalt) {
        this.identityName = identityName;
        this.masterIdentityKey = masterIdentityKey;
        this.passwordVerify = passwordVerify;
        this.passwordSalt = passwordSalt;
    }

    public String getIdentityName() {
        return identityName;
    }

    public byte[] getMasterIdentityKey() {
        return masterIdentityKey;
    }

    public byte[] getPasswordVerify() {
        return passwordVerify;
    }

    public byte[] getPasswordSalt() {
        return passwordSalt;
    }

    @Override
    public String toString() {
        return "SQRLIdentity [identityName=" + identityName + ", masterIdentityKey=" + Base64.encode(masterIdentityKey)
                + ", passwordVerify=" + Base64.encode(passwordVerify) + ", passwordSalt=" + Base64.encode(passwordSalt)
                + "]";
    }

}
