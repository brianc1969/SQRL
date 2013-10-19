package com.sqrl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.sqrl.utils.Base64Url;

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

    /**
     * Encapsulates all of the password information
     */
    private SQRLPasswordParameters passwordParameters;

    public SQRLIdentity(String identityName, byte[] masterIdentityKey, byte[] passwordVerify, byte[] passwordSalt,
                        SQRLPasswordParameters passwordParameters) {
        this.identityName = identityName;
        this.masterIdentityKey = masterIdentityKey;
        this.passwordVerify = passwordVerify;
        this.passwordSalt = passwordSalt;
        this.passwordParameters = passwordParameters;
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
    
    public SQRLPasswordParameters getPasswordParameters() {
        return passwordParameters;
    }

    /**
     * pack the exported identity into the agreed upon export format, the
     * current proposal is:
     *     8-bit signature algorithm version
     *     256-bit encrypted master key
     *     8-bit password algorithm version
     *     64-bit per-password nonce
     *     64-bit per-password verifier
     *     16-bit computation burden spec (10 bit mantissa + 6 bit exp)
     *
     * in this implementation, "computation burden" is replaced with the following 4-byte value:
     *     8-bit SCrypt base-2 exponent of N parameter
     *     8-bit SCrypt r parameter
     *     16-bit SCrypt p parameter
     *
     * @return exported packaged identity
     * @throws IOException
     */
    public byte[] createExportPackage() throws IOException {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        bytesOut.write(1); // signature algorithm version
        bytesOut.write(getMasterIdentityKey()); // encrypted master key
        bytesOut.write(1); // password algorithm version
        bytesOut.write(getPasswordSalt()); // per-password nonce
        bytesOut.write(getPasswordVerify());
        bytesOut.write(getPasswordParameters().getHashN());
        bytesOut.write(getPasswordParameters().getHashR());
        bytesOut.write((getPasswordParameters().getHashP() >>> 8) & 0xFF);
        bytesOut.write((getPasswordParameters().getHashP() >>> 0) & 0xFF);
        return bytesOut.toByteArray();
    }

    @Override
    public String toString() {
        return "SQRLIdentity [identityName=" + identityName + ", masterIdentityKey="
                + Base64Url.encode(masterIdentityKey) + ", passwordVerify=" + Base64Url.encode(passwordVerify)
                + ", passwordSalt=" + Base64Url.encode(passwordSalt)
                + ", passwordParameters=" + passwordParameters + "]";
    }
}
