package com.sqrl.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

import com.sqrl.SQRLAuthentication;
import com.sqrl.SQRLIdentity;
import com.sqrl.SQRLPasswordParameters;
import com.sqrl.exception.SQRLException;
import com.sqrl.utils.Base64Url;
import com.sqrl.utils.URLs;

public class TestSQRLClient {

    // stored user profile information, This should be loaded off disk for an
    // existing sqrl identity OR
    // generated fresh for a new sqrl identity
    // 256-bit private master identity key
    // 64-bit password salt
    // 256-bit password verify value
    byte[] privateMasterIdentityKey = Base64Url.decode("VxXA0VcczUN6nj_9bMVlCeP7ogpqhmLCK54GIFTSl1s");
    byte[] passwordSalt = Base64Url.decode("Ze6tha--1E0");
    byte[] passwordVerify = Base64Url.decode("wMS9dlme6gyPDkT9obtWiQyLYiLLC9nv-QJICM3xgXI");

    SQRLPasswordParameters examplePasswordParameters = new SQRLPasswordParameters(passwordSalt, 16, 8, 12);
    SQRLIdentity exampleIdentity = new SQRLIdentity("example identity", privateMasterIdentityKey, passwordVerify,
            examplePasswordParameters);

    @Test
    public void testLogin() {
        // STEP 0: Have the user enter the password for the identity.
        // example user-entered password
        String password = "password";

        // This is the web-site URL the user is going to login to using SQRL.
        // This URL would normally be decoded from the QR-code displayed on the
        // site
        String siteURL = "www.example.com/~bob/sqrl.php?d=5&nut=KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";

        try {
            // compute the SQRL authentication
            SQRLAuthentication authentication = SQRLClient.createAuthentication(exampleIdentity, password, siteURL);

            // Expected Values
            String expectedPublicKey = "Tdgn28vzvs29_4F2aC35aWpLaV1VEHGSabSlJ-rrRC4";
            String expectedSig = "c2PK4d2014l3gQZ-ZuOFafg0UHfO-9Dw9UkoouH3ljtycBbWM"
                    + "u3EjECh_bfgIEPz5ID2PLY0F_uoHJMCYuTyCg";

            assertEquals(expectedPublicKey, Base64Url.encode(authentication.getPublicKey()));
            assertEquals(expectedSig, Base64Url.encode(authentication.getSignature()));
        } catch (SQRLException e) {
            fail("Error creating authentication for " + URLs.getTLD(siteURL) + ":" + e.getMessage());
        }
    }

    @Test
    public void testChangePassword() {
        // STEP 0: Have the user enter the current password for the identity.
        // example user-entered password
        String currentPassword = "password";

        // STEP 1: Get the new password from the user
        // User entered password, should probably have them enter twice because
        // there is no returning from the change
        // once its persisted on disk
        String newPassword = "newpassword";

        try {
            // Change the user's password, this will throw
            // PasswordVerifyException if the current password is incorrect
            SQRLIdentity changedPasswordIdentity = SQRLClient.changePassword(exampleIdentity, currentPassword,
                    newPassword);

            // To verify that the password change works as expected, the orginal
            // exampleIdentity and the new
            // changedPasswordIdentity should both still produce the same
            // publickey and signature for a given website.
            String siteURL = "www.example.com/~bob/sqrl.php?d=5&nut=KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
            SQRLAuthentication oldAuth = SQRLClient.createAuthentication(exampleIdentity, currentPassword, siteURL);
            SQRLAuthentication newAuth = SQRLClient.createAuthentication(changedPasswordIdentity, newPassword, siteURL);

            assertEquals(Base64Url.encode(oldAuth.getPublicKey()), Base64Url.encode(newAuth.getPublicKey()));
            assertEquals(Base64Url.encode(oldAuth.getSignature()), Base64Url.encode(newAuth.getSignature()));
        } catch (SQRLException e) {
            fail("Error trying to change password from '" + currentPassword + "' to '" + newPassword + "': "
                    + e.getMessage());
        }
    }

    @Test
    public void testExportMasterKey() {
        /**
         * WARNING: This test takes nearly 2 mins to run because we are creating
         * an exported master key and then verifying it.
         */
        // STEP 0: Have the user enter the current password for the identity.
        // example user-entered password
        String currentPassword = "password";

        try {
            // It is recommended to allow the user to specify a different
            // password when exporting the master key
            // to do this just call change password before exporting:
            // exportMasterKey(changePassword(exampleIdentity, currentPassword,
            // newPassword), newPassword);
            SQRLIdentity exportedIdentity = SQRLClient.exportMasterKey(exampleIdentity, currentPassword);

            // To verify that the exported identity, if imported, would produce
            // the same publickey and signature
            // for a given website url
            String siteURL = "www.example.com/~bob/sqrl.php?d=5&nut=KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
            SQRLAuthentication oldAuth = SQRLClient.createAuthentication(exampleIdentity, currentPassword, siteURL);
            SQRLAuthentication exportedAuth = SQRLClient.createAuthentication(exportedIdentity, currentPassword,
                    siteURL);

            assertEquals(Base64Url.encode(oldAuth.getPublicKey()), Base64Url.encode(exportedAuth.getPublicKey()));
            assertEquals(Base64Url.encode(oldAuth.getSignature()), Base64Url.encode(exportedAuth.getSignature()));
        } catch (SQRLException e) {
            fail("Error exporting master identity key: " + e.getMessage());
        }
    }
}
