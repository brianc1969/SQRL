package com.sqrl.utils;

public class URLs {
    public static String getTLD(String siteURL) {
        // Example site URL:
        // "www.example.com/~bob/sqrl.php?d=5&nut=KJA7nLFDQWWmvt10yVjNDoQ81uTvNorPrr53PPRJesz";
        String tld = new String();
        int d = 0;

        tld = siteURL.split("\\?")[0];
        String params[] = siteURL.split("\\?")[1].split("&");

        for (String param : params) {
            if (param.startsWith("d=")) {
                try {
                    d = Integer.parseInt(param.split("=")[1]);
                } catch (NumberFormatException e) {
                    d = 0;
                }
            }
        }

        // Find the first / to find the end of the normal TLD
        int endOfTld = tld.indexOf("/");
        // Add the value of d, to get the SQRL TLD
        endOfTld += d;

        tld = tld.substring(0, endOfTld);
        return tld;
    }
}
