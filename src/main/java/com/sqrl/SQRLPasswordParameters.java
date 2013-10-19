package com.sqrl;


/**
 * Encapsulates all of the password encryption parameters.
 */
public class SQRLPasswordParameters {
    /**
     * SCrypt number of rounds
     */
    private int N;

    /**
     * SCrypt memory factor
     */
    private int r;

    /**
     * SCrypt parallelization factor
     */
    private int p;

    /**
     * SCrypt hash output length
     */
    private int dkLen;

    public SQRLPasswordParameters(int N, int r, int p) {
        this.N = N;
        this.r = r;
        this.p = p;
        this.dkLen = 32;
    }

    public int getHashN() {
        return N;
    }

    public int getHashR() {
        return r;
    }

    public int getHashP() {
        return p;
    }

    public int getHashLength() {
        return dkLen;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[N=" + N + ", r=" + r + ", p=" + p + "]";
    }
}
