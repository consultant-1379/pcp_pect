package com.ericsson.pcp;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author ericker
 * @since 05/06/13
 */
public class MagicString {
    static final String magicStringA = "Use the Force, Luke!";
    static final String magicStringZ = "My spider-sense is tingling!";

    static final int SHA256_DIGEST_LENGTH = 32;


    public static String  makeMagicString() throws MagicStringException {
        MessageDigest messageDigest = null;
        String magic0;

        long epochHour = (((System.currentTimeMillis() / 1000) + 3599) / 3600);
        String epochHourString = null;

        try {
            messageDigest = MessageDigest.getInstance("SHA-256");


            messageDigest.update(magicStringA.getBytes("US-ASCII"), 0, magicStringA.length());
            epochHourString = String.format("%016x", epochHour);
            messageDigest.update(epochHourString.getBytes("US-ASCII"), 0, 16);
            messageDigest.update(magicStringZ.getBytes("US-ASCII"), 0, magicStringZ.length());
            final byte[] m0digest = messageDigest.digest();
            magic0 = "";
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                magic0 += String.format("%02x", m0digest[i]);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new MagicStringException(e);
        } catch (UnsupportedEncodingException e) {
            throw new MagicStringException(e);
        }

        return  magic0;
    }
}