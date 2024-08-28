package com.ericsson.pcp;

/**
 * @author ericker
 * @since 05/06/13
 */
public class CannotAccessLicensingServiceException extends Exception {
    public CannotAccessLicensingServiceException(final Exception rootException) {
        super(rootException);
    }
}
