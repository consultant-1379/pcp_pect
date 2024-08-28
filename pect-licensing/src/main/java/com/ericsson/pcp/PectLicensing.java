package com.ericsson.pcp;

/**
 * @author ericker
 * @since 05/06/13
 */
public class PectLicensing {

    private Arguments arguments;
    private String licenceCXCString;

    public PectLicensing(Arguments arguments, String licenseCXCString) {
        this.arguments = arguments;
        this.licenceCXCString = licenseCXCString;
    }

    public String getMagicString() throws CannotAccessLicensingServiceException, MagicStringException, InvalidLicenseException {
        LicensingService licensingService = new LicensingServiceImpl(arguments);

        if(licensingService.hasLicense(licenceCXCString)) {
            return MagicString.makeMagicString();
        } else {
            throw new InvalidLicenseException();
        }

    }
}
