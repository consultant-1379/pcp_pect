package com.ericsson.pcp;

/**
 * @author ericker
 * @since 05/06/13
 */
import com.ericsson.eniq.licensing.cache.LicenseInformation;

import java.util.Vector;

/**
 * Interface for accessing the ENIQ RMI Licensing service
 *
 * @author ericker
 *
 */
public interface LicensingService {

    /**
     * Check if the specified license is a valid license
     * This class checks all license information with the ENIQ RMI Licensing service
     *
     * @param licenseCXC                eg CXC123456
     * @return boolean                  true if specified license valid, false otherwise
     * @throws CannotAccessLicensingServiceException
     */
    boolean hasLicense(String licenseCXC) throws CannotAccessLicensingServiceException;

}