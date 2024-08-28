package com.ericsson.pcp;

import com.ericsson.eniq.licensing.cache.*;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Vector;

/**
 * @author ericker
 * @since 05/06/13
 */
public class LicensingServiceImpl implements LicensingService {
    private String rmiLicensingServiceURL;

    public LicensingServiceImpl(Arguments arguments) {
        rmiLicensingServiceURL = arguments.getLicensingServiceURL();
    }

    @Override
    public boolean hasLicense(String licenseCXC) throws CannotAccessLicensingServiceException {
        try {
            final LicensingCache licensingCache = (LicensingCache) Naming.lookup(rmiLicensingServiceURL);
            final LicenseDescriptor licenseDescriptor = new DefaultLicenseDescriptor(licenseCXC);
            final LicensingResponse licensingResponse = licensingCache.checkLicense(licenseDescriptor);
            return licensingResponse.isValid();
        } catch (final RemoteException e) {
            throw new CannotAccessLicensingServiceException(e);
        } catch (final MalformedURLException e) {
            throw new CannotAccessLicensingServiceException(e);
        } catch (final NotBoundException e) {
            throw new CannotAccessLicensingServiceException(e);
        }
    }
}
