package com.ericsson.pcp;

import com.beust.jcommander.Parameter;

/**
 * @author ericker
 * @since 04/06/13
 */
public class Arguments {
    @Parameter(names = "-rmiHost")
    public String rmiHost = "licenceserver";

    @Parameter(names = "-rmiPort")
    public int rmiPort = 1200;

    @Parameter(names = "-licensingServiceName")
    public String licensingServiceName = "LicensingCache";

    public String getLicensingServiceURL() {
        return "rmi://" + rmiHost + ":" + rmiPort + "/" + licensingServiceName;
    }
}
