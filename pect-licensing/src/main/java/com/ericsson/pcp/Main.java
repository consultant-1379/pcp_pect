package com.ericsson.pcp;

import com.beust.jcommander.JCommander;

public class Main
{
	private static final String PCP_LICENCE_CXC = "CXC4011506";

    private static final String INVALID_LICENCE_STRING = "PCP Feature Licence is not valid (" + PCP_LICENCE_CXC + ")";
    private static String UNABLE_TO_CHECK_LICENCE_STRING;
    private static final String UNABLE_TO_GENERATE_MAGIC_STRING = "Unable to generate licence string";

    public static void main( String[] args )
    {
        Arguments arguments = new Arguments();
        new JCommander(arguments, args);
        UNABLE_TO_CHECK_LICENCE_STRING = "Unable to connect to licence server at URL " + arguments.getLicensingServiceURL();
        PectLicensing pectLicensing = new PectLicensing(arguments, PCP_LICENCE_CXC);
        String magicString = null;
        try {
            magicString = pectLicensing.getMagicString();
            System.out.println(magicString);
            System.exit(0);
        } catch (CannotAccessLicensingServiceException e) {
            System.out.println(UNABLE_TO_CHECK_LICENCE_STRING);
            e.printStackTrace();
            System.exit(1);
        } catch (MagicStringException e) {
            System.out.println(UNABLE_TO_GENERATE_MAGIC_STRING);
            e.printStackTrace();
            System.exit(2);
        } catch (InvalidLicenseException e) {
            System.out.println(INVALID_LICENCE_STRING);
            e.printStackTrace();
            System.exit(3);
        }
        catch (Exception ex)
        {
            ex.printStackTrace();
            System.exit(5);

        }

    }
}
