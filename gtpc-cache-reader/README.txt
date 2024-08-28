=============================== GTP-C cache reader ===============================

This is a simple application that reads in a cache file from the pcp-pect application and outputs it's contents to
stdout using the provided PDPSession* stream operator.  Existing pcp-pect code has been reused throughout the
application, and as such a few abnormal dependencies are required (such as a dependency on the Napatech ntos library,
even though it is not used).  As such, the environment required for it to run more-or-less means that it has to be run
on a PCP server.  The application is absolutely in it's infancy at this stage, and will need to grow to become more
useful, but either way shows in some way how the code can be re-used.

BUILDING: 
--------- 
1) From the top level of the git repository (i.e. this projects parent directory) run the following maven build
	# mvn clean install -P library

   This builds the pcp-pect application as a static library and installs it into your local maven repository

2) From the gtpc-cache-reader directory (.../pcp_pect/gtpc-cache-reader/) run the following maven build
	# mvn clean compile

   This builds the gtpc-cache-reader application, linking it against the static library created in step 1)

The above steps will create an executable, located at
.../pcp_pect/gtpc-cache-reader/target/nar/gtpc-cache-reader-1.0.0-amd64-Linux-gpp-executable/bin/amd64-Linux-gpp/gtpc-cache-reader.

RUNNING: 
-------- 
Currently the application takes no parameters, so it can be invoked by the simple command line:
	# ./gtpc-cache-reader

The cache file is always read from a subdirectory named 'cache', relative to your current directory.

The application uses existing log4cxx definitions, including the logging statements located in pcp-pect code.  The log
configuration file is handled in the same manner as pcp-pect, it is loaded from the current directory, and must be named
log_config.xml.  It must contain the three core appenders which are found in the pcp-pect log_config.xml, so re-use of
the existing configuration is encouraged.

Directory structure required for execution

.../ 
   |-- gtpc_cache_reader 
   |-- log_config.xml 
   |-- cache/ 
      \-- gtpc.cache-001

