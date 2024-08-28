/*********************************************************************************
 * This file is part of CUTE.
 *
 * CUTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CUTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with CUTE.  If not, see <http://www.gnu.org/licenses/>.
 *
 *********************************************************************************/
#ifndef XML_OUTPUT_FILE_
#define XML_OUTPUT_FILE_

#include <fstream>

namespace cute {

class xml_output_file {

private:
    std::string filename;
    std::ofstream resultFile;

private:
    xml_output_file(const xml_output_file& copy);
    xml_output_file& operator= (const xml_output_file& other);

public:
    xml_output_file(const std::string& fn) : filename(fn) {
    	// TODO handle io exceptions
        openFile();
        writePrologue();
	}

    ~xml_output_file() {
    	writeEpilogue();
    	// fstream is RAII, so resources are released (and closed) implicitly
    }

    void testsuiteStart(const std::string& name, const int size) {
    	resultFile << ONE_TAB << "<testsuite name=\"" << name << "\" tests=\"" << size << "\">" << std::endl;
    }

    void testsuiteEnd() {
    	resultFile << ONE_TAB << "</testsuite>" << std::endl;
    }

    void testcaseStart(const std::string& classname, const std::string& testname) {
    	resultFile << TWO_TABS << "<testcase classname=\"" << classname << "\" name=\"" << testname << "\"";
    }

    void testcaseSuccess() {
    	// close testcase element
    	resultFile << "/>" << std::endl;
    }

    void testcaseFailure(const std::string & filename, const int lineno, const std::string & reason)
    {
    	// let testcase element open
    	resultFile << ">" << std::endl;
        resultFile << THREE_TABS << "<failure message=\"" << filename << ":" << lineno << " " << reason << "\"/>" << std::endl;
        testcaseEnd();
    }

    void testcaseError(const std::string& testname, const std::string& what) {
    	// let testcase element open
    	resultFile << ">" << std::endl;
		resultFile << THREE_TABS << "<failure message=\"" << testname << " " << what << "\"/>" << std::endl;
		testcaseEnd();
    }

private:
    void writePrologue() {
        resultFile << "<testsuites>" << std::endl;
    }

    void writeEpilogue() {
        resultFile << "</testsuites>" << std::endl;
    }

    void openFile() {
        resultFile.open(filename.c_str());
    }

    void testcaseEnd() {
        resultFile << TWO_TABS << "</testcase>" << std::endl;
    }

private:
    static const char* ONE_TAB;
    static const char* TWO_TABS;
    static const char* THREE_TABS;
};

const char* xml_output_file::ONE_TAB = "\t";
const char* xml_output_file::TWO_TABS = "\t\t";
const char* xml_output_file::THREE_TABS = "\t\t\t";

}

#endif /* XML_OUTPUT_FILE_ */
