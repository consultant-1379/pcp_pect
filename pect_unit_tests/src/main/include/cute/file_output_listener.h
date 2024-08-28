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
#ifndef FILE_OUTPUT_LISTENER_H_
#define FILE_OUTPUT_LISTENER_H_

#include "cute_listener.h"
#include "xml_output_file.h"
#include <boost/shared_ptr.hpp>

namespace cute {

template<typename Listener = null_listener>
class file_output_listener : Listener {

private:
	std::string suiteName;
	boost::shared_ptr<xml_output_file> resultFile;

public:

	file_output_listener() : Listener() {
		resultFile = boost::shared_ptr<xml_output_file>(new xml_output_file(TEST_RESULT_FILE_NAME));
    }

    void begin(const suite & s, const char *info)
    {
        suiteName = std::string(info);
        resultFile->testsuiteStart(suiteName, s.size());
        Listener::begin(s, info);
    }

    void end(const suite & s, const char *info)
    {
        resultFile->testsuiteEnd();
        Listener::end(s, info);
    }

    void start(const test & t)
    {
        resultFile->testcaseStart(suiteName, t.name());
        Listener::start(t);
    }

    void success(const test & t, const char *msg)
    {
        resultFile->testcaseSuccess();
        Listener::success(t, msg);
    }

    void failure(const test & t, const test_failure & e)
    {
        resultFile->testcaseFailure(e.filename, e.lineno, e.reason);
        Listener::failure(t, e);
    }

    void error(const test & t, const char *what)
    {
        resultFile->testcaseError(t.name(), what);
        Listener::error(t, what);
    }

    static const char* TEST_RESULT_FILE_NAME;
};

// kind of ugly...
template <typename T>
const char* file_output_listener<T>::TEST_RESULT_FILE_NAME = "test_results.xml";
}


#endif /* FILE_OUTPUT_LISTENER_H_ */



