ShodanCPP is a C++ library for accessing the Shodan API.

Usage example:

   	//Print information about the API plan.
    ShodanClient cl;
    cl.SetAPIKey("insert api key here");
    std::cout << cl.GetAPIInfo() << "\n";

    //Print the number of devices that have the string "webcam" in their banner
    rapidjson::Document doc;
    doc.Parse(cl.GetHostCount("webcam").c_str());
    std::cout << doc["total"].GetInt() << "\n";

Libraries used:

curl (https://curl.haxx.se)

rapidjson (https://github.com/Tencent/rapidjson)

string_view_lite (https://github.com/martinmoene/string-view-lite)


