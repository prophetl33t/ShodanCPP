# ShodanCPP

ShodanCPP is a C++ library for accessing the Shodan API.

Cloning a repository with submodules:
```shell
git clone --recursive https://github.com/prophetl33t/ShodanCPP.git
git submodule update --init --recursive
```

Usage example:

   	//Print information about the API plan.
    ShodanClient cl;
    cl.SetAPIKey("insert api key here");
    std::cout << cl.GetAPIInfo() << "\n";

    //Print the number of devices that have the string "webcam" in their banner
    rapidjson::Document doc;
    doc.Parse(cl.GetHostCount("webcam").c_str());
    std::cout << doc["total"].GetInt() << "\n";

Dependencies:

curl (https://curl.haxx.se)

rapidjson (https://github.com/Tencent/rapidjson)

string_view_lite (https://github.com/martinmoene/string-view-lite)

The repository contains a solution for Visual Studio 2019 and CMakeLists.txt, in case you want to use a different IDE. The library was tested only on Windows, but apparently it works on linux too (if you find the curl library yourself).
