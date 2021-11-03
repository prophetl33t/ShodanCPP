#include "ShodanClient.h"

//demo without api key
void Demo1()
{
    ShodanClient cl;
    std::cout << "Your IP address is: " << cl.GetMyIP() << '\n';
}

//demo with api key
void Demo2(nonstd::string_view s)
{
    //Print information about the API plan.
    ShodanClient cl;
    cl.SetAPIKey(s);
    std::cout << cl.GetAPIInfo() << '\n';

    //Print the number of devices that have the string "webcam" in their banner
    rapidjson::Document doc;
    doc.Parse(cl.GetHostCount("webcam").c_str());
    std::cout << doc["total"].GetInt() << '\n';
}

int main(void)
{
    Demo1();

    std::string key;
    std::cout << "Enter your api key:\n";
    std::cin >> key;
    Demo2(key);

    std::cout << "Press any key to continue...";
    std::cin.get();
    std::cin.get();
    return 0;
}