#include "ShodanClient.h"

int main(void)
{
    //Print information about the API plan.
    ShodanClient cl;
    cl.SetAPIKey("insert api key here");
    std::cout << cl.GetAPIInfo() << "\n";

    //Print the number of devices that have the string "webcam" in their banner
    rapidjson::Document doc;
    doc.Parse(cl.GetHostCount("webcam").c_str());
    std::cout << doc["total"].GetInt() << "\n";
    return 0;
}