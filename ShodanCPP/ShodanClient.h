#ifndef H_SHODANCLIENT
#define H_SHODANCLIENT

#include "curl/curl.h"
#include "document.h"
#include "allocators.h"
#include <iostream>
#include <stdarg.h>
#include <memory> 
#include "string_view_lite.hpp"

static bool CurlWasInitialized = false;
static char errorBuffer[CURL_ERROR_SIZE];
static std::string NULL_STRING = "";

std::string string_format(const std::string fmt_str, ...);

class ShodanClient
{
private:
	const char* api_url;
	const char* stream_api_url;
	const char* exploits_api_url;
	const char* api_key;
	CURL* curl;
	CURLcode result;
	std::string buffer;

	static int writer(char* data, size_t size, size_t nmemb, std::string* buffer)
	{
		int result = 0;
		if (buffer != NULL)
		{
			buffer->append(data, size * nmemb);
			result = size * nmemb;
		}
		return result;
	}

	//Curl request sender
	std::string& GetData()
	{
		buffer.clear();
		result = curl_easy_perform(curl);
		//return request type to default
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
		curl_easy_setopt(curl, CURLOPT_POST, 0);
		if (result == CURLE_OK)
		{
			return buffer;
		}
		else
		{
			std::cout << "Error " << std::to_string(result) << "\n";
			return NULL_STRING;
		}	
	}
	// Shorthand for method without parameters (or with params only in CURLOPT_POSTFIELDS)
	inline void NoGETParamsMethod(const char* method)
	{
		curl_easy_setopt(curl, CURLOPT_URL, string_format("%s%s?key=%s", api_url, method, api_key).c_str());
	}

public:
	//Constructor
	ShodanClient() : api_url("https://api.shodan.io"), stream_api_url("https://stream.shodan.io"), exploits_api_url("https://exploits.shodan.io")
	{
		buffer.reserve(100);
		if (!CurlWasInitialized)
		{
			curl = curl_easy_init();
		}
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
		curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "ShodanCPP");
		curl_easy_setopt(curl, CURLOPT_URL, api_url);
		if (curl)
		{
			std::cout << "Initialized ShodanClient\n";
		}
		else
		{
			std::cout << "Can't initialize CURL!\n";
		}
	}

	~ShodanClient()
	{		
		curl_easy_cleanup(curl);
	}

	//Sets Shodan API key.
	void SetAPIKey(nonstd::string_view key);

	//Search methods

	//Returns all services that have been found on the given host IP.
	std::string GetHostInfo(nonstd::string_view ip, bool history = false, bool minify = false);
	//Returns the total number of results that matched the query and any facet information that was requested.
	std::string GetHostCount(nonstd::string_view query, nonstd::string_view facets = "");
	//Search Shodan using the same query syntax as the website and use facets to get summary information for different properties.
	std::string SearchHost(nonstd::string_view query, nonstd::string_view facets, int page = 1, bool minify = true );
	//Returns a list of facets that can be used to get a breakdown of the top values for a property.
	std::string GetFacets();
	//Returns a list of search filters that can be used in the search query.
	std::string GetFilters();
	//Returns which filters are being used by the query string and what parameters were provided to the filters.
	std::string GetTokens(nonstd::string_view query);
	//Returns a list of port numbers that the crawlers are looking for.
	std::string GetPorts();

	//Shodan On-Demand Scanning

	//Returns an object containing all the protocols that can be used when launching an Internet scan.
	std::string GetProtocols();
	//Use this method to request Shodan to crawl a network.
	std::string Scan(nonstd::string_view ips);
	//Use this method to request Shodan to crawl the Internet for a specific port.
	//Restricted to security researchers and companies with a Shodan Enterprise Data license.
	std::string ScanInternet(int port, nonstd::string_view ips);
	//Check the progress of a previously submitted scan request.
	std::string GetScanStatus(nonstd::string_view id);

	//Shodan Network Alerts

	//Use this method to create a network alert for a defined IP / netblock
	std::string CreateAlert(nonstd::string_view name, nonstd::string_view filters_ip, int expires = 0);
	//Returns a listing of all the network alerts that are currently active on the account.
	std::string GetAllAlertsInfo();
	//Returns the information about a specific network alert.
	std::string GetAlertInfo(nonstd::string_view id);
	//Remove the specified network alert.
	std::string DeleteAlert(nonstd::string_view id);
	//Add the specified notifier to the network alert. Notifications are only sent if triggers have also been enabled.
	std::string AddAlertNotifier(nonstd::string_view alert_id, nonstd::string_view notifier_id);
	//Remove the notification service from the alert. Notifications are only sent if triggers have also been enabled.
	std::string DeleteAlertNotifier(nonstd::string_view alert_id, nonstd::string_view notifier_id);
	//Returns a list of all the triggers that can be enabled on network alerts.
	std::string GetAlertTriggers();
	//Get notifications when the specified trigger is met.
	std::string EnableAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name);
	//Stop getting notifications for the specified trigger.
	std::string DisableAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name);
	//Ignore the specified service when it is matched for the trigger.
	std::string StartIgnoreAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name, nonstd::string_view service);
	//Start getting notifications again for the specified trigger.
	std::string StopIgnoreAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name, nonstd::string_view service);

	//Notifiers
	
	//Get a list of all the notifiers that the user has created.
	std::string GetAllNotifiers();
	//Use this method to create a new notification service endpoint that Shodan services can send notifications through.
	//Example of params: "chat_id=1337&token=abcd"
	std::string CreateNotifier(nonstd::string_view params);
	//Get a list of all the notification providers that are available and the parameters to submit when creating them.
	std::string GetAllNotificationProviders();
	//Remove the notification service created for the user.
	std::string DeleteNotifier(nonstd::string_view id);
	//Use this method to create a new notification service endpoint that Shodan services can send notifications through.
	std::string GetNotifierInfo(nonstd::string_view id);
	//Use this method to update the parameters of a notifier.
	std::string EditNotifier(nonstd::string_view id, nonstd::string_view params);

	//Shodan Directory Methods

	//Use this method to obtain a list of search queries that users have saved in Shodan.
	std::string GetSavedQueries(int page = 0, nonstd::string_view sort = "", nonstd::string_view order = "");
	//Use this method to search the directory of search queries that users have saved in Shodan.
	std::string GetDirectoryOfSavedQueires(nonstd::string_view query, int page = 0);
	//Use this method to obtain a list of popular tags for the saved search queries in Shodan.
	std::string GetPopularTagsForSavedQueries(int size = 10);

	//Shodan Bulk Data

	//Use this method to see a list of the datasets that are available for download.
	std::string GetAvailableDatasets();
	//Get a list of files that are available for download from the provided dataset.
	std::string GetListOfDatasetFiles(nonstd::string_view dataset_name);

	//Manage Organization

	//Get information about your organization such as the list of its members, upgrades, authorized domains and more.
	std::string GetOrgInfo();
	//Add a Shodan user to the organization and upgrade them.
	std::string AddOrgUser(nonstd::string_view user, bool notify = false);
	//Remove and downgrade the provided member from the organization.
	std::string DeleteOrgUser(nonstd::string_view user);

	//Account Methods

	//Returns information about the Shodan account linked to the API key.
	std::string GetProfileInfo();

	//DNS Methods

	//Get all the subdomains and other DNS entries for the given domain. Uses 1 query credit per lookup.
	std::string GetDNSDomainInfo(nonstd::string_view domain);
	//Look up the IP address for the provided list of hostnames.
	std::string ResolveDNS(nonstd::string_view hostnames);
	//Look up the hostnames that have been defined for the given list of IP addresses.
	std::string ReverseDNS(nonstd::string_view ips);

	//Utility Methods

	//Shows the HTTP headers that your client sends when connecting to a webserver.
	std::string GetHTTPHeaders();
	//Get your current IP address as seen from the Internet.
	std::string GetMyIP();

	//API Status Methods

	//Returns information about the API plan.
	std::string GetAPIInfo();

	//Experimental Methods

	//Calculates a honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot).
	std::string GetHoneyScore(nonstd::string_view ip);

	//Shodan Data Streams

	//This stream provides ALL of the data that Shodan collects. If you only care about specific ports, please use the Ports stream.
	std::string GetAllBanners();
	//This stream provides a filtered, bandwidth-saving view of the Banners stream in case you are only interested in devices located in certain ASNs.
	std::string GetASNBanners(nonstd::string_view asn);
	//This stream provides a filtered, bandwidth-saving view of the Banners stream in case you are only interested in devices located in certain countries.
	std::string GetCountriesBanners(nonstd::string_view countries);
	//This stream provides a filtered, bandwidth-saving view of the Banners stream in case you are only interested in a specific list of ports.
	std::string GetPortsBanners(nonstd::string_view ports);
	//Subscribe to banners discovered on all IP ranges described in the network alerts.
	std::string SubscribeToBannersInAllAlerts();
	//Subscribe to banners discovered on the IP range defined in a specific network alert.
	std::string SubscribeToBannersInAlert(nonstd::string_view id);

	//Shodan Exploits Methods

	//Search across a variety of data sources for exploits and use facets to get summary information.
	std::string GetExploits(nonstd::string_view query, nonstd::string_view facets = "", int page = 0);
	//This method behaves identical to the GetExploits method with the difference that it doesn't return any results.
	std::string GetExploitsCount(nonstd::string_view query, nonstd::string_view facets = "");

	//Util (not part of Shodan API!)

	//Removes all network alerts.
	//Returns a list of deleted alerts
	std::string DeleteAllAlerts();
};

#endif