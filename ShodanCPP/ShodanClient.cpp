#include "ShodanClient.h"
#include <prettywriter.h>

std::string string_format(const std::string fmt_str, ...) {
	int final_n, n = ((int)fmt_str.size()) * 2;
	std::unique_ptr<char[]> formatted;
	va_list ap;
	while (1) {
		formatted.reset(new char[n]);
		strcpy(&formatted[0], fmt_str.c_str());
		va_start(ap, fmt_str);
		final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
		va_end(ap);
		if (final_n < 0 || final_n >= n)
			n += abs(final_n - n + 1);
		else
			break;
	}
	std::cout << "Request to api: " << std::string(formatted.get()) << "\n";
	return std::string(formatted.get());
}

void ShodanClient::SetAPIKey(nonstd::string_view key)
{
	api_key = key.data();
}

std::string ShodanClient::GetHostInfo(nonstd::string_view ip, bool history , bool minify )
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/host/%s?key=%s&history=%i&minify=%i", api_url, ip.data(), api_key,history,minify).c_str());
	return GetData();
}

std::string ShodanClient::GetHostCount(nonstd::string_view query, nonstd::string_view facets)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/host/count?key=%s&query=%s&facets=%s", api_url, api_key, query.data(), facets.data()).c_str());
	return GetData();
}

std::string ShodanClient::SearchHost(nonstd::string_view query, nonstd::string_view facets, int page, bool minify)
{
	std::string tmp = "%s/shodan/host/search?key=%s&query=%s&page=%i&minify=%i";

	if (facets.size() != 0)
	tmp.append("&facets=%s");

	curl_easy_setopt(curl, CURLOPT_URL, string_format(std::move(tmp), api_url, api_key, query.data(),page,minify, facets.data()).c_str());
	return GetData();
}

std::string ShodanClient::GetFacets()
{
	NoGETParamsMethod("/shodan/host/search/facets");
	return GetData();
}

std::string ShodanClient::GetFilters()
{
	NoGETParamsMethod("/shodan/host/search/filters");
	return GetData();
}

std::string ShodanClient::GetTokens(nonstd::string_view query)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/host/search/tokens?key=%s&query=%s", api_url, api_key, query.data()).c_str());
	return GetData();
}

std::string ShodanClient::GetPorts()
{
	NoGETParamsMethod("/shodan/ports");
	return GetData();
}

std::string ShodanClient::GetProtocols()
{
	NoGETParamsMethod("/shodan/protocols");
	return GetData();
}

std::string ShodanClient::Scan(nonstd::string_view ips)
{
	NoGETParamsMethod("/shodan/scan");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ips.data());
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	return GetData();
}

std::string ShodanClient::ScanInternet(int port, nonstd::string_view ips)
{
	NoGETParamsMethod("/shodan/scan/internet");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, string_format("port=%i&ips=%s",port,ips.data()));
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	return GetData();
}

std::string ShodanClient::GetScanStatus(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/scan/%s?key=%s", api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::CreateAlert(nonstd::string_view name, nonstd::string_view filters_ip, int expires)
{
	NoGETParamsMethod("/shodan/alert");
	rapidjson::Document doc;
	doc.SetObject();
	auto &alloc = doc.GetAllocator();
	doc.AddMember("name",rapidjson::Value(name.data(),alloc), alloc);
	doc.AddMember("filters", rapidjson::Value("ip", alloc).SetObject().AddMember("ip", rapidjson::Value(filters_ip.data(), alloc), alloc), alloc);
	if (expires != 0)
	{
		doc.AddMember("expires", rapidjson::Value(std::to_string(expires).c_str(), alloc), alloc);
	}
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	rapidjson::StringBuffer sb;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
	doc.Accept(writer);
	std::cout << sb.GetString();
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, sb.GetString());
	return GetData();
}

std::string ShodanClient::GetAllAlertsInfo()
{
	NoGETParamsMethod("/shodan/alert/info");
	return GetData();
}

std::string ShodanClient::GetAlertInfo(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/info?key=%s", api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::DeleteAlert(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s?key=%s", api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::AddAlertNotifier(nonstd::string_view alert_id, nonstd::string_view notifier_id)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/notifier/%s?key=%s", api_url, api_key, alert_id.data(), notifier_id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::DeleteAlertNotifier(nonstd::string_view alert_id, nonstd::string_view notifier_id)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/notifier/%s?key=%s", api_url, api_key, alert_id.data(), notifier_id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetAlertTriggers()
{
	NoGETParamsMethod("/shodan/alert/triggers");
	return GetData();
}

std::string ShodanClient::EnableAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/trigger/%s?key=%s", api_url, alert_id.data(), name.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::DisableAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/trigger/%s?key=%s", api_url, alert_id.data(), name.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::StartIgnoreAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name, nonstd::string_view service)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/trigger/%s/ignore/%s?key=%s", api_url, alert_id.data(), name.data(), service.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::StopIgnoreAlertTrigger(nonstd::string_view alert_id, nonstd::string_view name, nonstd::string_view service)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s/trigger/%s/ignore/%s?key=%s", api_url, alert_id.data(), name.data(), service.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetSavedQueries(int page, nonstd::string_view sort, nonstd::string_view order)
{
	std::string tmp = "%s/shodan/query?key=%s";
	if (page != 0)
		tmp.append("&page=%i");
	if (sort.size() != 0)
		tmp.append("&sort=%s");
	if (order.size() != 0)
		tmp.append("&order=%s");
	curl_easy_setopt(curl, CURLOPT_URL, string_format(std::move(tmp), api_url, api_key,page,sort.data(),order.data()).c_str());
	return GetData();
}

std::string ShodanClient::GetDirectoryOfSavedQueires(nonstd::string_view query, int page)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/query/search?key=%s&query=%s", api_url, api_key, query.data(), page).append(page != 0 ? "&page=%i" : "").c_str());
	return GetData();
}

std::string ShodanClient::GetPopularTagsForSavedQueries(int size)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/query/tags?key=%s&size=%i", api_url, api_key, size).c_str());
	return GetData();
}

std::string ShodanClient::GetAvailableDatasets()
{
	NoGETParamsMethod("/shodan/data");
	return GetData();
}

std::string ShodanClient::GetListOfDatasetFiles(nonstd::string_view dataset_name)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/data/%s?key=%s", api_url, dataset_name.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetOrgInfo()
{
	NoGETParamsMethod("/org");
	return GetData();
}

std::string ShodanClient::AddOrgUser(nonstd::string_view user, bool notify)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/org/member/%s?key=%s", api_url, user.data(), api_key).c_str());
	if (notify == true)
	{
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "notify=1");
	}
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	return GetData();
}

std::string ShodanClient::DeleteOrgUser(nonstd::string_view user)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/org/member/%s?key=%s", api_url, user.data(), api_key).c_str());
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	return GetData();
}

std::string ShodanClient::GetProfileInfo()
{
	NoGETParamsMethod("/account/profile");
	return GetData();
}

std::string ShodanClient::GetDNSDomainInfo(nonstd::string_view domain)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/dns/domain/%s?key=%s", api_url, domain.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::ResolveDNS(nonstd::string_view hostnames)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/dns/resolve?hostnames=%s&key=%s", api_url, hostnames.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::ReverseDNS(nonstd::string_view ips)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/dns/reverse?ips=%s&key=%s", api_url, ips.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetHTTPHeaders()
{
	//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "coolheader");
	NoGETParamsMethod("/tools/httpheaders");
	return GetData();
}

std::string ShodanClient::GetMyIP()
{
	NoGETParamsMethod("/tools/myip");
	return GetData();
}

std::string ShodanClient::GetAPIInfo()
{
	NoGETParamsMethod("/api-info");
	return GetData();
}

std::string ShodanClient::GetHoneyScore(nonstd::string_view ip)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/labs/honeyscore/%s?key=%s", api_url,ip.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetAllBanners()
{
	//not using shorthand because of different api address
	//std::cout << string_format("%s/shodan/banners?key=%s", stream_api_url, api_key).c_str();
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/banners?key=%s", stream_api_url, api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetASNBanners(nonstd::string_view asn)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/asn/%s?key=%s", stream_api_url, asn.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetAllNotifiers()
{
	NoGETParamsMethod("/notifier");
	return GetData();
}

std::string ShodanClient::CreateNotifier(nonstd::string_view params)
{
	NoGETParamsMethod("/shodan/scan");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.data());
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	return GetData();
}

std::string ShodanClient::GetAllNotificationProviders()
{
	NoGETParamsMethod("/notifier/provider");
	return GetData();
}

std::string ShodanClient::DeleteNotifier(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/notifier/%s?key=%s", api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetNotifierInfo(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/notifier/%s", api_url, id.data()).c_str());
	return GetData();
}

std::string ShodanClient::EditNotifier(nonstd::string_view id, nonstd::string_view params)
{
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.data());
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/notifier/%s?key=%s", api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetCountriesBanners(nonstd::string_view countries)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/countries/%s?key=%s", stream_api_url, countries.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetPortsBanners(nonstd::string_view ports)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/ports/%s?key=%s", stream_api_url, ports.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::SubscribeToBannersInAllAlerts()
{
	NoGETParamsMethod("/shodan/alert");
	return GetData();
}

std::string ShodanClient::SubscribeToBannersInAlert(nonstd::string_view id)
{
	curl_easy_setopt(curl, CURLOPT_URL, string_format("%s/shodan/alert/%s?key=%s", stream_api_url, id.data(), api_key).c_str());
	return GetData();
}

std::string ShodanClient::GetExploits(nonstd::string_view query, nonstd::string_view facets, int page)
{
	std::string tmp = "%s/api/search?query=%s&key=%s";
	if (facets.size() != 0)
		tmp.append("&facets=%s");
	if (page != 0)
		tmp.append("&page=%i");
	curl_easy_setopt(curl, CURLOPT_URL, string_format(std::move(tmp), exploits_api_url, query.data(), api_key,facets.data(),page).c_str());
	return GetData();
}

std::string ShodanClient::GetExploitsCount(nonstd::string_view query, nonstd::string_view facets)
{
	std::string tmp = "%s/api/count?query=%s&key=%s";
	if (facets.size() != 0)
		tmp.append("&facets=%s");
	curl_easy_setopt(curl, CURLOPT_URL, string_format(std::move(tmp), exploits_api_url, query.data(), api_key, facets.data()).c_str());
	return GetData();
}

std::string ShodanClient::DeleteAllAlerts()
{
	std::string tmp;
	tmp.reserve(40);
	rapidjson::Document doc;
	doc.Parse(this->GetAllAlertsInfo().c_str());

	for (auto const& p : doc.GetArray())
	{
		tmp.append(p["id"].GetString()).append("\n");
		this->DeleteAlert(p["id"].GetString());
	}
	return tmp;
}
