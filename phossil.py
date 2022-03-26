from bs4 import BeautifulSoup
import requests
import requests_random_user_agent
from pprint import pprint


def build_internal_url_representation(original):
    acceptable_protocols = ["http://", "https://"]
    for protocol in acceptable_protocols:
        if original.startswith(protocol):
            fqdn_and_url = original[len(protocol) :]
            first_slash = fqdn_and_url.find("/")

            if first_slash == -1:
                fqdn = fqdn_and_url
                url = "/"
            else:
                fqdn = fqdn_and_url[:first_slash]
                url = fqdn_and_url[first_slash:]

            phish_data = {
                "protocol": protocol,
                "fqdn": fqdn,
                "url": url,
                "original": original,
            }
            return phish_data
    return False


def source_urls_phishtank():
    phishtank_data = "https://data.phishtank.com/data/online-valid.json"
    try:
        request = requests.get(phishtank_data)
        if request.status_code != 200:
            print(f"PhishTank returned non-200 HTTP code: {request.status_code}")
            return False

        response = request.json()
        if len(response) < 10:
            print(f"PhishTank returned too little data?")

        urls = []
        for phish in response:
            if phish["verified"] == "yes":
                url = build_internal_url_representation(phish["url"])
                if url:
                    urls.append(url)

        return urls
    except Exception as e:
        print(f"PhishTank download failed: {e}")


def expand_initial_url_set(url):
    if url["url"] == "/":
        return [url]

    new_urls = []
    components_to_origin = url["url"].strip("/").split("/")
    components_to_origin.insert(0, "")
    for component_ctr in range(0, len(components_to_origin) + 1):
        new_url = url.copy()
        this_url_components = []
        for this_url_component_ctr in range(0, component_ctr):
            this_url_components.append(components_to_origin[this_url_component_ctr])
        this_url_components.append("")
        new_url["url"] = "/".join(this_url_components)

        if new_url["url"] == "":
            continue
        if component_ctr >= len(components_to_origin) and len(new_url["url"]) > 1:
            new_url["url"] = new_url["url"].rstrip("/")
        new_urls.append(new_url)

    return new_urls


def find_zip_if_index(url):
    reconstructed_url = url["protocol"] + url["fqdn"] + url["url"]
    print(reconstructed_url)

    try:
        request = requests.get(reconstructed_url)
    except Exception:
        return False

    if request.status_code == 200:
        response = request.text
        # print(response)
        testing_lookups = [
            "Index of",
            "index of",
            "Index of /",
            "index of /",
            "Last modified",
            "last modified",
            "Parent Directory",
            "Parent directory",
            "parent directory",
        ]
        # for lookup in testing_lookups:
            # if lookup in response:
                # print("- SAW: " + lookup)
        soup = BeautifulSoup(response, "lxml")

        links = []
        for link in soup.findAll("a"):
            links.append(link.get("href"))
            
        archive_formats = [".zip", ".7z", ".gz", ".tar", ".rar"]
        for link in links:
            if link:
                for filetype in archive_formats:
                    if link.endswith(filetype):
                        print(f"GOT: {link} ({reconstructed_url})")


urls = source_urls_phishtank()
for url in urls:
    for check in expand_initial_url_set(url):
        find_zip_if_index(check)
