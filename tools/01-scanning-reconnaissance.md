# 1. 🕵️ Scanning & Reconnaissance Tools

This section covers tools and techniques essential for the initial phases of security assessments. They are used to gather information about targets, discover assets, map the attack surface, and identify potential weaknesses.

---

## WHOIS Lookup

* **Description:** A query and response protocol widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system. It provides information like domain ownership, registration dates, expiration dates, name servers, and contact information (often redacted for privacy).
* **Key Features/Why it's useful:**
    * Identifying the owner of a domain name.
    * Finding administrative and technical contact information (useful for social engineering or reporting issues).
    * Determining the registrar and name servers associated with a domain.
    * Checking domain registration and expiration dates (can indicate potential takeover opportunities if expired).
* **Official Website/Repository:** N/A (Protocol). Web-based lookups available (e.g., [ICANN Lookup](https://lookup.icann.org/), many registrar sites). Built-in CLI command on Linux/macOS/Windows.
* **Type:** Protocol, CLI Utility, Web Service
* **Platform(s):** Linux, macOS, Windows (usually built-in or easily installable)
* **Installation:**
    ```bash
    # Often pre-installed. If not:
    # Debian/Ubuntu
    sudo apt update && sudo apt install whois
    # Fedora
    sudo dnf install whois
    # Windows: May need to enable via Features or use WSL/Cygwin.
    ```
* **Basic Usage Example:**
    ```bash
    # Query domain information
    whois example.com

    # Query IP address information
    whois 8.8.8.8 
    ```
* **Alternatives:** DomainTools (Commercial), various online lookup services.
* **Notes/Tips:** Much contact information is now protected by GDPR or privacy services, limiting OSINT value compared to the past, but technical details like nameservers remain useful.

---

## BuiltWith

* **Description:** An online service that profiles websites to determine the technologies they are built with. It identifies web servers, content management systems (CMS), frameworks, advertising networks, analytics tools, JavaScript libraries, widgets, and much more.
* **Key Features/Why it's useful:**
    * Quickly understanding the technology stack of a target website.
    * Identifying potentially vulnerable or outdated software components.
    * Gaining insights into the target's infrastructure and third-party dependencies.
    * Useful for competitive analysis and market research beyond cybersecurity.
* **Official Website/Repository:** [https://builtwith.com/](https://builtwith.com/)
* **Type:** Web Service
* **Platform(s):** Web (Browser access)
* **Installation:** N/A
* **Basic Usage Example:** Visit the website and enter the target domain name.
* **Alternatives:** Wappalyzer, WhatWeb (CLI), Netcraft.
* **Notes/Tips:** Free usage provides significant information; paid plans offer more details, history, and lead generation features. Browser extensions are also available.

---

## Wayback Machine (Internet Archive)

* **Description:** A massive digital archive of the World Wide Web, allowing users to view archived versions of websites throughout history. It periodically crawls and saves snapshots of publicly accessible web pages.
* **Key Features/Why it's useful:**
    * Finding historical versions of websites, potentially revealing removed information, old contacts, or previous site structures.
    * Identifying technologies used in the past.
    * Discovering old subdomains or directories from archived `robots.txt` files or site maps.
    * Valuable OSINT resource for understanding a target's evolution.
* **Official Website/Repository:** [https://archive.org/web/](https://archive.org/web/)
* **Type:** Web Service, Digital Archive
* **Platform(s):** Web (Browser access)
* **Installation:** N/A
* **Basic Usage Example:** Visit the website and enter the URL you want to explore through time.
* **Alternatives:** Google Cache (limited scope), personal web scraping/archiving (complex).
* **Notes/Tips:** Not all websites are archived, and the frequency of snapshots varies greatly. Javascript-heavy sites may not render correctly in older archives.

---

## Shodan

* **Description:** A unique search engine that lets users find specific types of devices (computers, servers, routers, webcams, IoT devices, industrial control systems - ICS) connected to the internet using a variety of filters. Instead of web content, Shodan crawls the internet looking for service banners.
* **Key Features/Why it's useful:**
    * Discovering internet-facing devices belonging to a target organization beyond standard web servers.
    * Identifying exposed services, default credentials, and potentially vulnerable systems (e.g., open databases, unprotected RDP, vulnerable IoT devices).
    * Monitoring an organization's external attack surface.
    * Finding specific technologies or vulnerabilities across the internet.
* **Official Website/Repository:** [https://www.shodan.io/](https://www.shodan.io/)
* **Type:** Web Service, Search Engine (with API and CLI tool)
* **Platform(s):** Web, CLI (Python tool)
* **Installation (CLI):**
    ```bash
    # Requires Python and pip
    pip install -U --user shodan
    # Initialize with your API key (get from Shodan account)
    shodan init YOUR_API_KEY 
    ```
* **Basic Usage Example (CLI):**
    ```bash
    # Get info about an IP address
    shodan host <ip_address>

    # Search for devices (e.g., MongoDB servers in a specific netblock)
    shodan search --fields ip_str,port,org 'mongodb net:192.168.0.0/16' 

    # Count results for a query
    shodan count apache country:ES
    ```
* **Alternatives:** Censys, Zoomeye, BinaryEdge (similar device search engines).
* **Notes/Tips:** Free accounts have limitations on search results and filters. A paid subscription or academic access unlocks full potential. The CLI tool is very powerful for automation. Use responsibly and ethically.

---