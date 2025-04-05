# 5. 🧠 Cyber Threat Intelligence (CTI)

Cyber Threat Intelligence involves collecting, analyzing, and disseminating information about current and potential threats targeting an organization. For Blue Teams, CTI provides context about adversaries, their motivations, capabilities, infrastructure (Indicators of Compromise - IOCs), and tactics, techniques, and procedures (TTPs). This understanding helps prioritize defenses, improve detection capabilities, and speed up incident response.

## Index of Tools in this Section

* [abuse.ch Projects (URLhaus, MalwareBazaar, ThreatFox)](#abusech-projects-urlhaus-malwarebazaar-threatfox)
* [AbuseIPDB](#abuseipdb)
* [AlienVault OTX (Open Threat Exchange)](#alienvault-otx-open-threat-exchange)
* [Censys](#censys)
* [Hunchly](#hunchly)
* [Maltego](#maltego)
* [MISP (Malware Information Sharing Platform)](#misp-malware-information-sharing-platform)
* [OpenCTI](#opencti)
* [Recon-ng](#recon-ng)
* [SpiderFoot](#spiderfoot)
* [TheHive](#thehive)
* [YARA](#yara)

---

## abuse.ch Projects (URLhaus, MalwareBazaar, ThreatFox)

* **Description:** A suite of non-profit projects run by abuse.ch focused on tracking and sharing specific types of cyber threats. Key projects include:
    * **URLhaus:** Shares malicious URLs used for malware distribution.
    * **MalwareBazaar:** Shares malware samples (binaries).
    * **ThreatFox:** Shares Indicators of Compromise (IOCs) associated with malware.
* **Key Features/Why it's useful:**
    * Provides actionable, near real-time feeds of malicious URLs, malware samples, and IOCs.
    * Excellent source for enriching security alerts or proactively blocking known bad indicators.
    * Allows submission of samples/URLs, contributing to the community.
    * Free access to data via web portals and APIs.
* **Official Website/Repository:** [https://abuse.ch/](https://abuse.ch/) (Portal to projects like [https://urlhaus.abuse.ch/](https://urlhaus.abuse.ch/), [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/), [https://threatfox.abuse.ch/](https://threatfox.abuse.ch/))
* **Type:** Threat Intelligence Feeds / Repositories
* **Platform(s):** Web Portals, APIs
* **Installation:** N/A (Data access via web or API)
* **Basic Usage Example:** Browse the websites to search for specific indicators (hashes, URLs, IPs). Use APIs to integrate feeds into SIEMs, TIPs, or firewalls for automated blocking/alerting.
* **Alternatives:** Other specific threat feeds (e.g., PhishTank for phishing URLs), broader platforms (OTX, MISP).
* **Notes/Tips:** Valuable, free resource focused on specific threat types. Regularly check their different projects based on your needs.

---

## AbuseIPDB

* **Description:** A community-driven project and IP address reputation database. It aggregates reports from webmasters, sysadmins, and security professionals about malicious IP addresses involved in spamming, hacking attempts, DDoS attacks, and other abusive activity.
* **Key Features/Why it's useful:**
    * Quickly checking the reputation of an IP address encountered in logs or alerts.
    * Understanding the types of malicious activity associated with an IP.
    * Providing context to help determine if traffic from an IP should be blocked or investigated further.
    * API allows for automated IP reputation lookups.
* **Official Website/Repository:** [https://www.abuseipdb.com/](https://www.abuseipdb.com/)
* **Type:** IP Address Reputation Database / Threat Intelligence Feed
* **Platform(s):** Web Portal, API
* **Installation:** N/A
* **Basic Usage Example:** Visit the website and search for an IP address. Review the confidence score, reported categories, and comments. Use the API (requires free registration/key) for automated lookups (e.g., `curl 'https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4' -H 'Key: YOUR_API_KEY' -H 'Accept: application/json'`).
* **Alternatives:** Talos Intelligence Reputation Center, commercial IP reputation services, VirusTotal IP lookup.
* **Notes/Tips:** Community reports mean accuracy can vary, but high confidence scores or recent reports are strong indicators. Useful for quickly vetting suspicious IPs.

---

## AlienVault OTX (Open Threat Exchange)

* **Description:** A large, open threat intelligence community platform enabling collaborative defense. Users and organizations share threat data ("Pulses," which are collections of IOCs related to specific threats, campaigns, or malware), discuss threats, and subscribe to feeds.
* **Key Features/Why it's useful:**
    * Access to a vast repository of IOCs (IPs, domains, hashes, URLs, etc.) submitted by the community and AlienVault Labs.
    * Ability to search for specific indicators or threats.
    * Subscribing to "Pulses" relevant to your industry or observed threats.
    * API for integrating IOC feeds into security tools (SIEM, firewalls, TIPs).
    * Community discussion and context around threats.
* **Official Website/Repository:** [https://otx.alienvault.com/](https://otx.alienvault.com/)
* **Type:** Threat Intelligence Platform / Community Feed
* **Platform(s):** Web Portal, API
* **Installation:** N/A
* **Basic Usage Example:** Create a free account. Search for indicators (e.g., a suspicious IP or file hash). Explore Pulses related to specific malware families or threat actors. Configure API access to pull feeds relevant to your organization.
* **Alternatives:** MISP (more focused on structured sharing), commercial TIPs, specific feeds (abuse.ch).
* **Notes/Tips:** Quality of community pulses can vary. Prioritize pulses from trusted sources or AlienVault Labs. Use the API to automate IOC ingestion.

---

## Censys

* **Description:** An internet-wide scanning platform (similar to Shodan) that continuously scans IPv4 addresses, websites, and certificates, making the data searchable. Blue Teams use Censys to understand their own external attack surface, find exposed services or devices, monitor certificate transparency logs, and research attacker infrastructure.
* **Key Features/Why it's useful:**
    * Discovering services, devices, and websites associated with your organization's IP ranges or domains.
    * Identifying open ports, running software versions, and potential misconfigurations on external assets.
    * Monitoring SSL/TLS certificate issuance for your domains (via Certificate Transparency logs).
    * Researching infrastructure potentially linked to threat actors.
* **Official Website/Repository:** [https://search.censys.io/](https://search.censys.io/) (Search), [https://censys.io/](https://censys.io/) (Company)
* **Type:** Internet Scan Data Search Engine / Attack Surface Management Tool (Freemium)
* **Platform(s):** Web Portal, API
* **Installation:** N/A
* **Basic Usage Example:** Use the web search portal with specific queries (e.g., `services.http.response.html_title:"My Org Login"`, `ip:YOUR_IP_RANGE`, `services.tls.certificates.leaf_data.subject.common_name:yourdomain.com`). Use API for automated monitoring.
* **Alternatives:** Shodan, Zoomeye, BinaryEdge.
* **Notes/Tips:** Free account provides basic search capabilities. Paid plans offer more queries, historical data, and attack surface management features. Powerful for mapping your external footprint.

---

## Hunchly

* **Description:** A commercial browser extension (primarily for Chrome) designed for online investigations and OSINT gathering. It automatically captures, timestamps, and hashes web pages visited during an investigation, creating an audit trail. Essential for analysts needing to document their online research process for CTI or incident response.
* **Key Features/Why it's useful:**
    * Automatically creates a timestamped, forensically sound capture of every webpage visited during an investigation.
    * Stores pages locally for offline access and preservation of evidence.
    * Allows tagging, note-taking, and selector tracking (highlighting specific data points).
    * Generates investigation reports.
    * Prevents accidental loss of evidence due to pages being taken down or changed.
* **Official Website/Repository:** [https://www.hunch.ly/](https://www.hunch.ly/)
* **Type:** Browser Extension / OSINT Evidence Capture Tool (Commercial)
* **Platform(s):** Chrome Extension (works on Windows, macOS, Linux where Chrome runs).
* **Installation:** Install extension from Chrome Web Store, purchase license.
* **Basic Usage Example:** Start a new investigation case in Hunchly. Browse the web as normal; Hunchly automatically captures pages related to the case. Use tagging and notes to organize findings. Export report when finished.
* **Alternatives:** Manual screenshotting + note-taking (less efficient/reliable), web scrapers (different purpose), Wallabag (self-hosted read-it-later).
* **Notes/Tips:** Indispensable for serious online investigators needing to document their process rigorously. Requires purchasing a license.

---

## Maltego

* **Description:** A powerful graphical link analysis tool used for gathering and connecting open-source intelligence (OSINT) and threat intelligence. It visualizes relationships between pieces of information (like domains, IPs, emails, names, malware hashes) using "Transforms" that query various public and commercial data sources.
* **Key Features/Why it's useful:**
    * Visualizing complex relationships between different IOCs and intelligence data points.
    * Automating data gathering from diverse sources via Transforms (e.g., WHOIS, DNS records, Shodan, VirusTotal, Passive DNS).
    * Identifying hidden connections and infrastructure patterns.
    * Exploring threat actor infrastructure or mapping an organization's external footprint graphically.
* **Official Website/Repository:** [https://www.maltego.com/](https://www.maltego.com/)
* **Type:** Graphical Link Analysis / Intelligence Visualization Platform (Commercial, with free Community Edition)
* **Platform(s):** Windows, macOS, Linux (Java-based).
* **Installation:** Download installer from website. Requires registration. Community Edition is free but has limitations (e.g., number of results per Transform).
* **Basic Usage Example:** Start a new graph. Drag entities (e.g., Domain, IP Address) onto the graph. Run Transforms on entities to query data sources and discover related entities (e.g., run DNS transforms on a domain to find IPs, run reverse DNS on IPs to find other domains). Analyze the resulting graph for connections.
* **Alternatives:** OpenCTI (Data storage/linking, less visualization focus), SpiderFoot (Automation focus), custom scripting + visualization libraries (more effort).
* **Notes/Tips:** The power of Maltego lies in the Transforms available (both built-in and installable from the Transform Hub). Community Edition is useful for learning but professional use often requires paid versions for access to more data sources and fewer limitations.

---

## MISP (Malware Information Sharing Platform)

* **Description:** An open-source Threat Intelligence Platform (TIP) specifically designed for **sharing** threat information (IOCs, TTPs, threat actor info, vulnerabilities) within a trusted community or organization. It provides standardized formats (MISP objects, galaxies) for representing threat data.
* **Key Features/Why it's useful:**
    * **Structured Sharing:** Enables sharing of CTI in a standardized, machine-readable format.
    * **Collaboration:** Facilitates collaboration between different security teams or organizations.
    * **IOC Management:** Stores and correlates IOCs (IPs, domains, hashes, URLs, etc.).
    * **Feeds & Synchronization:** Can import external feeds and synchronize instances with other MISP communities.
    * **Integration:** Integrates with other security tools (SIEMs, IDS, analysis tools).
    * **Galaxies:** Provides rich context around threats using cluster relationships (e.g., linking malware to threat actors, tools, TTPs).
* **Official Website/Repository:** [https://www.misp-project.org/](https://www.misp-project.org/), [https://github.com/MISP/MISP](https://github.com/MISP/MISP)
* **Type:** Threat Intelligence Platform (TIP) / Sharing Platform (Web UI)
* **Platform(s):** Linux (Server application, typically Ubuntu/Debian). Often deployed as a VM or Docker container.
* **Installation:** Follow detailed official installation guide. Requires LAMP stack components (or similar) and dependencies.
* **Basic Usage Example:** Accessed via web interface. Involves creating "Events" which contain "Attributes" (IOCs) and contextual information (Galaxies). Explore existing events, add indicators found during investigations, configure feeds from external sources or other MISP instances.
* **Alternatives:** OpenCTI (broader CTI platform), TheHive (IR focus, integrates with MISP), commercial TIPs (Anomali, ThreatQuotient), AlienVault OTX (more community feed focused).
* **Notes/Tips:** Primarily designed for *sharing* intelligence. Setting up feeds and synchronization correctly is key. Understanding the MISP data model (Events, Attributes, Objects, Galaxies) is important for effective use.

---

## OpenCTI

* **Description:** An open-source platform designed to help organizations structure, store, visualize, and share cyber threat intelligence knowledge. It allows linking diverse pieces of information like threat actors, intrusion sets, malware, vulnerabilities, IOCs, TTPs, and reports using the STIX 2 standard.
* **Key Features/Why it's useful:**
    * **Structured Knowledge Base:** Organizes CTI data using the standardized STIX 2 format.
    * **Data Correlation & Linking:** Automatically links related entities (e.g., malware used by a specific actor in a campaign).
    * **Visualization:** Provides various ways to visualize relationships and timelines.
    * **Import/Export:** Connectors allow importing data from MISP, threat feeds, reports, and exporting data.
    * **Analysis Tools:** Includes features for pattern detection and relationship exploration.
* **Official Website/Repository:** [https://www.opencti.io/en/](https://www.opencti.io/en/), [https://github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti)
* **Type:** Threat Intelligence Platform (TIP) / Knowledge Management Platform (Web UI)
* **Platform(s):** Docker deployment recommended (includes backend, workers, frontend). Runs on Linux hosts primarily.
* **Installation:** Follow official Docker deployment guide. Requires Docker and Docker Compose.
* **Basic Usage Example:** Accessed via web interface. Import data via connectors (e.g., MISP feed). Manually create entities (Threat Actors, Malware, Reports, Indicators). Explore relationships between entities using graph views or dashboards. Use filters and search to find relevant intelligence.
* **Alternatives:** MISP (more sharing focused), TheHive (IR focus), Maltego (visualization focus), commercial TIPs.
* **Notes/Tips:** Provides a powerful way to structure and analyze CTI knowledge centrally. Steeper learning curve than simple feed aggregators. Integration with other tools (MISP, TheHive) is a key benefit.

---

## Recon-ng

* **Description:** A modular web reconnaissance framework written in Python, inspired by Metasploit. It provides an interactive command-line interface where users load modules to perform specific OSINT tasks, such as discovering hosts, collecting email addresses, querying APIs (Shodan, VirusTotal, etc.), and managing gathered data.
* **Key Features/Why it's useful:**
    * **Modular Design:** Easily extensible with numerous modules for different data sources and tasks.
    * **Interactive Console:** Metasploit-like interface familiar to many security professionals.
    * **API Integration:** Many modules interact with third-party APIs (requires managing API keys).
    * **Data Management:** Built-in database to store and manage collected reconnaissance data.
    * **Automation Potential:** Can be used for automating repetitive OSINT gathering steps.
* **Official Website/Repository:** [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng)
* **Type:** CLI OSINT Framework
* **Platform(s):** Linux, macOS, Windows (Python-based).
* **Installation:**
    ```bash
    git clone [https://github.com/lanmaster53/recon-ng.git](https://github.com/lanmaster53/recon-ng.git)
    cd recon-ng
    pip install -r REQUIREMENTS
    ./recon-ng 
    ```
* **Basic Usage Example:**
    ```bash
    # Launch recon-ng
    ./recon-ng

    # Create/load a workspace
    workspaces create my_target_org
    # or workspaces load my_target_org

    # Add a domain to scope
    db insert domains my_target_org.com

    # Search for available modules
    modules search hackertarget

    # Load a module
    modules load recon/domains-hosts/hackertarget

    # Run the module (uses domain(s) in scope)
    run

    # Show collected hosts
    show hosts 
    ```
* **Alternatives:** SpiderFoot (Web UI, broader automation), Maltego (GUI, visualization), custom OSINT scripts.
* **Notes/Tips:** Requires managing API keys for many powerful modules (`keys add ...`). Explore available modules (`modules search ...`) to understand capabilities. Good for structured, repeatable OSINT workflows.

---

## SpiderFoot

* **Description:** An open-source OSINT automation tool with both a command-line interface and an embedded web server providing a GUI. It integrates with a vast number of data sources (over 200 modules) to automatically gather intelligence on targets like IP addresses, domains, hostnames, emails, names, etc., and visualize the relationships.
* **Key Features/Why it's useful:**
    * **Automation:** Automates the process of querying numerous OSINT sources.
    * **Broad Data Collection:** Modules cover DNS, WHOIS, web scraping, threat intelligence feeds, social media, code repositories, dark web (requires Tor setup), and more.
    * **Visualization:** Web UI provides graphical representation of discovered relationships.
    * **Correlation:** Attempts to correlate different pieces of information found.
    * **Extensibility:** Users can write their own modules.
* **Official Website/Repository:** [https://www.spiderfoot.net/](https://www.spiderfoot.net/), [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
* **Type:** OSINT Automation Platform (Web UI & CLI)
* **Platform(s):** Linux, Windows, macOS (Python-based). Docker image available.
* **Installation:**
    ```bash
    # Using pip
    pip install spiderfoot
    # Or clone repo and install requirements
    git clone [https://github.com/smicallef/spiderfoot.git](https://github.com/smicallef/spiderfoot.git)
    cd spiderfoot
    pip install -r requirements.txt
    ```
* **Basic Usage Example:**
    * **Web UI:**
        ```bash
        # Start web server
        python ./sf.py -l 127.0.0.1:5001 
        ```
        (Access `http://127.0.0.1:5001` in browser. Configure API keys in Settings. Start a New Scan, define target, select modules.)
    * **CLI:**
        ```bash
        # Run a scan on a domain using all modules, output to stdout
        python ./sf.py -s yourdomain.com -u ALL 
        ```
* **Alternatives:** Recon-ng (CLI, modular framework), Maltego (GUI, visualization focus), custom scripts.
* **Notes/Tips:** Configure API keys for relevant modules in the web UI settings for best results. Scans can take a long time and generate a lot of data depending on selected modules. Useful for both broad initial recon and deep dives.

---

## TheHive

* **Description:** An open-source, scalable Security Incident Response Platform (SIRP) designed to help security analysts collaborate on investigations. It allows creating cases, adding observables (IOCs), tracking tasks, writing investigation timelines, and integrating with other tools like MISP and Cortex (analysis engine).
* **Key Features/Why it's useful:**
    * **Case Management:** Centralized platform for managing security incidents.
    * **Collaboration:** Allows multiple analysts to work on the same case simultaneously.
    * **Observable Management:** Tracks IOCs (IPs, domains, hashes, etc.) related to a case.
    * **Task Tracking:** Assign and monitor tasks required for incident investigation and response.
    * **Integration:** Connects with MISP (for CTI sharing), Cortex (for running analyzers on observables), and other tools.
    * **Real-time Updates:** Live stream of case updates and notifications.
* **Official Website/Repository:** [https://thehive-project.org/](https://thehive-project.org/), [https://github.com/TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive)
* **Type:** Security Incident Response Platform (SIRP) (Web UI)
* **Platform(s):** Linux server (distributed as packages, Docker). Web UI accessed via browser.
* **Installation:** Follow official installation guide. Typically involves installing backend + Elasticsearch + Cortex (optional) + MISP connector (optional). Docker deployment is common.
* **Basic Usage Example:** Accessed via web interface. Create a new case for an alert/incident. Add observables (IPs, hashes, domains). Add tasks for investigation (e.g., "Analyze malware sample," "Block IP on firewall"). Write log entries documenting findings. Use analyzers via Cortex (if configured) to enrich observables (e.g., VirusTotal lookup for a hash). Close case when resolved.
* **Alternatives:** Commercial SIRP/SOAR platforms (Splunk SOAR, Palo Alto XSOAR), Request Tracker (RT) for Incident Response (RTIR - Open Source ticketing system adapted for IR).
* **Notes/Tips:** TheHive shines when integrated with Cortex (for automated analysis) and MISP (for CTI enrichment/sharing). It structures the IR process and facilitates teamwork.

---

## YARA

* **Description:** Often called "the pattern matching swiss knife for malware researchers (and everyone else)." YARA provides a rule-based language to create descriptions (rules) that identify malware or other files based on textual or binary patterns. Blue Teams use YARA rules to scan files at rest, memory dumps, or network traffic to detect known malicious patterns.
* **Key Features/Why it's useful:**
    * **Flexible Pattern Matching:** Define rules based on strings (text, hex, regex), binary patterns, and conditions.
    * **Malware Identification & Classification:** Create/use rules to detect specific malware families or characteristics.
    * **IOC Searching:** Scan large datasets (files, memory) for indicators defined in YARA rules.
    * **Extensibility:** Can be integrated into other tools (IDS, sandboxes, forensic tools).
* **Official Website/Repository:** [https://virustotal.github.io/yara/](https://virustotal.github.io/yara/), [https://github.com/VirusTotal/yara](https://github.com/VirusTotal/yara)
* **Type:** Pattern Matching Engine / Rule Language (CLI Tool & Library)
* **Platform(s):** Linux, Windows, macOS.
* **Installation:** Via package managers, pip, or compiling from source.
    ```bash
    # Using pip (Python library + CLI tool)
    pip install yara-python
    # Or download pre-compiled binaries
    ```
* **Basic Usage Example:**
    ```bash
    # Create a simple YARA rule file (e.g., myrule.yar):
    /*
    rule HelloWorld {
      strings:
        $text = "Hello World" nocase wide ascii
      condition:
        $text
    }
    */

    # Scan a file or directory with the rule
    yara myrule.yar /path/to/scan/
    ```
* **Alternatives:** ClamAV (AV engine, uses its own signature format), commercial AV/EDR rulesets.
* **Notes/Tips:** Writing effective YARA rules requires understanding file formats and malware patterns. Many public repositories exist for sharing YARA rules (e.g., Awesome YARA). Essential skill for malware analysis and threat hunting.

---