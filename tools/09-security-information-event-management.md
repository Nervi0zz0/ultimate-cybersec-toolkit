# 9. 📊 SIEM & Log Management

Security Information and Event Management (SIEM) systems are a cornerstone of modern Blue Team operations and Security Operations Centers (SOCs). They provide centralized log collection from diverse sources (endpoints, servers, network devices, applications, cloud services), normalization of data, real-time correlation analysis to detect threats based on rules or behavioral anomalies, alerting, dashboarding for visibility, and long-term log retention for compliance and forensic investigation.

## Index of Tools, Concepts & Platforms in this Section

* [Elastic Stack / Elastic Security](#elastic-stack--elastic-security)
* [Graylog](#graylog)
* [Security Onion](#security-onion)
* [SIEM Core Concepts](#siem-core-concepts)
* [Sigma Rules](#sigma-rules)
* [Splunk Free](#splunk-free)
* [Wazuh](#wazuh-siem-focus)
---

## Elastic Stack / Elastic Security

* **Description:** The Elastic Stack (formerly ELK Stack) is a popular set of open-source tools primarily used for search, analytics, and data visualization. It consists of **E**lasticsearch (search/analytics engine), **L**ogstash (server-side data processing pipeline), **K**ibana (visualization/dashboards), and **B**eats (lightweight data shippers). **Elastic Security** is the integrated SIEM and Endpoint Security solution built on top of the Elastic Stack, providing threat detection rules, machine learning anomalies, case management, and endpoint agent capabilities.
* **Key Features/Why it's useful:**
    * **Scalable Log Aggregation & Search:** Elasticsearch provides powerful, fast searching across vast amounts of log data.
    * **Flexible Data Ingestion:** Logstash and Beats offer numerous ways to collect and parse logs from various sources.
    * **Rich Visualization:** Kibana allows creating custom dashboards for monitoring and threat hunting.
    * **Integrated SIEM/Security:** Elastic Security adds pre-built detection rules (including Sigma rule support), ML-based anomaly detection, security dashboards, and investigation workflows.
* **Official Website/Repository:** [https://www.elastic.co/](https://www.elastic.co/) (Elastic Stack & Security), [https://github.com/elastic](https://github.com/elastic)
* **Type:** Log Management & Analytics Platform, SIEM (Elastic Security) (Open Source Core with Commercial Features/Licenses - Elastic License/SSPL)
* **Platform(s):** Server components primarily Linux. Beats agents available for Linux, Windows, macOS. Can be self-hosted or used via Elastic Cloud.
* **Installation:** Can be complex. Options include individual component installation, Docker containers, Kubernetes operators, or cloud service. Follow official guides.
* **Basic Usage Example:** Deploy Beats agents to forward logs (e.g., Filebeat for logs, Winlogbeat for Windows events) to Logstash or directly to Elasticsearch. Configure Logstash pipelines for parsing/enrichment (optional). Use Kibana to explore data (Discover tab), build visualizations/dashboards, and use Elastic Security app for alert triage, detection rule management, and threat hunting.
* **Alternatives:** Splunk, Graylog, Wazuh (as an all-in-one), Microsoft Sentinel (Cloud-native SIEM).
* **Notes/Tips:** The core stack is open source but advanced security features might require a paid license. Resource intensive (especially Elasticsearch). Strong community support.

---

## Graylog

* **Description:** An open-source log management platform focused on collecting, indexing, and analyzing log data from various sources. It provides powerful search capabilities, alerting, dashboards, and processing pipelines. Often considered a strong open-source alternative to Splunk or the Elastic Stack for log aggregation and basic SIEM use cases.
* **Key Features/Why it's useful:**
    * Centralized log aggregation and storage.
    * Fast search and analysis of log data.
    * Customizable dashboards and visualization.
    * Alerting based on search queries or thresholds.
    * Data processing rules (pipelines) for parsing, normalization, and enrichment.
    * Marketplace for content packs (inputs, dashboards, rules).
* **Official Website/Repository:** [https://www.graylog.org/](https://www.graylog.org/), [https://github.com/Graylog2/graylog2-server](https://github.com/Graylog2/graylog2-server)
* **Type:** Log Management Platform / Basic SIEM (Open Source & Commercial Enterprise version)
* **Platform(s):** Server runs on Linux. Web UI accessed via browser.
* **Installation:** Packages (DEB/RPM), Docker, OVA appliance. Requires MongoDB and Elasticsearch/OpenSearch as dependencies. Follow official guides.
* **Basic Usage Example:** Configure inputs (e.g., Syslog, Beats, GELF) to receive logs. Use the web interface to search logs (using Graylog Query Language), create dashboards, set up alert conditions, and manage data streams/pipelines.
* **Alternatives:** Elastic Stack, Splunk, Wazuh, Loki (by Grafana, log aggregation focus).
* **Notes/Tips:** Open source version is powerful for log management. Enterprise version adds more SIEM-focused features and support. Can be less resource-intensive than Elastic Stack for similar log volumes in some cases.

---

## Security Onion

* **Description:** A free and open-source Linux distribution specifically designed for Network Security Monitoring (NSM), Intrusion Detection (IDS), Enterprise Security Monitoring (ESM), and Log Management. It bundles and pre-configures a suite of best-of-breed open source security tools into a cohesive platform.
* **Key Features/Why it's useful:**
    * **Integrated Platform:** Provides a turnkey solution bundling tools like Suricata, Zeek, Wazuh, Elastic Stack (or its own SO specific components), Stenographer (full packet capture), etc.
    * **Simplified Deployment:** Greatly simplifies the setup and integration of multiple complex security monitoring tools.
    * **Multiple Use Cases:** Can function as a standalone SIEM/NSM/IDS or as distributed sensors feeding a central server.
    * **Built-in Dashboards:** Includes pre-configured dashboards (Kibana/Grafana) for visualizing alerts and logs.
    * **Analysis Tools:** Includes tools like Wireshark, NetworkMiner directly within the distribution.
* **Official Website/Repository:** [https://securityonionsolutions.com/](https://securityonionsolutions.com/), [https://github.com/Security-Onion-Solutions/securityonion](https://github.com/Security-Onion-Solutions/securityonion)
* **Type:** Security Monitoring Linux Distribution / Integrated Platform
* **Platform(s):** Linux (Installs as an OS via ISO).
* **Installation:** Download ISO image, install on dedicated hardware or VM following the official guide. Requires careful consideration of deployment type (Standalone, Manager, Sensor, etc.).
* **Basic Usage Example:** After installation and setup (`so-setup`), access the Security Onion Console (SOC) web interface. Use included tools like Dashboards (Kibana/Grafana), Alerts, Hunt (pcap analysis), Cases to monitor network traffic, investigate alerts from Suricata/Zeek/Wazuh, and analyze logs.
* **Alternatives:** Building a similar stack manually (Elastic + Suricata + Zeek + Wazuh), commercial SIEM/NDR platforms.
* **Notes/Tips:** Excellent platform for learning NSM/SIEM concepts or deploying a robust open-source monitoring solution without complex manual integration. Requires dedicated hardware/VM resources. Strong community support.

---

## SIEM Core Concepts

* **Description:** Understanding the fundamental concepts behind SIEM systems is crucial for effective use, regardless of the specific tool chosen. Key concepts include:
    * **Log Collection:** Gathering logs from diverse sources (endpoints, network devices, firewalls, servers, applications, cloud services, threat feeds). Often uses agents (Beats, Wazuh Agent, Splunk UF) or standard protocols (Syslog, SNMP Traps, API calls).
    * **Parsing & Normalization:** Converting logs from various formats into a common, structured format (e.g., ECS - Elastic Common Schema) so they can be correlated. Extracts key fields (IP addresses, usernames, timestamps, action).
    * **Correlation:** Applying rules (e.g., Sigma rules) or statistical/ML models to analyze normalized events from multiple sources to detect patterns indicative of threats or policy violations (e.g., multiple failed logins followed by success from a new location).
    * **Alerting:** Notifying analysts when correlation rules or detection logic trigger on potentially malicious activity.
    * **Dashboarding & Reporting:** Providing visual summaries of security posture, active alerts, key metrics, and compliance status.
    * **Log Retention:** Storing logs securely for a defined period to meet compliance requirements and allow for historical investigation/forensics.
    * **Threat Hunting:** Proactively searching through log data for signs of compromise that may not have triggered automated alerts.
* **Type:** Concepts
* **Notes/Tips:** Effective SIEM implementation requires careful planning regarding log sources, normalization, rule tuning (to minimize false positives), and defining clear processes for alert triage and incident response.

---

## Sigma Rules

* **Description:** Sigma is an open-source, generic signature format for SIEM systems. It aims to create a standardized way to write detection rules that can then be converted to work across various SIEM platforms (Splunk, Elastic Security, QRadar, Microsoft Sentinel, Wazuh, etc.).
* **Key Features/Why it's useful:**
    * **Vendor Agnostic:** Write detection logic once in Sigma format, then convert it for your specific SIEM using converters (like `sigmac`).
    * **Community Sharing:** Enables easy sharing of detection rules between different organizations and researchers, regardless of the SIEM tool used.
    * **Structured Format:** YAML-based rules are human-readable and define log source, detection logic (keywords, fields, conditions), severity, TTP mapping (MITRE ATT&CK), etc.
* **Official Website/Repository:** [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (Rule repository), [https://github.com/SigmaHQ/sigmac](https://github.com/SigmaHQ/sigmac) (Converter)
* **Type:** SIEM Rule Format / Standard
* **Platform(s):** N/A (Format definition). Rules used within SIEMs. Converter (`sigmac`) is Python-based.
* **Installation:** Rules are downloaded/cloned from GitHub. `sigmac` installed via pip.
* **Basic Usage Example:**
    ```yaml
    # Example Sigma Rule Snippet (powershell_suspicious_download.yml)
    title: Suspicious PowerShell Download Activity
    status: stable
    description: Detects PowerShell downloading files using specific methods often used for malware staging.
    logsource:
        product: windows
        service: powershell # Or sysmon Event ID 1 for process creation
    detection:
        selection:
            # Example for Sysmon Event ID 1
            EventID: 1
            CommandLine|contains|all:
                - 'powershell'
                - 'Net.WebClient'
                - 'DownloadFile'
        condition: selection
    falsepositives:
        - Legitimate administrative scripts
    level: high
    tags:
        - attack.execution
        - attack.t1059.001
    ```
    * Use `sigmac` to convert rules: `sigmac -t splunk myrule.yml > splunk_query.txt`
* **Alternatives:** Vendor-specific rule languages (Splunk SPL, Elastic KQL/EQL).
* **Notes/Tips:** The SigmaHQ repository contains thousands of community rules. Contribute rules back! Essential for standardizing detection logic and leveraging community knowledge.

---

## Splunk Free

* **Description:** Splunk Enterprise offers a free license tier allowing users to index up to 500 MB of data per day. While limited in volume, it provides access to Splunk's powerful search processing language (SPL), data ingestion, indexing, alerting, and dashboarding capabilities. Excellent for learning Splunk or for very small environments/home labs.
* **Key Features/Why it's useful:**
    * **Powerful Search Language (SPL):** Industry-leading language for searching, analyzing, and visualizing machine data.
    * **Data Indexing & Onboarding:** Can ingest data from various sources (files, network ports, scripts, APIs).
    * **Alerting & Dashboarding:** Create alerts based on search results and build custom dashboards.
    * **Apps & Add-ons:** Splunkbase offers numerous apps (like Splunk Security Essentials) to extend functionality (some may require paid license features).
* **Official Website/Repository:** [https://www.splunk.com/](https://www.splunk.com/) (Download requires registration)
* **Type:** Log Management / SIEM Platform (Commercial with Free Tier)
* **Platform(s):** Linux, Windows, macOS.
* **Installation:** Download installer from Splunk website. Follow installation guide. Can be run as a single instance or distributed components (Forwarders, Indexers, Search Heads).
* **Basic Usage Example:** Configure data inputs (e.g., monitor files/logs, receive Syslog). Use the Search & Reporting app to write SPL queries (e.g., `index=main sourcetype=syslog failed` or `index=wineventlog EventCode=4625 | stats count by user`). Create dashboards based on searches.
* **Alternatives:** Elastic Stack (Open source core), Graylog (Open source), Wazuh, Microsoft Sentinel.
* **Notes/Tips:** The 500MB/day limit is strict. Exceeding it triggers warnings but doesn't stop indexing initially (behavior may vary by version). Learning SPL is a valuable skill. The free tier lacks many enterprise features (clustering, premium apps, advanced security capabilities).

---

## Wazuh (SIEM Focus)

* **Description:** While also providing HIDS, vulnerability detection, and FIM capabilities via its agents, Wazuh includes a robust central server component built on forks of OpenSearch (indexer) and OpenSearch Dashboards/Kibana (Web UI). This allows it to function as a complete SIEM solution, collecting logs not just from its own agents but also via Syslog, Beats, etc., normalizing data with decoders/rules, and providing dashboards, alerting, and compliance reporting.
* **Key Features/Why it's useful (SIEM aspects):**
    * **Centralized Log Collection & Analysis:** Ingests logs from Wazuh agents and other sources.
    * **Rule-Based Correlation & Alerting:** Includes extensive ruleset for detecting security events across collected logs.
    * **Integrated Dashboards:** Pre-built dashboards for security events, compliance (PCI DSS, GDPR, NIST 800-53), vulnerabilities, FIM, etc.
    * **Open Source & Scalable:** Provides a free, comprehensive SIEM/XDR platform that can scale.
* **Official Website/Repository:** [https://wazuh.com/](https://wazuh.com/)
* **Type:** Open Source Security Platform (SIEM/XDR/HIDS)
* **Platform(s):** Server components on Linux. Agents cross-platform.
* **Notes/Tips:** Can be a powerful all-in-one solution, especially when combined with its endpoint agent capabilities. Requires tuning of rules and dashboards. *Refer to Section 8 (Endpoint Security & Analysis) for more details on agent capabilities.*

---
