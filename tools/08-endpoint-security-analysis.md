# 8. 💻 Endpoint Security & Analysis

Endpoints (desktops, laptops, servers) are often the primary targets for attackers. Securing and monitoring them is a core function of any Blue Team. This section covers concepts and tools related to endpoint protection (EPP), detection and response (EDR/XDR), system monitoring, and detailed analysis of endpoint activity to identify and investigate threats.

## Index of Tools & Concepts in this Section

* [Antivirus (AV) / Endpoint Protection Platform (EPP) / Endpoint Detection & Response (EDR) / Extended Detection & Response (XDR)](#antivirus-av--endpoint-protection-platform-epp--endpoint-detection--response-edr--extended-detection--response-xdr)
* [Osquery](#osquery)
* [Sysinternals Suite](#sysinternals-suite)
* [Sysmon (System Monitor)](#sysmon-system-monitor)
* [Velociraptor](#velociraptor)
* [Wazuh](#wazuh)

---

## Antivirus (AV) / Endpoint Protection Platform (EPP) / Endpoint Detection & Response (EDR) / Extended Detection & Response (XDR)

* **Description:** These represent an evolution of endpoint security technologies:
    * **AV (Legacy):** Primarily focused on detecting known malware signatures and basic heuristics.
    * **EPP (Next-Gen AV):** Builds on AV with more advanced prevention techniques like machine learning, behavior analysis, exploit prevention, and device control. Often cloud-managed.
    * **EDR:** Assumes prevention will eventually fail and focuses on *detection*, *investigation*, and *response*. Provides deep visibility into endpoint activities (processes, network, registry, files), allows threat hunting, isolates endpoints, and enables remediation actions.
    * **XDR:** Extends EDR concepts by integrating telemetry and control points beyond the endpoint, correlating data from network, cloud, email, identity sources, etc., for a more unified view of an attack chain.
* **Key Features/Why it's useful:** Blue Teams rely on these platforms (especially EDR/XDR) as the primary means of preventing, detecting, and responding to threats directly on endpoints where user activity and initial compromises often occur. They provide crucial visibility and control.
* **Examples (Vendors):** Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne Singularity, Palo Alto Cortex XDR, Carbon Black, Cybereason, Trend Micro Vision One, Sophos Intercept X. (Listing specific vendors can be complex, focus on the concepts).
* **Type:** Endpoint Security Concepts & Platforms
* **Platform(s):** Primarily Windows, macOS, Linux (agent-based).
* **Installation:** Deployment of agents via management consoles.
* **Basic Usage Example:** Interacting via vendor's cloud management console for configuration, alert triage, threat hunting (using vendor-specific query languages often similar to KQL or SQL), initiating response actions (e.g., isolate host, kill process, run live query).
* **Alternatives:** Open source tools like Wazuh combined with other components can provide some EDR-like capabilities, but commercial EDR/XDR generally offer more integrated features and advanced analytics.
* **Notes/Tips:** Understanding the capabilities and limitations of your organization's specific EPP/EDR/XDR solution is critical for the Blue Team. Effective use involves configuring policies, tuning alerts, proactive threat hunting, and integrating with other security tools (like SIEM).

---

## Osquery

* **Description:** An open-source framework exposing the operating system as a relational database queryable with SQL. Extremely valuable for Blue Teams needing deep, flexible visibility into endpoint state for threat hunting, compliance checks, and incident investigation across fleets of diverse endpoints.
* **Key Features/Why it's useful:** Querying running processes, kernel modules, network connections, hardware, configurations, file hashes, user logins, browser plugins, etc., using standard SQL syntax.
* **Official Website/Repository:** [https://osquery.io/](https://osquery.io/)
* **Type:** Endpoint Instrumentation / Query Engine (Agent + CLI `osqueryi`)
* **Platform(s):** Linux, Windows, macOS, FreeBSD.
* **Notes/Tips:** While powerful standalone via `osqueryi`, it's often deployed as a daemon (`osqueryd`) feeding data into a central log management/SIEM system or a dedicated Osquery fleet manager (e.g., FleetDM, Kolide). *Refer to Section 7 (Miscellaneous Defensive Tools) for more details.*

---

## Sysinternals Suite

* **Description:** An essential suite of free utilities from Microsoft for deep Windows system analysis, troubleshooting, and diagnostics. Indispensable for Blue Teams performing manual endpoint investigations or malware analysis on Windows systems.
* **Key Features/Why it's useful (Key Tools):** Process Explorer (advanced task mgr), Process Monitor (real-time activity logging), Autoruns (persistence mechanisms), Sysmon (detailed event logging - see separate entry), TCPView (network connections), Strings.
* **Official Website/Repository:** [Microsoft Sysinternals Documentation](https://docs.microsoft.com/en-us/sysinternals/)
* **Type:** Windows Troubleshooting & Analysis Utilities (GUI & CLI)
* **Platform(s):** Windows.
* **Notes/Tips:** These tools provide granular insights often not available through standard Windows interfaces. Excellent for live analysis or analyzing forensic images when combined with tools like KAPE. *Refer to Section 7 (Miscellaneous Defensive Tools) for more details.*

---

## Sysmon (System Monitor)

* **Description:** A Windows system service and device driver that, once installed, remains resident across reboots to monitor and log detailed system activity to the Windows Event Log. It provides deep visibility into process creation (with command lines), network connections, file creation events, registry modifications, image loading, WMI events, and much more, far beyond standard Windows logging. It's a foundational data source for EDR capabilities and SIEM-based threat hunting.
* **Key Features/Why it's useful:**
    * Logs detailed information about process creation including parent process, command line arguments, and hashes.
    * Records network connections initiated by processes.
    * Tracks driver/image loading events.
    * Monitors registry modifications and file creation/deletion events.
    * Highly configurable via XML configuration files to tune logging verbosity and filter noise.
    * Generated logs are standard Windows Events, easily forwardable to SIEMs.
* **Official Website/Repository:** Included in the [Microsoft Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). Configuration resources: [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config), [Olaf Hartong Sysmon Modular](https://github.com/olafhartong/sysmon-modular).
* **Type:** Windows System Monitoring Service / Event Log Data Source
* **Platform(s):** Windows.
* **Installation:** Requires Administrator privileges. Configuration is key.
    ```bash
    # Install Sysmon service with a configuration file
    sysmon.exe -accepteula -i config.xml 

    # Update configuration
    sysmon.exe -c config.xml

    # Uninstall service
    sysmon.exe -u
    ```
* **Basic Usage Example:** Sysmon runs as a background service. The "usage" involves *analyzing* the logs it generates (Event IDs 1-25+) within Windows Event Viewer or preferably a centralized SIEM, using queries to hunt for suspicious patterns (e.g., specific command lines, parent-child process relationships, network connections to known bad IPs).
* **Alternatives:** Built-in Windows logging (less detailed), commercial EDR agents (often incorporate similar telemetry), Auditd (Linux).
* **Notes/Tips:** Effective Sysmon deployment relies heavily on a good configuration file (like SwiftOnSecurity's or Olaf Hartong's modular one) to balance detail with noise/performance impact. Forwarding Sysmon logs to a SIEM is essential for effective threat hunting and detection.

---

## Velociraptor

* **Description:** An advanced open-source endpoint visibility, collection, and response tool. It uses a flexible query language (VQL) to explore endpoint state, collect forensic artifacts, hunt for threats across many endpoints simultaneously, and automate response actions. It operates with a client-server architecture.
* **Key Features/Why it's useful:**
    * **Powerful Query Language (VQL):** Allows flexible querying of endpoint state (processes, files, registry, network, OS info, etc.) similar to Osquery but with more built-in forensic capabilities.
    * **Fleet Management:** Can query and manage thousands of endpoints concurrently from a central server.
    * **Artifact Collection:** Efficiently collects specific files, logs, or forensic artifacts based on VQL queries or predefined artifact definitions.
    * **Real-time Monitoring & Hunting:** Can monitor for events or run scheduled hunts across the fleet.
    * **Extensibility:** Define custom artifacts and VQL queries for specific needs.
* **Official Website/Repository:** [https://docs.velociraptor.app/](https://docs.velociraptor.app/), [https://github.com/Velocidex/velociraptor](https://github.com/Velocidex/velociraptor)
* **Type:** Endpoint Visibility & Response Platform (Client/Server Architecture, Web UI, VQL)
* **Platform(s):** Agents (Clients) for Windows, Linux, macOS. Server runs on Linux primarily (also Windows/macOS possible).
* **Installation:** Requires setting up the server and deploying client agents. Binaries available on GitHub releases. Docker deployment option exists.
* **Basic Usage Example:** Interact via the Web UI hosted by the server. Select client(s) or groups. Use the VQL Shell to run queries (e.g., `SELECT * FROM pslist()`, `SELECT * FROM Artifact.Windows.Sysinternals.Autoruns()`). Launch "Hunts" to run queries/artifact collection across multiple clients. Collect files using `upload()` function in VQL.
* **Alternatives:** GRR Rapid Response (Google), commercial EDR/XDR platforms, Osquery + Fleet Manager.
* **Notes/Tips:** Steeper learning curve than basic tools but extremely powerful for large-scale IR and threat hunting. Understanding VQL is key.

---

## Wazuh

* **Description:** A popular open-source, unified XDR and SIEM platform designed for threat detection, visibility, security monitoring, and compliance. It uses agents deployed on endpoints (Windows, Linux, macOS) to collect security data (logs, file integrity, configuration assessment, vulnerability data, etc.), which is sent to a central server for analysis and alerting.
* **Key Features/Why it's useful:**
    * **Log Data Analysis:** Collects and analyzes logs from endpoints and network devices.
    * **File Integrity Monitoring (FIM):** Detects changes to critical system files.
    * **Vulnerability Detection:** Scans endpoints for known vulnerabilities (integrates with CVE databases).
    * **Security Configuration Assessment (SCA):** Checks configurations against security baselines (like CIS).
    * **Intrusion Detection (HIDS):** Rule-based detection of suspicious activity on hosts.
    * **Active Response:** Can automatically trigger actions on agents based on alerts.
    * **Web UI (Kibana based):** Provides dashboards, alert investigation, and agent management.
* **Official Website/Repository:** [https://wazuh.com/](https://wazuh.com/), [https://github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)
* **Type:** Open Source Security Platform (XDR/SIEM/HIDS) (Agent/Server Architecture, Web UI)
* **Platform(s):** Agents for Windows, Linux, macOS, Solaris, AIX. Server components run on Linux.
* **Installation:** Offers various installation methods (All-in-one, distributed, Docker, cloud images). Follow official documentation. Typically involves setting up Wazuh server, indexer (OpenSearch/Elasticsearch fork), and dashboard.
* **Basic Usage Example:** Interact via the Wazuh Dashboard (Kibana). Monitor alerts, investigate events using dashboards for FIM, vulnerabilities, logs, etc. Manage agent deployment and configuration. Tune rules to reduce noise.
* **Alternatives:** Elastic Security (requires Elastic Stack), Splunk + Security Essentials App, Security Onion (Distro including Wazuh/other tools), commercial SIEM/XDR platforms.
* **Notes/Tips:** Wazuh is very feature-rich but requires proper setup and tuning. Can serve as both endpoint agent (HIDS) and central SIEM/analysis platform. Scales well.

---