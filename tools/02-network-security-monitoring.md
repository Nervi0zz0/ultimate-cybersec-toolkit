# 2. 📡 Network Security Monitoring (NSM)

Network Security Monitoring involves collecting and analyzing network traffic data to detect and respond to security threats. For Blue Teams, this means having visibility into network communications, identifying anomalous behavior, intrusions, and policy violations. Tools in this section range from deep packet inspection to high-level flow analysis and intrusion detection systems.

## Index of Tools in this Section

* [Ettercap](#ettercap)
* [Snort](#snort)
* [Suricata](#suricata)
* [tcpdump](#tcpdump)
* [Wireshark (including TShark)](#wireshark-including-tshark)
* [Zeek](#zeek)

---

## Ettercap

* **Description:** A comprehensive suite primarily known for man-in-the-middle (MITM) attacks on LAN. Blue Teams primarily study Ettercap to **understand MITM techniques** (like ARP poisoning, DNS spoofing) in order to better detect and defend against them, rather than using it offensively. Its sniffing capabilities can occasionally be used for diagnostics in controlled environments.
* **Key Features/Why it's useful (for Blue Team understanding):**
    * Demonstrates mechanisms of ARP poisoning and DNS spoofing.
    * Shows how traffic can be intercepted on a LAN.
    * Highlights the importance of switch security features (like Dynamic ARP Inspection) and monitoring ARP tables.
    * Underscores risks of unencrypted protocols.
* **Official Website/Repository:** [https://www.ettercap-project.org/](https://www.ettercap-project.org/), [https://github.com/Ettercap/ettercap](https://github.com/Ettercap/ettercap)
* **Type:** GUI & CLI MITM Suite
* **Platform(s):** Primarily Linux; ports exist for macOS and Windows but may be less stable or feature-complete.
* **Installation:**
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install ettercap-graphical
    ```
* **Basic Usage Example:** Primarily for lab/educational use to understand attacks. Real-world Blue Team use is minimal.
* **Alternatives (for Blue Team tasks):** Dedicated ARP monitoring tools, IDS/NSM tools (Snort, Suricata, Zeek), Network Analyzers (Wireshark).
* **Notes/Tips:** **USE ETHICALLY AND LEGALLY.** Understanding Ettercap helps configure defenses but using it on networks without permission is illegal and disruptive. Focus on the *concepts* it demonstrates.

---

## Snort

* **Description:** A widely deployed, open-source Intrusion Prevention System (IPS) and Intrusion Detection System (IDS). Snort uses a rule-based language to perform real-time traffic analysis and packet logging, detecting probes, attacks, malware, and other policy violations based on predefined signatures and protocol anomalies.
* **Key Features/Why it's useful:**
    * **Signature-Based Detection:** Detects known threats using a vast set of community and commercial rules.
    * **Protocol Analysis:** Can decode and analyze various application layer protocols.
    * **Packet Logging:** Captures packets that trigger alerts for later analysis.
    * **Real-time Alerts:** Generates alerts when malicious traffic or policy violations are detected.
    * **Modes:** Can run as a sniffer, packet logger, or Network IDS/IPS.
* **Official Website/Repository:** [https://www.snort.org/](https://www.snort.org/)
* **Type:** Network IDS/IPS
* **Platform(s):** Linux, BSD, macOS, Windows (Performance typically best on Linux/BSD).
* **Installation:** Via package managers or source compilation. Requires careful configuration.
    ```bash
    # Debian/Ubuntu (May vary depending on Snort version - Snort 3 recommended)
    # Check official docs for current install procedures, often involves adding repos.
    sudo apt install snort 
    ```
* **Basic Usage Example (Conceptual):**
    ```bash
    # Run Snort in IDS mode using a specific config file and logging to /var/log/snort
    sudo snort -c /etc/snort/snort.conf -l /var/log/snort -i eth0 -A console
    # (-c config, -l log dir, -i interface, -A alert mode)
    ```
* **Alternatives:** Suricata (multi-threaded), Zeek (different approach), commercial IDS/IPS solutions.
* **Notes/Tips:** Effective use requires well-configured rulesets (e.g., Snort Community Rules, Emerging Threats Open, paid Talos rules) and regular updates using tools like PulledPork or Suricata-Update. Tuning rules is crucial to reduce false positives.

---

## Suricata

* **Description:** A high-performance, open-source Network Intrusion Detection System (IDS), Intrusion Prevention System (IPS), and Network Security Monitoring (NSM) engine. Developed by the OISF (Open Information Security Foundation). It is multi-threaded, offering significant performance advantages on multi-core hardware compared to single-threaded engines.
* **Key Features/Why it's useful:**
    * **Multi-Threading:** Excellent performance and scalability on modern hardware.
    * **Rule Compatibility:** Supports Snort VRT and Emerging Threats rule formats.
    * **Automatic Protocol Detection:** Identifies protocols on non-standard ports.
    * **File Extraction:** Can extract files transmitted over HTTP, SMTP, FTP, NFS, SMB for offline analysis (e.g., malware analysis).
    * **Lua Scripting:** Allows for complex detection logic and custom output.
    * **Rich Logging:** Generates JSON-based logs (Eve JSON) suitable for integration with SIEMs (Elastic Stack, Splunk).
* **Official Website/Repository:** [https://suricata.io/](https://suricata.io/)
* **Type:** Network IDS/IPS/NSM Engine
* **Platform(s):** Linux, BSD, macOS, Windows.
* **Installation:** Via package managers or source. Recommended method often via OISF PPA on Ubuntu.
    ```bash
    # Ubuntu (using OISF PPA - Recommended)
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt update && sudo apt install suricata
    ```
* **Basic Usage Example (Conceptual):**
    ```bash
    # Run Suricata in IDS mode on interface eth0 using default config
    sudo suricata -c /etc/suricata/suricata.yaml -i eth0
    ```
* **Alternatives:** Snort (single-threaded rule-based), Zeek (protocol analysis focus), commercial IDS/IPS.
* **Notes/Tips:** Like Snort, requires managing and updating rulesets (e.g., using `suricata-update`). Performance tuning (CPU affinity, capture methods like AF_PACKET, PF_RING) is important for high-traffic networks. Eve JSON logging is very powerful for log aggregation.

---

## tcpdump

* **Description:** A powerful and ubiquitous command-line packet analyzer. It allows users to display TCP/IP and other packets being transmitted or received over a network. Crucial for Blue Teams for quick captures, troubleshooting, and providing raw packet data for deeper analysis.
* **Key Features/Why it's useful:**
    * Lightweight and fast packet capture directly from the console.
    * Powerful filtering language (Berkeley Packet Filter - BPF syntax) to capture only relevant traffic.
    * Excellent for use in scripts or environments without a GUI.
    * Can write captured packets to a file (`.pcap`) for later analysis in tools like Wireshark.
    * Available on almost all Unix-like operating systems, often pre-installed.
* **Official Website/Repository:** [https://www.tcpdump.org/](https://www.tcpdump.org/)
* **Type:** CLI Packet Analyzer
* **Platform(s):** Linux, macOS, BSD, other Unix-like systems (often pre-installed). Windows version available (requires Npcap or deprecated WinPcap driver).
* **Installation:** Often pre-installed.
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install tcpdump
    # ... other platforms ...
    ```
* **Basic Usage Example:** (Requires root/administrator privileges)
    ```bash
    # Start basic capture on interface eth0 - Ctrl+C to stop
    sudo tcpdump -i eth0 -nn -A
    # (-nn disables name/port resolution, -A shows packet content in ASCII)

    # Capture traffic related to a specific host and write to file
    sudo tcpdump -i eth0 host 192.168.1.50 -w suspicious_traffic.pcap

    # Capture DNS traffic (port 53)
    sudo tcpdump -i eth0 port 53
    ```
* **Alternatives:** TShark (Wireshark's CLI - more focused on dissection/analysis), ngrep (grep for network packets).
* **Notes/Tips:** Understanding BPF filter syntax is key. Use `-w` to save full packets for Wireshark analysis. Use `-nn` to avoid potentially slow DNS lookups during capture.

---

## Wireshark (including TShark)

* **Description:** The world's foremost network protocol analyzer. Essential for Blue Teams for deep-diving into network traffic, troubleshooting issues, performing forensic analysis on packet captures, and understanding protocol interactions. **TShark** is the vital command-line counterpart for capturing or analyzing traffic on servers or via scripts.
* **Key Features/Why it's useful:**
    * **GUI (Wireshark):** Deep graphical packet inspection, powerful display filtering, stream reconstruction (TCP/HTTP/etc.), statistics, graphing.
    * **CLI (TShark):** Remote/scripted capture, CLI filtering, field extraction, powerful analysis capabilities without a GUI.
    * **Protocol Dissection:** Understands hundreds of protocols at various layers.
    * **File Format Support:** Reads/writes various capture file formats (pcap, pcapng).
* **Official Website/Repository:** [https://www.wireshark.org/](https://www.wireshark.org/)
* **Type:** GUI Network Analyzer (Wireshark), CLI Network Analyzer (TShark)
* **Platform(s):** Windows, macOS, Linux, other Unix-like systems.
* **Installation:** Installs both Wireshark (GUI) and TShark (CLI).
    ```bash
    # Debian/Ubuntu (May need to allow non-root capture during install)
    sudo apt update && sudo apt install wireshark
    # ... other platforms ...
    ```
* **Basic Usage Example:**
    * **Wireshark (GUI):** Start capture, apply display filters (e.g., `ip.addr == x.x.x.x`, `http.request`, `dns.qry.name contains "malicious"`), follow streams, save captures.
    * **TShark (CLI):**
        ```bash
        # Capture traffic on eth0, write to file
        sudo tshark -i eth0 -w capture.pcapng

        # Read file, apply display filter, show specific fields related to DNS queries
        tshark -r capture.pcapng -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name
        ```
* **Alternatives:** tcpdump (CLI capture focus), Microsoft Network Monitor (Windows, older), ngrep (CLI pattern matching).
* **Notes/Tips:** Learn the difference between Capture Filters (BPF syntax, applied during capture) and Display Filters (Wireshark syntax, applied after capture). Following streams (TCP/TLS/HTTP) is very powerful for analysis.

---

## Zeek (formerly Bro)

* **Description:** An open-source network security monitoring framework, distinct from traditional signature-based IDS. Zeek operates by deeply parsing network traffic and generating rich, high-fidelity logs describing network activity (connections, DNS queries, HTTP requests, SSL certificates, files transferred, etc.). It's highly extensible via its scripting language.
* **Key Features/Why it's useful:**
    * **Rich Transaction Logs:** Creates detailed logs for many protocols, providing context beyond simple packet headers (e.g., `conn.log`, `http.log`, `dns.log`, `ssl.log`, `files.log`). These logs are invaluable for incident response and threat hunting.
    * **Behavioral Analysis:** The scripting engine allows for custom detection logic based on traffic patterns and behaviors, not just signatures.
    * **File Extraction & Analysis:** Can carve files from traffic and integrate with external analysis tools.
    * **Operational Security:** Provides insights into network usage, encryption standards (TLS versions, certificates), and application behavior.
* **Official Website/Repository:** [https://zeek.org/](https://zeek.org/)
* **Type:** Network Security Monitoring Framework / Network Analysis Tool
* **Platform(s):** Linux, BSD, macOS.
* **Installation:** Via package managers or source compilation.
    ```bash
    # Follow official instructions, often involves specific repos or build steps.
    # Example (may vary):
    # Debian/Ubuntu (using OBS repo - check Zeek docs for current recommendation)
    # sudo apt install zeek
    ```
* **Basic Usage Example:**
    ```bash
    # Run Zeek on live interface eth0 using default scripts, logging to current dir
    sudo zeek -i eth0

    # Analyze an existing pcap file
    zeek -r capture.pcapng

    # Check the generated logs (e.g., conn.log for connection summaries)
    cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service duration
    # (zeek-cut is a helper to parse logs)
    ```
* **Alternatives:** IDS (Snort/Suricata complement Zeek), SIEMs (often ingest Zeek logs), commercial NSM platforms.
* **Notes/Tips:** Zeek generates a LOT of log data; requires appropriate storage and log management (often sent to a SIEM like Elastic Stack or Splunk). Learning the Zeek scripting language unlocks its full potential. Understanding the structure and meaning of the different log files (`conn.log`, `dns.log`, etc.) is key.

---