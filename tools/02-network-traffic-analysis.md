# 2. 📡 Network Traffic Analysis Tools

These tools are essential for capturing, inspecting, and analyzing network packets. They help in troubleshooting network issues, understanding communication flows, and identifying suspicious or malicious activity within network traffic.

---

## Wireshark (including TShark)

* **Description:** The world's foremost and widely-used network protocol analyzer. It lets you capture and interactively browse the traffic running on a computer network. It has a rich feature set including deep inspection of hundreds of protocols, live capture, offline analysis, and powerful filtering. **TShark** is the companion command-line utility included with Wireshark, enabling scripted or remote captures and analysis.
* **Key Features/Why it's useful:**
    * **GUI (Wireshark):**
        * Detailed graphical packet Browse and inspection.
        * Rich display filters for drilling down into specific traffic.
        * Color coding rules for quick identification of traffic types.
        * Network statistics generation (endpoints, conversations, protocol hierarchies).
        * Ability to follow TCP, UDP, HTTP, and other protocol streams.
    * **CLI (TShark):**
        * Capturing traffic directly from the command line (ideal for servers or remote systems).
        * Filtering traffic during capture (capture filters) or display (display filters).
        * Extracting specific fields from packets for scripting or logging.
        * Performing statistical analysis from the command line.
        * Reading and writing capture files in various formats (libpcap, pcapng).
* **Official Website/Repository:** [https://www.wireshark.org/](https://www.wireshark.org/)
* **Type:** GUI Network Analyzer (Wireshark), CLI Network Analyzer (TShark)
* **Platform(s):** Windows, macOS, Linux, other Unix-like systems.
* **Installation:** Installs both Wireshark (GUI) and TShark (CLI).
    ```bash
    # Debian/Ubuntu (May need to allow non-root capture during install)
    sudo apt update && sudo apt install wireshark
    # Fedora
    sudo dnf install wireshark-cli wireshark-qt # Or just wireshark package
    # macOS (using Homebrew)
    brew install --cask wireshark
    # Windows: Download installer from official site. Ensure Npcap driver is installed.
    ```
* **Basic Usage Example:**
    * **Wireshark (GUI):**
        1. Launch Wireshark.
        2. Select the network interface you want to capture from (e.g., Ethernet, Wi-Fi).
        3. Double-click the interface or press the Start button (shark fin icon).
        4. Traffic starts appearing.
        5. Use the "Apply a display filter" bar to filter packets (e.g., `ip.addr == 192.168.1.1`, `tcp.port == 80`, `dns`).
        6. Stop capture (red square button).
        7. Save the capture file (File > Save As).
    * **TShark (CLI):**
        ```bash
        # List available capture interfaces (might need root/admin)
        sudo tshark -D

        # Basic capture from an interface (e.g., eth0 or interface number from -D) - use Ctrl+C to stop
        sudo tshark -i eth0 

        # Capture traffic and write to a file
        sudo tshark -i eth0 -w capture.pcapng

        # Capture specific traffic (e.g., only port 80) using capture filter
        sudo tshark -i eth0 -w http_capture.pcapng -f "tcp port 80"

        # Read a capture file and apply a display filter
        tshark -r capture.pcapng -Y "ip.addr == 192.168.1.100"

        # Read file and extract specific fields (e.g., source/dest IP, TCP port)
        tshark -r capture.pcapng -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport "tcp"
        ```
* **Alternatives:** tcpdump (CLI, often pre-installed on Linux/macOS), Microsoft Network Monitor (Windows, older), ngrep (CLI).
* **Notes/Tips:** Capturing network traffic often requires administrator or root privileges. Installing Wireshark on Windows usually includes installing the Npcap driver for packet capture. Understanding capture filters (libpcap syntax) and display filters (Wireshark syntax) is crucial for effective use.

---


## Ettercap

* **Description:** A comprehensive suite for man-in-the-middle (MITM) attacks on LAN. It features sniffing of live connections, content filtering on the fly, and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis. It was a pioneering tool for MITM testing.
* **Key Features/Why it's useful:**
    * Sniffing traffic on switched networks (via ARP poisoning or ICMP redirect).
    * Active interception and manipulation of network traffic.
    * ARP poisoning to redirect traffic through the attacker's machine.
    * DNS spoofing to redirect users to fake websites.
    * Password capturing for various protocols (HTTP, FTP, Telnet, etc. - often less effective on modern encrypted traffic).
    * Character injection into established connections.
    * Plugin support for extending functionality (e.g., DoS attacks, specific protocol manipulation).
* **Official Website/Repository:** [https://www.ettercap-project.org/](https://www.ettercap-project.org/), [https://github.com/Ettercap/ettercap](https://github.com/Ettercap/ettercap)
* **Type:** GUI & CLI MITM Suite
* **Platform(s):** Primarily Linux; ports exist for macOS and Windows but may be less stable or feature-complete.
* **Installation:**
    ```bash
    # Debian/Ubuntu
    sudo apt update && sudo apt install ettercap-graphical # For GUI + CLI
    # or just ettercap-common for CLI only
    
    # Fedora
    sudo dnf install ettercap ettercap-graphical 
    ```
* **Basic Usage Example (Use ONLY on networks you OWN or have EXPLICIT permission to test):**
    * **GUI:**
        1. Launch with `sudo ettercap -G`.
        2. Select unified sniffing (`Sniff` > `Unified sniffing...` > choose interface).
        3. Scan for hosts (`Hosts` > `Scan for hosts`).
        4. View host list (`Hosts` > `Hosts list`).
        5. Select target(s) (e.g., target machine IP -> `Add to Target 1`, gateway IP -> `Add to Target 2`).
        6. Start ARP poisoning (`Mitm` > `Arp poisoning...` > check `Sniff remote connections`).
        7. Start sniffing (`Start` > `Start sniffing`).
        8. Observe connections (`View` > `Connections`).
    * **CLI:**
        ```bash
        # Example: ARP poisoning between target 192.168.1.10 and gateway 192.168.1.1 on interface eth0
        sudo ettercap -Tq -i eth0 -M arp:remote /192.168.1.10/ /192.168.1.1/ 
        # (-Tq for text-only quiet mode, -i for interface, -M for MITM attack) 
        ```
* **Alternatives:** Bettercap (more modern), mitmproxy (HTTP/S focus), Scapy (packet crafting library for custom attacks), Responder (LLMNR/NBT-NS poisoning).
* **Notes/Tips:** **EXTREME CAUTION ADVISED.** Using Ettercap inappropriately can easily disrupt networks and is illegal without authorization. Much of its classic password sniffing effectiveness is reduced by modern encryption (SSL/TLS/HTTPS). It requires root privileges. Understand ARP poisoning and its effects before attempting use.

---

## tcpdump

* **Description:** A powerful and ubiquitous command-line packet analyzer. It allows users to display TCP/IP and other packets being transmitted or received over a network to which the computer is attached. It's highly flexible due to its rich filtering capabilities.
* **Key Features/Why it's useful:**
    * Lightweight and fast packet capture directly from the console.
    * Powerful filtering language (Berkeley Packet Filter - BPF syntax) to capture only relevant traffic.
    * Excellent for use in scripts or environments without a GUI.
    * Can write captured packets to a file (`.pcap`) for later analysis in tools like Wireshark.
    * Available on almost all Unix-like operating systems, often pre-installed.
* **Official Website/Repository:** [https://www.tcpdump.org/](https://www.tcpdump.org/)
* **Type:** CLI Packet Analyzer
* **Platform(s):** Linux, macOS, BSD, other Unix-like systems (often pre-installed). Windows version available (requires Npcap or deprecated WinPcap driver).
* **Installation:**
    ```bash
    # Often pre-installed on Linux/macOS. If not:
    # Debian/Ubuntu
    sudo apt update && sudo apt install tcpdump
    # Fedora
    sudo dnf install tcpdump
    # macOS (using Homebrew if not present)
    brew install tcpdump 
    # Windows: Included with Npcap installation (which Wireshark uses), or via WinPcap (older).
    ```
* **Basic Usage Example:** (Requires root/administrator privileges)
    ```bash
    # List available network interfaces
    sudo tcpdump -D

    # Start basic capture on a specific interface (e.g., eth0) - Ctrl+C to stop
    sudo tcpdump -i eth0

    # Capture with more verbosity (-v) and no DNS resolution (-n)
    sudo tcpdump -i eth0 -vn

    # Capture traffic related to a specific host
    sudo tcpdump -i eth0 host 192.168.1.50

    # Capture traffic for a specific port (e.g., HTTP port 80)
    sudo tcpdump -i eth0 port 80

    # Capture traffic and write to a file
    sudo tcpdump -i eth0 -w capture_file.pcap

    # Read from a capture file
    tcpdump -r capture_file.pcap

    # Complex filter: capture TCP traffic to/from host 10.0.0.5 on port 443
    sudo tcpdump -i eth0 'tcp and host 10.0.0.5 and port 443' 
    ```
* **Alternatives:** TShark (Wireshark's CLI - more focused on dissection/analysis), ngrep (grep for network packets), Snort (IDS, but can be used for capture).
* **Notes/Tips:** Understanding the BPF filter syntax is key to using `tcpdump` effectively (it's the same syntax used for Wireshark's *capture* filters). It