# 4. 🔍 Digital Forensics & Incident Response (DFIR)

When a security incident occurs, Digital Forensics and Incident Response (DFIR) processes are critical for understanding what happened, containing the damage, eradicating the threat, and recovering systems. Blue Teams rely on specialized tools to acquire, preserve, and analyze digital evidence from disks, memory, logs, and networks to piece together the timeline of an attack and identify the attacker's actions. Modern DFIR also increasingly involves analyzing cloud environments.

## Index of Tools in this Section

* [Autopsy](#autopsy)
* [Chainsaw / Hayabusa](#chainsaw--hayabusa)
* [ExifTool](#exiftool)
* [FTK Imager](#ftk-imager)
* [KAPE (Kroll Artifact Parser and Extractor)](#kape-kroll-artifact-parser-and-extractor)
* [Memory Acquisition Tools](#memory-acquisition-tools)
* [Plaso / Log2Timeline](#plaso--log2timeline)
* [Sleuth Kit](#sleuth-kit)
* [StegAnalyzer](#steganalyzer)
* [Volatility / Volatility 3](#volatility--volatility-3)
* [X-Ways Forensics](#x-ways-forensics)

---

## Autopsy

* **Description:** A popular open-source digital forensics platform and graphical interface for The Sleuth Kit and other digital forensics tools. It allows examiners to analyze disk images, mobile devices (via add-ons), and file systems to investigate potential evidence.
* **Key Features/Why it's useful:**
    * Graphical interface simplifies disk image analysis.
    * Timeline analysis of file system activity.
    * Keyword searching and indexing.
    * Web artifact analysis (browser history, cache).
    * Registry analysis (on Windows images).
    * Extensible with Python modules for additional functionality.
* **Official Website/Repository:** [https://www.autopsy.com/](https://www.autopsy.com/) / [https://github.com/sleuthkit/autopsy](https://github.com/sleuthkit/autopsy)
* **Type:** Digital Forensics Platform (GUI)
* **Platform(s):** Windows, macOS, Linux.
* **Installation:** Download installers from the official website.
* **Basic Usage Example:** Create a new case, add a data source (disk image like `.dd`, `.E01`), wait for ingest modules to run, then browse the file system, view artifacts, search keywords, and build a timeline.
* **Alternatives:** FTK Imager (Imaging focused, some analysis), EnCase (Commercial), X-Ways Forensics (Commercial), Open Source CLI tools (Sleuth Kit, etc.).
* **Notes/Tips:** Autopsy provides a user-friendly way to leverage the power of The Sleuth Kit. Performance depends on the size of the image and the ingest modules selected.

---

## Chainsaw / Hayabusa

* **Description:** Fast, complementary tools designed for rapid triage and threat hunting within Windows Event Logs (`.evtx` files). Chainsaw leverages Sigma rules for detection, while Hayabusa uses its own built-in logic and counters. Both aim to quickly identify suspicious activity within potentially massive log files.
* **Key Features/Why it's useful:**
    * **Speed:** Written in Go (Chainsaw) and Rust (Hayabusa) for high performance.
    * **Threat Hunting:** Quickly surfaces potentially malicious activities based on Sigma rules (Chainsaw) or built-in heuristics (Hayabusa).
    * **EVTX Focus:** Specifically designed for the complexities of Windows Event Logs.
    * **Output Formats:** Provide results in easily readable formats (console, CSV, JSON).
* **Official Website/Repository:**
    * Chainsaw: [https://github.com/countercept/chainsaw](https://github.com/countercept/chainsaw)
    * Hayabusa: [https://github.com/Yamato-Security/hayabusa](https://github.com/Yamato-Security/hayabusa)
* **Type:** CLI Log Analysis / Threat Hunting Tool
* **Platform(s):** Windows, Linux, macOS (distributed as binaries).
* **Installation:** Download pre-compiled binaries from GitHub releases.
* **Basic Usage Example:**
    ```bash
    # Chainsaw: Hunt using built-in Sigma rules against EVTX files in a directory
    chainsaw hunt C:\path\to\evtx\logs\ -r rules\ --mapping mappings\sigma-event-log-mapping.yml

    # Hayabusa: Scan EVTX files in a directory, output to CSV
    hayabusa.exe -d C:\path\to\evtx\logs\ -o report.csv
    ```
* **Alternatives:** DeepBlueCLI (PowerShell), Event Log Explorer (GUI), SIEM queries (Splunk, Elastic).
* **Notes/Tips:** Excellent for initial triage of event logs during incident response before diving deeper with a SIEM. Use Chainsaw for Sigma rule coverage and Hayabusa for its specific detection modules.

---

## ExifTool

* **Description:** A powerful command-line utility and Perl library for reading, writing, and editing meta information (metadata) in a wide variety of file types (images, videos, audio, documents). Crucial for extracting hidden information like timestamps, GPS coordinates, camera models, software used, etc.
* **Key Features/Why it's useful:**
    * Supports a huge number of file formats and metadata tags.
    * Extracting timestamps (creation, modification dates) which might differ from filesystem timestamps.
    * Finding GPS coordinates embedded in photos/videos.
    * Identifying software used to create or modify files.
    * Detecting hidden information or anomalies in metadata.
* **Official Website/Repository:** [https://exiftool.org/](https://exiftool.org/)
* **Type:** CLI Metadata Analysis Tool
* **Platform(s):** Windows, macOS, Linux.
* **Installation:** Download from the website (Windows executable, macOS package, or Perl archive for Linux/others).
    ```bash
    # Often available in Linux repos
    sudo apt install libimage-exiftool-perl
    # or use the downloaded archive
    ```
* **Basic Usage Example:**
    ```bash
    # Display all metadata for a file
    exiftool image.jpg

    # Display only GPS information
    exiftool -gps* image.jpg

    # Display Common tags in a readable format
    exiftool -common image.jpg

    # Extract metadata recursively from a directory, output to CSV
    exiftool -csv -r /path/to/directory > metadata.csv
    ```
* **Alternatives:** Built-in OS file properties (very limited), specific viewers (limited formats), Phil Harvey's website provides detailed tag information.
* **Notes/Tips:** Invaluable for forensics and OSINT. Be aware that metadata can be easily stripped or modified. Use `-a` to show duplicate tags and `-G` to show group names for tags.

---

## FTK Imager

* **Description:** A free data preview and imaging tool from AccessData. It allows examiners to create forensic images (bit-for-bit copies) of storage media (hard drives, USB drives, etc.) in various formats, preview files within images or on live systems, and export files.
* **Key Features/Why it's useful:**
    * **Forensic Imaging:** Creates forensically sound images (e.g., `.E01`, `.dd`, `.SMART`) with hashing (MD5, SHA1) for integrity verification. Supports hardware write blockers.
    * **Image Mounting:** Can mount forensic images as read-only volumes in Windows for easy Browse.
    * **File System Preview:** Allows Browse files and folders on attached devices or within images without altering the source.
    * **Memory Capture:** Can capture RAM contents from a live Windows system.
    * **Triage:** Quickly preview files (including deleted ones from unallocated space) and export specific items.
* **Official Website/Repository:** [https://www.exterro.com/ftk-imager](https://www.exterro.com/ftk-imager) (Part of Exterro FTK suite)
* **Type:** Forensic Imaging & Preview Tool (GUI)
* **Platform(s):** Windows. A CLI version for Linux exists but is less common.
* **Installation:** Download installer from the official website (requires registration).
* **Basic Usage Example:** Launch FTK Imager. Use `File > Create Disk Image...` to image a drive. Use `File > Add Evidence Item...` to load an image or physical drive for previewing. Browse files, export as needed. Use `File > Capture Memory...` for RAM capture.
* **Alternatives:** `dd` / `dc3dd` (CLI imaging on Linux), Guymager (GUI imaging on Linux), Arsenal Image Mounter (Mounting images), Belkasoft RAM Capturer / Magnet RAM Capture (Memory capture).
* **Notes/Tips:** FTK Imager is a standard tool for forensic acquisition. Always use a hardware write blocker when imaging original evidence drives if possible. Verify image hashes after creation.

---

## KAPE (Kroll Artifact Parser and Extractor)

* **Description:** An extremely efficient and popular free tool for forensic artifact collection and parsing. KAPE allows responders to quickly collect targeted files (system logs, browser history, registry hives, etc.) from live Windows systems or mounted images based on predefined "Targets," and then process them using various external CLI programs defined as "Modules."
* **Key Features/Why it's useful:**
    * **Speed & Efficiency:** Designed for rapid triage and collection of the most forensically relevant artifacts.
    * **Targeted Collection:** Uses configurable YAML files (`.tkape`) to define exactly what artifacts to collect, reducing data volume.
    * **Modular Processing:** Uses external CLI tools (e.g., RegRipper, AppCompatibilityParser, PECmd) defined in Module files (`.mkape`) to automatically parse collected artifacts.
    * **Flexibility:** Can run against live systems (via `kape.exe`) or mounted images/folders (using `--source` flag).
    * **VHD/VHDX Mounting:** Can automatically mount Volume Shadow Copies for historical artifact collection.
* **Official Website/Repository:** [https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kape)
* **Type:** CLI Forensic Artifact Collection & Processing Tool (with optional GUI wrapper - GKAPE)
* **Platform(s):** Windows.
* **Installation:** Download from the Kroll website (requires registration). Extract the archive. Regularly update Targets and Modules from the KapeFiles GitHub repo ([https://github.com/Kroll-Cyber-Security/KapeFiles](https://github.com/Kroll-Cyber-Security/KapeFiles)).
* **Basic Usage Example (CLI):**
    ```bash
    # Collect basic artifacts from C: drive, save to VHDX container, process with default modules, store output in C:\temp\kape_out
    kape.exe --tsource C: --tdest C:\temp\kape_triage --tflush --target BasicCollection --vss true --mdest C:\temp\kape_out --mflush --module !Disabled 

    # Run modules only against previously collected artifacts in a folder
    kape.exe --msource C:\temp\kape_triage\C --mdest C:\temp\kape_out --mflush --module !Disabled 
    ```
* **Alternatives:** Velociraptor (Full endpoint agent), GRR Rapid Response (Endpoint agent), custom collection scripts.
* **Notes/Tips:** KAPE has become an industry standard for rapid triage. Keep Targets/Modules updated. Understand what artifacts different Targets collect. The GUI (GKAPE.exe) simplifies usage for many.

---

## Memory Acquisition Tools

* **Description:** Capturing the contents of volatile memory (RAM) is crucial for malware analysis and incident response, as RAM contains running processes, network connections, loaded drivers, command history, encryption keys, and other evidence that is lost when a system powers down. Various tools specialize in acquiring memory dumps. Volatility then analyzes these dumps.
* **Key Features/Why it's useful:**
    * Capturing volatile data before it's lost.
    * Providing data for memory analysis tools like Volatility.
    * Enabling analysis of malware that runs only in memory (fileless malware).
* **Examples:**
    * **Belkasoft RAM Capturer:** Free, easy-to-use GUI tool for Windows. ([https://belkasoft.com/ram-capturer](https://belkasoft.com/ram-capturer))
    * **Magnet RAM Capture:** Free GUI/CLI tool for Windows from Magnet Forensics. ([https://www.magnetforensics.com/resources/free-tools/magnet-ram-capture/](https://www.magnetforensics.com/resources/free-tools/magnet-ram-capture/))
    * **FTK Imager:** Includes a memory capture feature for Windows.
    * **DumpIt:** Older, but simple CLI tool for Windows memory acquisition.
    * **Linux:** `dd` (use carefully!), LiME (Loadable Kernel Module).
    * **macOS:** `sudo pmset dumpstate` or specialized tools.
* **Type:** Memory Acquisition Utility (GUI/CLI)
* **Platform(s):** Primarily Windows for popular free tools; specific tools/methods exist for Linux/macOS.
* **Installation:** Varies by tool (often standalone executables for Windows).
* **Basic Usage Example (Conceptual):** Run the chosen tool on the live system (with admin privileges), specify an output file path (ideally on an external trusted drive), and initiate the capture.
* **Alternatives:** Depends on OS. Commercial forensic suites often include memory capture.
* **Notes/Tips:** Acquire memory as early as possible during an incident response on a live system. Minimize interaction with the target system while running the capture tool to avoid overwriting evidence. Ensure sufficient space on the destination drive for the memory dump (equal to the amount of RAM).

---

## Plaso / Log2Timeline

* **Description:** A framework for creating "super timelines" in digital forensics. Log2timeline extracts timestamps from a vast array of file types, log files, registry hives, browser history, and other artifacts from a disk image or live system, and Plaso stores and allows querying/filtering of this aggregated timeline data.
* **Key Features/Why it's useful:**
    * **Comprehensive Timestamp Extraction:** Gathers timestamps from hundreds of artifact types.
    * **Event Correlation:** Helps correlate activity across different data sources based on time.
    * **Building Case Timelines:** Essential for understanding the sequence of events during an incident.
    * **Filtering & Searching:** Plaso (`psort.py`) allows powerful filtering and searching of the aggregated timeline.
* **Official Website/Repository:** [https://github.com/log2timeline/plaso](https://github.com/log2timeline/plaso)
* **Type:** CLI Timeline Creation & Analysis Framework
* **Platform(s):** Linux, macOS, Windows.
* **Installation:** Via pip or packages (can have many dependencies). Docker images often available.
    ```bash
    pip install plaso
    # Or follow OS-specific instructions on project page
    ```
* **Basic Usage Example:**
    ```bash
    # Create a Plaso storage file from a disk image
    log2timeline.py plaso_output.plaso /path/to/disk_image.dd

    # Sort/filter the timeline and output to CSV (e.g., events between two dates)
    psort.py -o csv -w timeline.csv plaso_output.plaso "date > '2024-01-15 10:00:00' AND date < '2024-01-15 12:00:00'"
    ```
* **Alternatives:** Autopsy Timeline feature, Timeline Explorer (GUI for CSV/Bodyfile timelines), commercial forensic suite timelines (EnCase, X-Ways).
* **Notes/Tips:** Processing large images can take significant time and resources. Learning `psort.py` filtering syntax is key. Output can be voluminous; filtering is essential.

---

## Sleuth Kit

* **Description:** A collection of command-line tools and a C library that allows for forensic analysis of disk images and file systems. It forms the underlying engine for many other forensic tools, including Autopsy. It provides granular access to file system data structures, deleted files, and metadata.
* **Key Features/Why it's useful:**
    * **Deep File System Analysis:** Tools to analyze NTFS, FAT, Ext3/4, HFS+, APFS, and other file system structures in detail.
    * **Deleted File Recovery:** Can carve files from unallocated space or examine file system structures for deleted entries.
    * **Metadata Examination:** Tools like `istat` show detailed metadata for files/inodes.
    * **Timeline Generation:** `fls` and `mactime` tools can generate timelines of file system activity (MAC times).
    * **Command-Line Power:** Ideal for scripting and automated analysis.
* **Official Website/Repository:** [https://www.sleuthkit.org/](https://www.sleuthkit.org/) / [https://github.com/sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit)
* **Type:** CLI Digital Forensics Toolkit / Library
* **Platform(s):** Linux, macOS, Windows, BSD.
* **Installation:** Via package managers or source compilation. Often included in security/forensics Linux distributions.
    ```bash
    # Debian/Ubuntu
    sudo apt install sleuthkit
    # macOS (Homebrew)
    brew install sleuthkit
    ```
* **Basic Usage Example:** (Run against a disk image, e.g., `image.dd`)
    ```bash
    # List file system type
    fsstat image.dd

    # List files and directories (like ls)
    fls image.dd

    # Display details about a specific inode/file
    istat image.dd <inode_number>

    # Extract a specific file by inode number
    icat image.dd <inode_number> > extracted_file

    # Generate a MAC time bodyfile for timeline analysis
    fls -r -m / image.dd > bodyfile.txt
    mactime -b bodyfile.txt > timeline.csv
    ```
* **Alternatives:** Autopsy (GUI front-end), commercial forensic suites.
* **Notes/Tips:** Powerful but requires understanding file system concepts. Often used in conjunction with other tools or scripts. Autopsy provides an easier way to access much of its functionality.

---

## StegAnalyzer

* **Description:** A tool designed for detecting information hidden using steganography within image files. It applies various algorithms and statistical analyses to identify potential hidden data payloads.
* **Key Features/Why it's useful:**
    * Detecting the presence of hidden data within images, which could be used by attackers for data exfiltration or covert communication.
    * Applying specific steganography detection algorithms (e.g., LSB analysis).
* **Official Website/Repository:** (Note: Seems less actively maintained or easily findable than others. Often found within older security tool collections or specific academic projects. Example reference: [https://github.com/DominicBreuker/stego-tools](https://github.com/DominicBreuker/stego-tools) lists related tools). Need to verify specific "StegAnalyzer" source if possible, or generalize to "Steganalysis Tools". Let's keep it generic for now.
* **Type:** Steganalysis Tool (Often CLI or specific GUI)
* **Platform(s):** Varies depending on the specific tool (Often Linux, Windows).
* **Installation:** Varies greatly.
* **Basic Usage Example:** (Conceptual)
    ```bash
    # Example assuming a CLI tool
    steganalyzer --input image.png --method lsb_analysis
    ```
* **Alternatives:** StegDetect, StegExpose, Aletheia (framework), online steganalysis tools. Manual inspection with image editors (checking LSB planes).
* **Notes/Tips:** Steganalysis is a complex field. No single tool detects all forms of steganography. Often involves comparing potential stego images against known clean originals if available.

---

## Volatility / Volatility 3

* **Description:** The premier open-source framework for volatile memory (RAM) analysis. It allows examiners to extract digital artifacts from memory dumps, providing insights into running processes, network connections, loaded modules, registry keys accessed, command history, passwords/hashes, injected code, and much more. Volatility 3 is the newer, Python 3 based version.
* **Key Features/Why it's useful:**
    * Analyzing system state at the time of memory capture.
    * Finding evidence of malware execution (processes, DLLs, network activity) even if it's fileless.
    * Extracting running processes, open network sockets, loaded kernel modules.
    * Recovering command history (cmd, PowerShell).
    * Dumping password hashes or potentially cleartext credentials from memory.
    * Identifying injected code or rootkit activity.
* **Official Website/Repository:** [https://www.volatilityfoundation.org/](https://www.volatilityfoundation.org/), [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility) (Legacy Volatility 2), [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) (Volatility 3)
* **Type:** CLI Memory Forensics Framework
* **Platform(s):** Python based - Runs on Linux, macOS, Windows.
* **Installation:** Requires Python. Use `pip` or download releases. Volatility 3 is generally recommended for modern OS support.
    ```bash
    # Volatility 3 (Recommended)
    pip install volatility3
    # Needs symbol packs for specific OS versions - see documentation

    # Volatility 2 (Legacy)
    # Download/clone repo, install dependencies (see docs)
    ```
* **Basic Usage Example (Volatility 3):**
    ```bash
    # List running processes from a Windows memory dump
    python3 vol.py -f memory_dump.vmem windows.pslist.PsList

    # List network connections
    python3 vol.py -f memory_dump.vmem windows.netscan.NetScan

    # Dump password hashes (requires system/sam hives potentially)
    python3 vol.py -f memory_dump.vmem windows.hashdump.Hashdump

    # Check for command line history
    python3 vol.py -f memory_dump.vmem windows.cmdline.CmdLine
    ```
* **Alternatives:** Rekall (Similar memory analysis framework, less active recently), commercial tools (Magnet AXIOM, EnCase).
* **Notes/Tips:** Requires an accurate profile/symbols for the operating system version the memory dump came from. Volatility 3 aims to automate profile detection. Output can be extensive; pipe through `grep` or use Volatility plugins that filter/format output. Essential tool for malware analysis and IR.

---

## X-Ways Forensics

* **Description:** A powerful, commercial, Windows-based software application for digital forensics and data recovery. Known for its speed, efficiency in handling large datasets, and comprehensive feature set for analyzing disk images, memory dumps, and file systems.
* **Key Features/Why it's useful:**
    * Fast and efficient processing of large disk images.
    * Robust file system analysis (including finding deleted files, alternate data streams).
    * Powerful keyword searching and indexing capabilities.
    * Built-in file viewers for numerous formats.
    * Registry viewing and analysis.
    * Memory analysis capabilities.
    * Case management and reporting features.
* **Official Website/Repository:** [https://www.x-ways.net/forensics/](https://www.x-ways.net/forensics/)
* **Type:** Commercial Digital Forensics Suite (GUI)
* **Platform(s):** Windows.
* **Installation:** Purchase license and download from the official website. Requires a license dongle or activation.
* **Basic Usage Example:** Create/open case, add evidence items (images, drives), allow processing to complete, then use integrated tools to browse files, search keywords, filter by criteria, view timelines, analyze registry/memory, and generate reports.
* **Alternatives:** EnCase (Commercial), Magnet AXIOM (Commercial), Autopsy (Open Source), FTK Suite (Commercial).
* **Notes/Tips:** Widely used in law enforcement and corporate DFIR. Known for its performance and low-level data access capabilities. Steeper learning curve compared to some GUI tools. Requires purchasing a license.

---