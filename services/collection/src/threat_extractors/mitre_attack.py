"""
MITRE ATT&CK Framework Mapping

Comprehensive mapping of MITRE ATT&CK techniques to tactics.
Based on MITRE ATT&CK v14 (2024).

This module provides structured data for mapping technique IDs to:
- Technique names
- Tactics (Initial Access, Execution, Persistence, etc.)
- Sub-technique details
- Detection methods
- Mitigations

References:
- https://attack.mitre.org/
- https://attack.mitre.org/matrices/enterprise/
"""

from typing import Dict, List, Optional, Tuple

# Mapping of technique ID to (name, primary_tactic, detection_methods, mitigations)
MITRE_TECHNIQUES: Dict[str, Tuple[str, str, List[str], List[str]]] = {
    # ========================================================================
    # RECONNAISSANCE
    # ========================================================================
    "T1595": (
        "Active Scanning",
        "Reconnaissance",
        ["Monitor for suspicious network scans", "Analyze external network traffic"],
        ["Network Intrusion Prevention", "Pre-compromise"],
    ),
    "T1592": (
        "Gather Victim Host Information",
        "Reconnaissance",
        ["Monitor for enumeration activities"],
        ["Pre-compromise"],
    ),
    "T1589": (
        "Gather Victim Identity Information",
        "Reconnaissance",
        ["Monitor for reconnaissance activities"],
        ["Pre-compromise"],
    ),
    "T1590": (
        "Gather Victim Network Information",
        "Reconnaissance",
        ["Monitor for network reconnaissance"],
        ["Pre-compromise"],
    ),
    # ========================================================================
    # RESOURCE DEVELOPMENT
    # ========================================================================
    "T1583": (
        "Acquire Infrastructure",
        "Resource Development",
        ["Monitor domain registrations", "Track infrastructure acquisition"],
        ["Pre-compromise"],
    ),
    "T1586": (
        "Compromise Accounts",
        "Resource Development",
        ["Monitor for compromised credentials"],
        ["User Account Management", "Multi-factor Authentication"],
    ),
    "T1587": (
        "Develop Capabilities",
        "Resource Development",
        ["Threat intelligence monitoring"],
        ["Pre-compromise"],
    ),
    # ========================================================================
    # INITIAL ACCESS
    # ========================================================================
    "T1189": (
        "Drive-by Compromise",
        "Initial Access",
        ["Web proxy monitoring", "Browser exploit detection"],
        ["Application Isolation", "Exploit Protection"],
    ),
    "T1190": (
        "Exploit Public-Facing Application",
        "Initial Access",
        ["Monitor application logs", "IDS/IPS alerts", "Vulnerability scanning"],
        ["Application Isolation", "Update Software", "Network Segmentation"],
    ),
    "T1133": (
        "External Remote Services",
        "Initial Access",
        ["Monitor VPN/RDP connections", "Analyze authentication logs"],
        ["Multi-factor Authentication", "Network Segmentation"],
    ),
    "T1200": (
        "Hardware Additions",
        "Initial Access",
        ["Monitor USB device connections", "Asset management"],
        ["Disable or Remove Feature", "Limit Hardware Installation"],
    ),
    "T1566": (
        "Phishing",
        "Initial Access",
        ["Email gateway analysis", "User reporting", "Sandbox execution"],
        ["User Training", "Email Security", "Antivirus/Antimalware"],
    ),
    "T1091": (
        "Replication Through Removable Media",
        "Initial Access",
        ["Monitor USB device usage", "Autorun detection"],
        ["Disable or Remove Feature", "Limit Hardware Installation"],
    ),
    "T1195": (
        "Supply Chain Compromise",
        "Initial Access",
        ["Software composition analysis", "Vendor security assessment"],
        ["Update Software", "Vulnerability Scanning"],
    ),
    "T1199": (
        "Trusted Relationship",
        "Initial Access",
        ["Monitor third-party access", "Network traffic analysis"],
        ["Network Segmentation", "User Account Management"],
    ),
    "T1078": (
        "Valid Accounts",
        "Initial Access",
        ["Monitor authentication logs", "Anomalous login detection"],
        ["Multi-factor Authentication", "Privileged Account Management"],
    ),
    # ========================================================================
    # EXECUTION
    # ========================================================================
    "T1059": (
        "Command and Scripting Interpreter",
        "Execution",
        ["Process monitoring", "Script execution logging", "PowerShell logging"],
        ["Execution Prevention", "Disable or Remove Feature"],
    ),
    "T1059.001": (
        "PowerShell",
        "Execution",
        ["PowerShell logging", "Script block logging", "AMSI monitoring"],
        ["Execution Prevention", "Code Signing", "Disable or Remove Feature"],
    ),
    "T1059.003": (
        "Windows Command Shell",
        "Execution",
        ["Command-line logging", "Process monitoring"],
        ["Execution Prevention"],
    ),
    "T1059.005": (
        "Visual Basic",
        "Execution",
        ["Macro execution monitoring", "VBA logging"],
        ["Disable or Remove Feature", "Antivirus/Antimalware"],
    ),
    "T1059.006": (
        "Python",
        "Execution",
        ["Process monitoring", "Script execution detection"],
        ["Execution Prevention"],
    ),
    "T1059.007": (
        "JavaScript",
        "Execution",
        ["Script execution monitoring", "Browser monitoring"],
        ["Execution Prevention", "Disable or Remove Feature"],
    ),
    "T1203": (
        "Exploitation for Client Execution",
        "Execution",
        ["Exploit detection", "Memory forensics"],
        ["Application Isolation", "Exploit Protection"],
    ),
    "T1559": (
        "Inter-Process Communication",
        "Execution",
        ["IPC monitoring", "COM object tracking"],
        ["Execution Prevention"],
    ),
    "T1106": (
        "Native API",
        "Execution",
        ["API call monitoring", "System call tracking"],
        ["Execution Prevention"],
    ),
    "T1053": (
        "Scheduled Task/Job",
        "Execution",
        ["Task scheduler monitoring", "Cron job auditing"],
        ["User Account Management", "Privileged Account Management"],
    ),
    "T1129": (
        "Shared Modules",
        "Execution",
        ["DLL loading monitoring", "Module analysis"],
        ["Execution Prevention"],
    ),
    "T1204": (
        "User Execution",
        "Execution",
        ["User activity monitoring", "File execution tracking"],
        ["User Training", "Execution Prevention"],
    ),
    "T1047": (
        "Windows Management Instrumentation",
        "Execution",
        ["WMI event monitoring", "WMI query logging"],
        ["Privileged Account Management", "User Account Management"],
    ),
    # ========================================================================
    # PERSISTENCE
    # ========================================================================
    "T1098": (
        "Account Manipulation",
        "Persistence",
        ["Account change monitoring", "Privilege escalation detection"],
        ["Multi-factor Authentication", "Privileged Account Management"],
    ),
    "T1197": (
        "BITS Jobs",
        "Persistence",
        ["BITS job monitoring", "Network transfer analysis"],
        ["User Account Management", "Operating System Configuration"],
    ),
    "T1547": (
        "Boot or Logon Autostart Execution",
        "Persistence",
        ["Registry monitoring", "Startup folder analysis"],
        ["User Account Management"],
    ),
    "T1037": (
        "Boot or Logon Initialization Scripts",
        "Persistence",
        ["Script execution monitoring", "Logon script analysis"],
        ["Restrict File and Directory Permissions"],
    ),
    "T1176": (
        "Browser Extensions",
        "Persistence",
        ["Extension installation monitoring"],
        ["User Training", "Audit"],
    ),
    "T1136": (
        "Create Account",
        "Persistence",
        ["Account creation monitoring", "Authentication log analysis"],
        ["Multi-factor Authentication", "Privileged Account Management"],
    ),
    "T1543": (
        "Create or Modify System Process",
        "Persistence",
        ["Service creation monitoring", "Driver installation tracking"],
        ["User Account Management", "Privileged Account Management"],
    ),
    "T1546": (
        "Event Triggered Execution",
        "Persistence",
        ["WMI event monitoring", "Trap monitoring"],
        ["Execution Prevention"],
    ),
    "T1574": (
        "Hijack Execution Flow",
        "Persistence",
        ["DLL search order monitoring", "PATH analysis"],
        ["Execution Prevention", "Restrict File and Directory Permissions"],
    ),
    "T1525": (
        "Implant Internal Image",
        "Persistence",
        ["Container image analysis", "VM template monitoring"],
        ["Code Signing", "Privileged Account Management"],
    ),
    # ========================================================================
    # PRIVILEGE ESCALATION
    # ========================================================================
    "T1548": (
        "Abuse Elevation Control Mechanism",
        "Privilege Escalation",
        ["UAC bypass detection", "Sudo usage monitoring"],
        ["Privileged Account Management", "User Account Control"],
    ),
    "T1134": (
        "Access Token Manipulation",
        "Privilege Escalation",
        ["Token usage monitoring", "API call analysis"],
        ["Privileged Account Management", "User Account Management"],
    ),
    "T1068": (
        "Exploitation for Privilege Escalation",
        "Privilege Escalation",
        ["Exploit detection", "Vulnerability scanning"],
        ["Update Software", "Exploit Protection"],
    ),
    "T1055": (
        "Process Injection",
        "Privilege Escalation",
        ["Memory analysis", "DLL injection detection", "Process hollowing detection"],
        ["Behavior Prevention on Endpoint"],
    ),
    "T1055.001": (
        "Dynamic-link Library Injection",
        "Privilege Escalation",
        ["DLL injection monitoring", "Process analysis"],
        ["Behavior Prevention on Endpoint"],
    ),
    "T1055.012": (
        "Process Hollowing",
        "Privilege Escalation",
        ["Memory forensics", "Process creation monitoring"],
        ["Behavior Prevention on Endpoint"],
    ),
    "T1078": (
        "Valid Accounts",
        "Privilege Escalation",
        ["Authentication monitoring", "Privilege usage tracking"],
        ["Multi-factor Authentication", "Privileged Account Management"],
    ),
    # ========================================================================
    # DEFENSE EVASION
    # ========================================================================
    "T1548": (
        "Abuse Elevation Control Mechanism",
        "Defense Evasion",
        ["UAC event monitoring", "Privilege escalation detection"],
        ["Execution Prevention", "Privileged Account Management"],
    ),
    "T1140": (
        "Deobfuscate/Decode Files or Information",
        "Defense Evasion",
        ["Script analysis", "Encoding detection"],
        ["Antivirus/Antimalware"],
    ),
    "T1006": (
        "Direct Volume Access",
        "Defense Evasion",
        ["Volume access monitoring", "Raw disk read detection"],
        ["User Account Management"],
    ),
    "T1484": (
        "Domain Policy Modification",
        "Defense Evasion",
        ["Group Policy change monitoring", "AD auditing"],
        ["Privileged Account Management", "User Account Management"],
    ),
    "T1562": (
        "Impair Defenses",
        "Defense Evasion",
        ["Security tool tampering detection", "Service modification monitoring"],
        ["Restrict File and Directory Permissions", "User Account Management"],
    ),
    "T1562.001": (
        "Disable or Modify Tools",
        "Defense Evasion",
        ["Security software monitoring", "Service change detection"],
        ["Restrict File and Directory Permissions"],
    ),
    "T1070": (
        "Indicator Removal",
        "Defense Evasion",
        ["Log deletion monitoring", "File deletion tracking"],
        ["Encrypt Sensitive Information", "Restrict File and Directory Permissions"],
    ),
    "T1202": (
        "Indirect Command Execution",
        "Defense Evasion",
        ["Process chain analysis", "Parent-child relationship monitoring"],
        ["Execution Prevention"],
    ),
    "T1564": (
        "Hide Artifacts",
        "Defense Evasion",
        ["Hidden file detection", "Registry monitoring"],
        ["Operating System Configuration"],
    ),
    "T1564.001": (
        "Hidden Files and Directories",
        "Defense Evasion",
        ["File attribute monitoring", "Hidden file scanning"],
        ["Operating System Configuration"],
    ),
    "T1564.003": (
        "Hidden Window",
        "Defense Evasion",
        ["Window visibility monitoring", "Process analysis"],
        ["Execution Prevention"],
    ),
    "T1036": (
        "Masquerading",
        "Defense Evasion",
        ["File name analysis", "Process name monitoring"],
        ["Code Signing", "Execution Prevention"],
    ),
    "T1112": (
        "Modify Registry",
        "Defense Evasion",
        ["Registry change monitoring", "Registry key analysis"],
        ["Restrict Registry Permissions"],
    ),
    "T1027": (
        "Obfuscated Files or Information",
        "Defense Evasion",
        ["File analysis", "Entropy detection", "Packing detection"],
        ["Antivirus/Antimalware"],
    ),
    "T1620": (
        "Reflective Code Loading",
        "Defense Evasion",
        ["Memory analysis", "Reflective DLL detection"],
        ["Behavior Prevention on Endpoint"],
    ),
    "T1553": (
        "Subvert Trust Controls",
        "Defense Evasion",
        ["Certificate validation monitoring", "Code signing analysis"],
        ["Code Signing", "Execution Prevention"],
    ),
    "T1218": (
        "System Binary Proxy Execution",
        "Defense Evasion",
        ["Process monitoring", "LOLBin detection"],
        ["Execution Prevention"],
    ),
    "T1216": (
        "System Script Proxy Execution",
        "Defense Evasion",
        ["Script execution monitoring"],
        ["Execution Prevention"],
    ),
    "T1497": (
        "Virtualization/Sandbox Evasion",
        "Defense Evasion",
        ["VM detection attempts", "Sandbox bypass detection"],
        ["Antivirus/Antimalware"],
    ),
    # ========================================================================
    # CREDENTIAL ACCESS
    # ========================================================================
    "T1110": (
        "Brute Force",
        "Credential Access",
        ["Failed login monitoring", "Account lockout detection"],
        ["Multi-factor Authentication", "Account Use Policies"],
    ),
    "T1555": (
        "Credentials from Password Stores",
        "Credential Access",
        ["Password manager access monitoring", "Credential store access"],
        ["Password Policies", "User Training"],
    ),
    "T1212": (
        "Exploitation for Credential Access",
        "Credential Access",
        ["Exploit detection", "Memory dumps"],
        ["Update Software", "Privileged Account Management"],
    ),
    "T1187": (
        "Forced Authentication",
        "Credential Access",
        ["SMB traffic monitoring", "Authentication request analysis"],
        ["Filter Network Traffic"],
    ),
    "T1056": (
        "Input Capture",
        "Credential Access",
        ["Keylogger detection", "Input monitoring"],
        ["User Training"],
    ),
    "T1056.001": (
        "Keylogging",
        "Credential Access",
        ["Keystroke logging detection", "Process monitoring"],
        ["User Training", "Antivirus/Antimalware"],
    ),
    "T1111": (
        "Multi-Factor Authentication Interception",
        "Credential Access",
        ["MFA token monitoring", "Authentication flow analysis"],
        ["Multi-factor Authentication"],
    ),
    "T1621": (
        "Multi-Factor Authentication Request Generation",
        "Credential Access",
        ["MFA request monitoring", "Push notification analysis"],
        ["User Training", "Multi-factor Authentication"],
    ),
    "T1040": (
        "Network Sniffing",
        "Credential Access",
        ["Promiscuous mode detection", "Packet capture detection"],
        ["Encrypt Sensitive Information", "User Account Management"],
    ),
    "T1003": (
        "OS Credential Dumping",
        "Credential Access",
        ["LSASS access monitoring", "SAM database access", "Credential dump detection"],
        ["Privileged Account Management", "Password Policies"],
    ),
    "T1003.001": (
        "LSASS Memory",
        "Credential Access",
        ["LSASS process access", "Memory dump detection"],
        ["Privileged Account Management", "Credential Access Protection"],
    ),
    "T1003.002": (
        "Security Account Manager",
        "Credential Access",
        ["SAM database access", "Registry access monitoring"],
        ["Privileged Account Management"],
    ),
    "T1003.003": (
        "NTDS",
        "Credential Access",
        ["NTDS.dit access monitoring", "Volume Shadow Copy detection"],
        ["Privileged Account Management", "Active Directory Configuration"],
    ),
    "T1528": (
        "Steal Application Access Token",
        "Credential Access",
        ["OAuth token monitoring", "API token usage"],
        ["User Account Management"],
    ),
    "T1558": (
        "Steal or Forge Kerberos Tickets",
        "Credential Access",
        ["Kerberos ticket monitoring", "Golden/Silver ticket detection"],
        ["Active Directory Configuration", "Privileged Account Management"],
    ),
    "T1539": (
        "Steal Web Session Cookie",
        "Credential Access",
        ["Cookie theft detection", "Browser monitoring"],
        ["Multi-factor Authentication", "Software Configuration"],
    ),
    "T1552": (
        "Unsecured Credentials",
        "Credential Access",
        ["Credential file scanning", "Configuration review"],
        ["Password Policies", "Audit"],
    ),
    # ========================================================================
    # DISCOVERY
    # ========================================================================
    "T1087": (
        "Account Discovery",
        "Discovery",
        ["Account enumeration detection", "AD query monitoring"],
        ["Operating System Configuration"],
    ),
    "T1010": (
        "Application Window Discovery",
        "Discovery",
        ["Window enumeration monitoring"],
        [],
    ),
    "T1217": (
        "Browser Bookmark Discovery",
        "Discovery",
        ["Browser data access monitoring"],
        [],
    ),
    "T1580": (
        "Cloud Infrastructure Discovery",
        "Discovery",
        ["Cloud API monitoring", "Metadata service access"],
        ["User Account Management"],
    ),
    "T1538": (
        "Cloud Service Dashboard",
        "Discovery",
        ["Console access monitoring"],
        ["User Account Management", "Multi-factor Authentication"],
    ),
    "T1526": (
        "Cloud Service Discovery",
        "Discovery",
        ["Cloud API enumeration"],
        ["User Account Management"],
    ),
    "T1613": (
        "Container and Resource Discovery",
        "Discovery",
        ["Container enumeration", "Kubernetes API monitoring"],
        ["User Account Management"],
    ),
    "T1083": (
        "File and Directory Discovery",
        "Discovery",
        ["File enumeration monitoring", "Directory traversal detection"],
        ["Operating System Configuration"],
    ),
    "T1046": (
        "Network Service Discovery",
        "Discovery",
        ["Port scanning detection", "Service enumeration"],
        ["Network Intrusion Prevention"],
    ),
    "T1135": (
        "Network Share Discovery",
        "Discovery",
        ["Share enumeration detection", "SMB monitoring"],
        ["Network Segmentation", "Operating System Configuration"],
    ),
    "T1040": (
        "Network Sniffing",
        "Discovery",
        ["Promiscuous mode detection"],
        ["User Account Management"],
    ),
    "T1201": (
        "Password Policy Discovery",
        "Discovery",
        ["Policy query monitoring"],
        [],
    ),
    "T1120": (
        "Peripheral Device Discovery",
        "Discovery",
        ["Device enumeration monitoring"],
        [],
    ),
    "T1069": (
        "Permission Groups Discovery",
        "Discovery",
        ["Group enumeration", "Privilege query monitoring"],
        [],
    ),
    "T1057": (
        "Process Discovery",
        "Discovery",
        ["Process enumeration monitoring", "Task list analysis"],
        [],
    ),
    "T1012": (
        "Query Registry",
        "Discovery",
        ["Registry query monitoring"],
        [],
    ),
    "T1018": (
        "Remote System Discovery",
        "Discovery",
        ["Network scanning", "Host discovery"],
        ["Network Intrusion Prevention"],
    ),
    "T1518": (
        "Software Discovery",
        "Discovery",
        ["Software enumeration monitoring"],
        [],
    ),
    "T1082": (
        "System Information Discovery",
        "Discovery",
        ["System information queries", "Enumeration detection"],
        [],
    ),
    "T1016": (
        "System Network Configuration Discovery",
        "Discovery",
        ["Network configuration queries"],
        [],
    ),
    "T1049": (
        "System Network Connections Discovery",
        "Discovery",
        ["Network connection enumeration"],
        [],
    ),
    "T1033": (
        "System Owner/User Discovery",
        "Discovery",
        ["User enumeration", "Whoami execution"],
        [],
    ),
    "T1007": (
        "System Service Discovery",
        "Discovery",
        ["Service enumeration monitoring"],
        [],
    ),
    "T1124": (
        "System Time Discovery",
        "Discovery",
        ["Time query monitoring"],
        [],
    ),
    # ========================================================================
    # LATERAL MOVEMENT
    # ========================================================================
    "T1210": (
        "Exploitation of Remote Services",
        "Lateral Movement",
        ["Exploit detection", "Remote service monitoring"],
        ["Network Segmentation", "Update Software"],
    ),
    "T1534": (
        "Internal Spearphishing",
        "Lateral Movement",
        ["Internal email monitoring"],
        ["User Training"],
    ),
    "T1570": (
        "Lateral Tool Transfer",
        "Lateral Movement",
        ["File transfer monitoring", "Network share activity"],
        ["Network Segmentation"],
    ),
    "T1021": (
        "Remote Services",
        "Lateral Movement",
        ["RDP/SSH monitoring", "Remote access detection"],
        ["Multi-factor Authentication", "Network Segmentation"],
    ),
    "T1021.001": (
        "Remote Desktop Protocol",
        "Lateral Movement",
        ["RDP connection monitoring", "Authentication analysis"],
        ["Multi-factor Authentication", "Disable or Remove Feature"],
    ),
    "T1021.002": (
        "SMB/Windows Admin Shares",
        "Lateral Movement",
        ["Admin share usage monitoring", "SMB traffic analysis"],
        ["Password Policies", "Privileged Account Management"],
    ),
    "T1021.004": (
        "SSH",
        "Lateral Movement",
        ["SSH connection monitoring", "Key-based authentication tracking"],
        ["Multi-factor Authentication", "Disable or Remove Feature"],
    ),
    "T1021.006": (
        "Windows Remote Management",
        "Lateral Movement",
        ["WinRM usage monitoring", "PowerShell remoting"],
        ["Privileged Account Management", "Disable or Remove Feature"],
    ),
    "T1091": (
        "Replication Through Removable Media",
        "Lateral Movement",
        ["USB device monitoring", "Removable media scanning"],
        ["Disable or Remove Feature"],
    ),
    "T1072": (
        "Software Deployment Tools",
        "Lateral Movement",
        ["SCCM/deployment tool monitoring"],
        ["Privileged Account Management", "User Account Management"],
    ),
    "T1080": (
        "Taint Shared Content",
        "Lateral Movement",
        ["Shared folder monitoring", "File modification tracking"],
        ["Restrict File and Directory Permissions"],
    ),
    # ========================================================================
    # COLLECTION
    # ========================================================================
    "T1557": (
        "Adversary-in-the-Middle",
        "Collection",
        ["ARP spoofing detection", "SSL/TLS interception"],
        ["Encrypt Sensitive Information", "Network Intrusion Prevention"],
    ),
    "T1560": (
        "Archive Collected Data",
        "Collection",
        ["Archive creation monitoring", "Compression tool usage"],
        [],
    ),
    "T1123": (
        "Audio Capture",
        "Collection",
        ["Microphone access monitoring", "Audio recording detection"],
        ["User Training"],
    ),
    "T1119": (
        "Automated Collection",
        "Collection",
        ["Automated data gathering detection"],
        [],
    ),
    "T1185": (
        "Browser Session Hijacking",
        "Collection",
        ["Browser monitoring", "Session token analysis"],
        ["Multi-factor Authentication"],
    ),
    "T1115": (
        "Clipboard Data",
        "Collection",
        ["Clipboard monitoring", "Data access detection"],
        [],
    ),
    "T1530": (
        "Data from Cloud Storage",
        "Collection",
        ["Cloud storage access monitoring"],
        ["User Account Management", "Audit"],
    ),
    "T1602": (
        "Data from Configuration Repository",
        "Collection",
        ["Configuration access monitoring"],
        ["Network Segmentation", "User Account Management"],
    ),
    "T1213": (
        "Data from Information Repositories",
        "Collection",
        ["Repository access monitoring", "SharePoint/Confluence access"],
        ["User Account Management", "Audit"],
    ),
    "T1005": (
        "Data from Local System",
        "Collection",
        ["File access monitoring", "Local data collection"],
        ["Data Loss Prevention"],
    ),
    "T1039": (
        "Data from Network Shared Drive",
        "Collection",
        ["Network share access", "File transfer monitoring"],
        ["Data Loss Prevention"],
    ),
    "T1025": (
        "Data from Removable Media",
        "Collection",
        ["Removable media access"],
        ["Data Loss Prevention"],
    ),
    "T1114": (
        "Email Collection",
        "Collection",
        ["Email access monitoring", "Mailbox access"],
        ["Audit", "Multi-factor Authentication"],
    ),
    "T1056": (
        "Input Capture",
        "Collection",
        ["Input monitoring", "Keylogger detection"],
        ["User Training"],
    ),
    "T1113": (
        "Screen Capture",
        "Collection",
        ["Screenshot detection", "Screen recording monitoring"],
        ["User Training"],
    ),
    "T1125": (
        "Video Capture",
        "Collection",
        ["Camera access monitoring", "Video recording detection"],
        ["User Training"],
    ),
    # ========================================================================
    # COMMAND AND CONTROL
    # ========================================================================
    "T1071": (
        "Application Layer Protocol",
        "Command and Control",
        ["Protocol analysis", "Anomalous HTTP/HTTPS traffic", "DNS monitoring"],
        ["Network Intrusion Prevention", "Network Segmentation"],
    ),
    "T1071.001": (
        "Web Protocols",
        "Command and Control",
        ["HTTP/HTTPS traffic analysis", "Beaconing detection"],
        ["Network Intrusion Prevention", "SSL/TLS Inspection"],
    ),
    "T1071.002": (
        "File Transfer Protocols",
        "Command and Control",
        ["FTP/SFTP monitoring", "File transfer analysis"],
        ["Network Intrusion Prevention"],
    ),
    "T1071.003": (
        "Mail Protocols",
        "Command and Control",
        ["Email traffic monitoring", "SMTP/IMAP analysis"],
        ["Network Intrusion Prevention"],
    ),
    "T1071.004": (
        "DNS",
        "Command and Control",
        ["DNS tunneling detection", "DNS query analysis"],
        ["Network Intrusion Prevention"],
    ),
    "T1092": (
        "Communication Through Removable Media",
        "Command and Control",
        ["Removable media monitoring"],
        ["Disable or Remove Feature"],
    ),
    "T1132": (
        "Data Encoding",
        "Command and Control",
        ["Encoded data detection", "Base64 monitoring"],
        ["Network Intrusion Prevention"],
    ),
    "T1001": (
        "Data Obfuscation",
        "Command and Control",
        ["Traffic pattern analysis", "Steganography detection"],
        ["Network Intrusion Prevention"],
    ),
    "T1568": (
        "Dynamic Resolution",
        "Command and Control",
        ["DGA detection", "Fast flux monitoring"],
        ["Network Intrusion Prevention"],
    ),
    "T1573": (
        "Encrypted Channel",
        "Command and Control",
        ["Encrypted traffic analysis", "SSL/TLS inspection"],
        ["Network Intrusion Prevention", "SSL/TLS Inspection"],
    ),
    "T1008": (
        "Fallback Channels",
        "Command and Control",
        ["Backup C2 detection", "Multiple C2 infrastructure"],
        ["Network Intrusion Prevention"],
    ),
    "T1105": (
        "Ingress Tool Transfer",
        "Command and Control",
        ["File download monitoring", "Tool transfer detection"],
        ["Network Intrusion Prevention"],
    ),
    "T1104": (
        "Multi-Stage Channels",
        "Command and Control",
        ["Multi-hop detection", "Proxy usage"],
        ["Network Segmentation"],
    ),
    "T1095": (
        "Non-Application Layer Protocol",
        "Command and Control",
        ["Custom protocol detection", "Raw socket usage"],
        ["Network Intrusion Prevention"],
    ),
    "T1571": (
        "Non-Standard Port",
        "Command and Control",
        ["Port usage analysis", "Protocol-port mismatch"],
        ["Network Intrusion Prevention", "Network Segmentation"],
    ),
    "T1572": (
        "Protocol Tunneling",
        "Command and Control",
        ["Tunneling detection", "Protocol encapsulation"],
        ["Network Intrusion Prevention"],
    ),
    "T1090": (
        "Proxy",
        "Command and Control",
        ["Proxy usage detection", "Traffic redirection"],
        ["Network Intrusion Prevention", "SSL/TLS Inspection"],
    ),
    "T1219": (
        "Remote Access Software",
        "Command and Control",
        ["Remote access tool detection", "TeamViewer/AnyDesk monitoring"],
        ["Execution Prevention", "Network Intrusion Prevention"],
    ),
    "T1205": (
        "Traffic Signaling",
        "Command and Control",
        ["Port knocking detection", "Magic packet monitoring"],
        ["Network Intrusion Prevention"],
    ),
    "T1102": (
        "Web Service",
        "Command and Control",
        ["Cloud service C2 detection", "API abuse monitoring"],
        ["Network Intrusion Prevention", "Restrict Web-Based Content"],
    ),
    # ========================================================================
    # EXFILTRATION
    # ========================================================================
    "T1020": (
        "Automated Exfiltration",
        "Exfiltration",
        ["Automated transfer detection", "Large data movement"],
        ["Data Loss Prevention"],
    ),
    "T1030": (
        "Data Transfer Size Limits",
        "Exfiltration",
        ["Transfer size analysis", "Chunked data detection"],
        ["Data Loss Prevention"],
    ),
    "T1048": (
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        ["Non-standard protocol monitoring", "Unusual port usage"],
        ["Data Loss Prevention", "Network Intrusion Prevention"],
    ),
    "T1041": (
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        ["C2 traffic analysis", "Data exfiltration detection"],
        ["Data Loss Prevention", "Network Segmentation"],
    ),
    "T1011": (
        "Exfiltration Over Other Network Medium",
        "Exfiltration",
        ["Wireless exfiltration", "Bluetooth monitoring"],
        ["Operating System Configuration"],
    ),
    "T1052": (
        "Exfiltration Over Physical Medium",
        "Exfiltration",
        ["Removable media monitoring", "USB file transfer"],
        ["Data Loss Prevention", "Disable or Remove Feature"],
    ),
    "T1567": (
        "Exfiltration Over Web Service",
        "Exfiltration",
        ["Cloud upload monitoring", "Web service usage"],
        ["Data Loss Prevention", "Restrict Web-Based Content"],
    ),
    "T1029": (
        "Scheduled Transfer",
        "Exfiltration",
        ["Scheduled task monitoring", "Timed transfers"],
        ["Data Loss Prevention"],
    ),
    "T1537": (
        "Transfer Data to Cloud Account",
        "Exfiltration",
        ["Cloud sync monitoring", "Cloud storage uploads"],
        ["Data Loss Prevention", "User Account Management"],
    ),
    # ========================================================================
    # IMPACT
    # ========================================================================
    "T1531": (
        "Account Access Removal",
        "Impact",
        ["Account lockout monitoring", "Password change detection"],
        ["Multi-factor Authentication"],
    ),
    "T1485": (
        "Data Destruction",
        "Impact",
        ["File deletion monitoring", "Disk wiping detection"],
        ["Data Backup"],
    ),
    "T1486": (
        "Data Encrypted for Impact",
        "Impact",
        ["Ransomware detection", "Mass encryption monitoring"],
        ["Data Backup", "Behavior Prevention on Endpoint"],
    ),
    "T1565": (
        "Data Manipulation",
        "Impact",
        ["Data integrity monitoring", "File modification tracking"],
        ["Restrict File and Directory Permissions"],
    ),
    "T1491": (
        "Defacement",
        "Impact",
        ["Website monitoring", "Content change detection"],
        ["Data Backup"],
    ),
    "T1561": (
        "Disk Wipe",
        "Impact",
        ["Disk operation monitoring", "MBR/GPT modification"],
        ["Data Backup"],
    ),
    "T1499": (
        "Endpoint Denial of Service",
        "Impact",
        ["Resource exhaustion", "CPU/memory spike detection"],
        ["Filter Network Traffic"],
    ),
    "T1495": (
        "Firmware Corruption",
        "Impact",
        ["Firmware modification monitoring", "BIOS/UEFI changes"],
        ["Boot Integrity", "Privileged Account Management"],
    ),
    "T1490": (
        "Inhibit System Recovery",
        "Impact",
        ["Backup deletion", "Shadow copy removal", "Recovery disablement"],
        ["Operating System Configuration"],
    ),
    "T1498": (
        "Network Denial of Service",
        "Impact",
        ["DDoS detection", "Traffic flood monitoring"],
        ["Filter Network Traffic"],
    ),
    "T1496": (
        "Resource Hijacking",
        "Impact",
        ["Cryptomining detection", "Unusual CPU usage"],
        ["Behavior Prevention on Endpoint"],
    ),
    "T1489": (
        "Service Stop",
        "Impact",
        ["Service shutdown monitoring", "Critical service disruption"],
        ["User Account Control", "Restrict File and Directory Permissions"],
    ),
    "T1529": (
        "System Shutdown/Reboot",
        "Impact",
        ["Shutdown command monitoring", "Reboot detection"],
        ["User Account Management"],
    ),
}

# Sub-technique names mapping (technique_id -> sub_technique_name)
SUB_TECHNIQUE_NAMES: Dict[str, str] = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1059.006": "Command and Scripting Interpreter: Python",
    "T1059.007": "Command and Scripting Interpreter: JavaScript",
    "T1055.001": "Process Injection: Dynamic-link Library Injection",
    "T1055.012": "Process Injection: Process Hollowing",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1056.001": "Input Capture: Keylogging",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1564.001": "Hide Artifacts: Hidden Files and Directories",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.002": "Application Layer Protocol: File Transfer Protocols",
    "T1071.003": "Application Layer Protocol: Mail Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
}


def get_technique_info(technique_id: str) -> Optional[Dict[str, any]]:
    """
    Get detailed information for a MITRE ATT&CK technique.

    Args:
        technique_id: MITRE technique ID (e.g., "T1059.001")

    Returns:
        Dictionary with technique details or None if not found
    """
    # Extract base technique (without sub-technique)
    base_technique = technique_id.split(".")[0]

    # Get technique info
    if base_technique not in MITRE_TECHNIQUES:
        return None

    name, tactic, detection_methods, mitigations = MITRE_TECHNIQUES[base_technique]

    technique_info = {
        "technique_id": technique_id,
        "technique_name": name,
        "tactic": tactic,
        "sub_technique": None,
        "detection_methods": detection_methods,
        "mitigations": mitigations,
        "reference_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }

    # Add sub-technique name if applicable
    if "." in technique_id:
        if technique_id in SUB_TECHNIQUE_NAMES:
            technique_info["sub_technique"] = SUB_TECHNIQUE_NAMES[technique_id]
        else:
            technique_info["sub_technique"] = f"Sub-technique {technique_id.split('.')[1]}"

    return technique_info


def get_all_techniques() -> List[str]:
    """
    Get list of all supported technique IDs.

    Returns:
        List of technique IDs
    """
    return list(MITRE_TECHNIQUES.keys()) + list(SUB_TECHNIQUE_NAMES.keys())


def get_techniques_by_tactic(tactic: str) -> List[str]:
    """
    Get all techniques for a specific tactic.

    Args:
        tactic: MITRE ATT&CK tactic name

    Returns:
        List of technique IDs for that tactic
    """
    return [
        tech_id
        for tech_id, (_, tech_tactic, _, _) in MITRE_TECHNIQUES.items()
        if tech_tactic == tactic
    ]


def get_all_tactics() -> List[str]:
    """
    Get list of all MITRE ATT&CK tactics.

    Returns:
        Sorted list of unique tactic names
    """
    tactics = set(tactic for _, tactic, _, _ in MITRE_TECHNIQUES.values())
    return sorted(list(tactics))
