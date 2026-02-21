/**
 * Fallback data matching exact Wazuh API response shapes.
 * Used when Wazuh API is not connected. When connected, real API data replaces this seamlessly.
 * Every structure mirrors the actual Wazuh REST API v4.x response format.
 */

// ═══════════════════════════════════════════════════════════════════════
// AGENTS
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_AGENTS = {
  data: {
    affected_items: [
      { id: "001", name: "wazuh-manager", ip: "10.0.0.2", status: "active", os: { name: "Ubuntu", platform: "ubuntu", version: "22.04.3 LTS", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-01-15T08:30:00Z", lastKeepAlive: "2026-02-21T22:00:00Z", group: ["default", "linux-servers"], configSum: "ab73af41699f13fdd81903b5f23d8d00", mergedSum: "f1a9e24e02ba4cc5ea80a9d3feb3bb9a" },
      { id: "002", name: "web-server-prod-01", ip: "10.0.1.10", status: "active", os: { name: "CentOS", platform: "centos", version: "8.5", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-02-10T14:20:00Z", lastKeepAlive: "2026-02-21T21:59:00Z", group: ["default", "web-servers", "pci-dss"], configSum: "cd93af41699f13fdd81903b5f23d8d11", mergedSum: "a2b9e24e02ba4cc5ea80a9d3feb3bb8b" },
      { id: "003", name: "db-server-prod-01", ip: "10.0.2.20", status: "active", os: { name: "Red Hat Enterprise Linux", platform: "rhel", version: "9.2", arch: "x86_64" }, version: "Wazuh v4.7.1", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-02-15T09:00:00Z", lastKeepAlive: "2026-02-21T21:58:00Z", group: ["default", "database-servers", "hipaa"], configSum: "ef83af41699f13fdd81903b5f23d8d22", mergedSum: "b3c9e24e02ba4cc5ea80a9d3feb3bb7c" },
      { id: "004", name: "win-dc-01", ip: "10.0.3.5", status: "active", os: { name: "Microsoft Windows Server 2022", platform: "windows", version: "10.0.20348", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-03-01T11:00:00Z", lastKeepAlive: "2026-02-21T22:00:00Z", group: ["default", "windows-servers", "domain-controllers"], configSum: "1234af41699f13fdd81903b5f23d8d33", mergedSum: "c4d9e24e02ba4cc5ea80a9d3feb3bb6d" },
      { id: "005", name: "k8s-worker-01", ip: "10.0.4.100", status: "active", os: { name: "Ubuntu", platform: "ubuntu", version: "20.04.6 LTS", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-03-10T16:30:00Z", lastKeepAlive: "2026-02-21T21:59:00Z", group: ["default", "kubernetes", "containers"], configSum: "5678af41699f13fdd81903b5f23d8d44", mergedSum: "d5e9e24e02ba4cc5ea80a9d3feb3bb5e" },
      { id: "006", name: "mail-server-01", ip: "10.0.5.15", status: "active", os: { name: "Debian GNU/Linux", platform: "debian", version: "12", arch: "x86_64" }, version: "Wazuh v4.7.0", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-04-05T08:00:00Z", lastKeepAlive: "2026-02-21T21:57:00Z", group: ["default", "mail-servers"], configSum: "9012af41699f13fdd81903b5f23d8d55", mergedSum: "e6f9e24e02ba4cc5ea80a9d3feb3bb4f" },
      { id: "007", name: "vpn-gateway-01", ip: "10.0.6.1", status: "active", os: { name: "Ubuntu", platform: "ubuntu", version: "22.04.3 LTS", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-04-20T10:15:00Z", lastKeepAlive: "2026-02-21T22:00:00Z", group: ["default", "network-devices"], configSum: "3456af41699f13fdd81903b5f23d8d66", mergedSum: "f7a9e24e02ba4cc5ea80a9d3feb3bb3a" },
      { id: "008", name: "dev-workstation-01", ip: "10.0.7.50", status: "disconnected", os: { name: "macOS", platform: "darwin", version: "14.3", arch: "arm64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-05-01T13:00:00Z", lastKeepAlive: "2026-02-20T18:30:00Z", group: ["default", "workstations"], configSum: "7890af41699f13fdd81903b5f23d8d77", mergedSum: "a8b9e24e02ba4cc5ea80a9d3feb3bb2b" },
      { id: "009", name: "backup-server-01", ip: "10.0.8.30", status: "active", os: { name: "Ubuntu", platform: "ubuntu", version: "22.04.3 LTS", arch: "x86_64" }, version: "Wazuh v4.7.1", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-05-15T07:45:00Z", lastKeepAlive: "2026-02-21T21:58:00Z", group: ["default", "backup-servers"], configSum: "abcdaf41699f13fdd81903b5f23d8d88", mergedSum: "b9c9e24e02ba4cc5ea80a9d3feb3bb1c" },
      { id: "010", name: "monitoring-01", ip: "10.0.9.10", status: "active", os: { name: "CentOS", platform: "centos", version: "8.5", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-06-01T09:00:00Z", lastKeepAlive: "2026-02-21T22:00:00Z", group: ["default", "monitoring"], configSum: "efghaf41699f13fdd81903b5f23d8d99", mergedSum: "c0d9e24e02ba4cc5ea80a9d3feb3bb0d" },
      { id: "011", name: "firewall-01", ip: "10.0.10.1", status: "active", os: { name: "Ubuntu", platform: "ubuntu", version: "20.04.6 LTS", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2024-06-15T11:30:00Z", lastKeepAlive: "2026-02-21T21:59:00Z", group: ["default", "network-devices", "firewalls"], configSum: "ijklaf41699f13fdd81903b5f23d8daa", mergedSum: "d1e9e24e02ba4cc5ea80a9d3feb3bbfe" },
      { id: "012", name: "win-endpoint-01", ip: "10.0.11.25", status: "never_connected", os: { name: "Microsoft Windows 11", platform: "windows", version: "10.0.22631", arch: "x86_64" }, version: "Wazuh v4.7.2", manager: "wazuh-manager", node_name: "node01", dateAdd: "2026-02-20T14:00:00Z", lastKeepAlive: "1970-01-01T00:00:00Z", group: ["default"], configSum: "mnopaf41699f13fdd81903b5f23d8dbb", mergedSum: "e2f9e24e02ba4cc5ea80a9d3feb3bbef" },
    ],
    total_affected_items: 12,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_AGENT_SUMMARY = {
  data: {
    affected_items: [{ active: 10, disconnected: 1, never_connected: 1, pending: 0, total: 12 }],
    total_affected_items: 1,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// RULES (with MITRE mappings)
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_RULES = {
  data: {
    affected_items: [
      { id: 5710, level: 14, description: "sshd: Attempt to login using a denied user.", groups: ["syslog", "sshd", "authentication_failed"], mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] }, pci_dss: ["10.2.4", "10.2.5"], gdpr: ["IV_35.7.d", "IV_32.2"], hipaa: ["164.312.b"] },
      { id: 5712, level: 10, description: "sshd: brute force trying to get access to the system.", groups: ["syslog", "sshd", "authentication_failed"], mitre: { id: ["T1110.001"], tactic: ["Credential Access"], technique: ["Password Guessing"] }, pci_dss: ["10.2.4", "10.2.5", "11.4"], gdpr: ["IV_35.7.d"], hipaa: ["164.312.b"] },
      { id: 60103, level: 12, description: "Integrity checksum changed.", groups: ["ossec", "syscheck", "syscheck_entry_modified"], mitre: { id: ["T1565.001"], tactic: ["Impact"], technique: ["Stored Data Manipulation"] }, pci_dss: ["11.5"], gdpr: ["II_5.1.f"], hipaa: ["164.312.c.1"] },
      { id: 80791, level: 13, description: "Shellshock attack detected.", groups: ["web", "attack", "shellshock"], mitre: { id: ["T1190"], tactic: ["Initial Access"], technique: ["Exploit Public-Facing Application"] }, pci_dss: ["6.5", "6.6", "11.4"], gdpr: ["IV_35.7.d"], hipaa: [] },
      { id: 87105, level: 15, description: "Windows: Mimikatz detected on system.", groups: ["windows", "attack", "credential_theft"], mitre: { id: ["T1003"], tactic: ["Credential Access"], technique: ["OS Credential Dumping"] }, pci_dss: ["10.2.7", "10.6.1"], gdpr: ["IV_35.7.d"], hipaa: ["164.312.b"] },
      { id: 92655, level: 12, description: "Docker: Container started with privileged mode.", groups: ["docker", "container"], mitre: { id: ["T1610"], tactic: ["Execution"], technique: ["Deploy Container"] }, pci_dss: ["2.2"], gdpr: ["IV_35.7.d"], hipaa: [] },
      { id: 100002, level: 10, description: "Suricata: ET MALWARE Known Malicious User-Agent.", groups: ["ids", "suricata"], mitre: { id: ["T1071.001"], tactic: ["Command and Control"], technique: ["Web Protocols"] }, pci_dss: ["10.6.1", "11.4"], gdpr: ["IV_35.7.d"], hipaa: ["164.312.b"] },
      { id: 550, level: 10, description: "Integrity checksum changed (2nd time).", groups: ["ossec", "syscheck"], mitre: { id: ["T1565.001"], tactic: ["Impact"], technique: ["Stored Data Manipulation"] }, pci_dss: ["11.5"], gdpr: ["II_5.1.f"], hipaa: ["164.312.c.1"] },
      { id: 5501, level: 5, description: "Login session opened.", groups: ["pam", "syslog", "authentication_success"], mitre: { id: ["T1078"], tactic: ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], technique: ["Valid Accounts"] }, pci_dss: ["10.2.5"], gdpr: ["IV_32.2"], hipaa: ["164.312.d"] },
      { id: 5502, level: 3, description: "Login session closed.", groups: ["pam", "syslog"], mitre: { id: [], tactic: [], technique: [] }, pci_dss: ["10.2.5"], gdpr: [], hipaa: [] },
      { id: 18104, level: 12, description: "Windows Audit: Logon failure - Unknown user or bad password.", groups: ["windows", "authentication_failed"], mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] }, pci_dss: ["10.2.4", "10.2.5"], gdpr: ["IV_35.7.d", "IV_32.2"], hipaa: ["164.312.b"] },
      { id: 31104, level: 6, description: "Web server 404 error.", groups: ["web", "accesslog"], mitre: { id: ["T1595.002"], tactic: ["Reconnaissance"], technique: ["Vulnerability Scanning"] }, pci_dss: ["10.6.1"], gdpr: [], hipaa: [] },
      { id: 31105, level: 6, description: "Web server 500 error (Internal Error).", groups: ["web", "accesslog"], mitre: { id: [], tactic: [], technique: [] }, pci_dss: ["10.6.1"], gdpr: [], hipaa: [] },
      { id: 5706, level: 6, description: "OpenSSH: authentication success.", groups: ["syslog", "sshd", "authentication_success"], mitre: { id: ["T1078"], tactic: ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], technique: ["Valid Accounts"] }, pci_dss: ["10.2.5"], gdpr: ["IV_32.2"], hipaa: ["164.312.d"] },
      { id: 5763, level: 10, description: "sshd: Possible SSH scan.", groups: ["syslog", "sshd", "recon"], mitre: { id: ["T1046"], tactic: ["Discovery"], technique: ["Network Service Discovery"] }, pci_dss: ["11.4"], gdpr: ["IV_35.7.d"], hipaa: [] },
    ],
    total_affected_items: 15,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// MANAGER STATUS / INFO / STATS
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_MANAGER_STATUS = {
  data: {
    affected_items: [{
      "wazuh-agentlessd": "stopped",
      "wazuh-analysisd": "running",
      "wazuh-authd": "running",
      "wazuh-csyslogd": "stopped",
      "wazuh-dbd": "stopped",
      "wazuh-execd": "running",
      "wazuh-integratord": "stopped",
      "wazuh-logcollector": "running",
      "wazuh-maild": "stopped",
      "wazuh-monitord": "running",
      "wazuh-remoted": "running",
      "wazuh-reportd": "stopped",
      "wazuh-syscheckd": "running",
      "wazuh-db": "running",
      "wazuh-modulesd": "running",
      "wazuh-clusterd": "running",
    }],
    total_affected_items: 1,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_MANAGER_INFO = {
  data: {
    affected_items: [{
      name: "wazuh-manager",
      version: "v4.7.2",
      compilation_date: "2024-01-15T10:00:00Z",
      type: "manager",
      max_agents: "14000",
      openssl_support: "yes",
      ruleset_version: "4702",
      tz_name: "UTC",
      tz_offset: "+0000",
      path: "/var/ossec",
    }],
    total_affected_items: 1,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_MANAGER_STATS = {
  data: {
    affected_items: [
      { hour: 0, totalall: 1245, events: 980, syscheck: 165, firewall: 100 },
      { hour: 1, totalall: 890, events: 720, syscheck: 110, firewall: 60 },
      { hour: 2, totalall: 650, events: 510, syscheck: 90, firewall: 50 },
      { hour: 3, totalall: 520, events: 400, syscheck: 80, firewall: 40 },
      { hour: 4, totalall: 480, events: 370, syscheck: 70, firewall: 40 },
      { hour: 5, totalall: 610, events: 480, syscheck: 85, firewall: 45 },
      { hour: 6, totalall: 1100, events: 870, syscheck: 150, firewall: 80 },
      { hour: 7, totalall: 2340, events: 1900, syscheck: 280, firewall: 160 },
      { hour: 8, totalall: 3560, events: 2900, syscheck: 410, firewall: 250 },
      { hour: 9, totalall: 4200, events: 3400, syscheck: 500, firewall: 300 },
      { hour: 10, totalall: 4680, events: 3800, syscheck: 550, firewall: 330 },
      { hour: 11, totalall: 4450, events: 3600, syscheck: 530, firewall: 320 },
      { hour: 12, totalall: 3900, events: 3150, syscheck: 470, firewall: 280 },
      { hour: 13, totalall: 4100, events: 3300, syscheck: 500, firewall: 300 },
      { hour: 14, totalall: 4500, events: 3650, syscheck: 540, firewall: 310 },
      { hour: 15, totalall: 4300, events: 3480, syscheck: 520, firewall: 300 },
      { hour: 16, totalall: 3800, events: 3080, syscheck: 460, firewall: 260 },
      { hour: 17, totalall: 3200, events: 2580, syscheck: 390, firewall: 230 },
      { hour: 18, totalall: 2500, events: 2020, syscheck: 300, firewall: 180 },
      { hour: 19, totalall: 2100, events: 1700, syscheck: 250, firewall: 150 },
      { hour: 20, totalall: 1800, events: 1450, syscheck: 220, firewall: 130 },
      { hour: 21, totalall: 1600, events: 1290, syscheck: 200, firewall: 110 },
      { hour: 22, totalall: 1400, events: 1130, syscheck: 180, firewall: 90 },
      { hour: 23, totalall: 1300, events: 1050, syscheck: 170, firewall: 80 },
    ],
    total_affected_items: 24,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_STATS_HOURLY = MOCK_MANAGER_STATS;

// ═══════════════════════════════════════════════════════════════════════
// MANAGER LOGS (alerts proxy)
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_MANAGER_LOGS = {
  data: {
    affected_items: [
      { timestamp: "2026-02-21T21:58:30Z", tag: "wazuh-analysisd", level: "error", description: "Rule 5710 fired (level 14) -> 'sshd: Attempt to login using a denied user.' Agent 002 (web-server-prod-01)" },
      { timestamp: "2026-02-21T21:55:12Z", tag: "wazuh-analysisd", level: "warning", description: "Rule 87105 fired (level 15) -> 'Windows: Mimikatz detected on system.' Agent 004 (win-dc-01)" },
      { timestamp: "2026-02-21T21:52:45Z", tag: "wazuh-analysisd", level: "info", description: "Rule 5501 fired (level 5) -> 'Login session opened.' Agent 003 (db-server-prod-01)" },
      { timestamp: "2026-02-21T21:50:00Z", tag: "wazuh-analysisd", level: "error", description: "Rule 80791 fired (level 13) -> 'Shellshock attack detected.' Agent 002 (web-server-prod-01)" },
      { timestamp: "2026-02-21T21:47:33Z", tag: "wazuh-syscheckd", level: "warning", description: "Rule 60103 fired (level 12) -> 'Integrity checksum changed.' Agent 003 (db-server-prod-01) /etc/shadow" },
      { timestamp: "2026-02-21T21:45:10Z", tag: "wazuh-analysisd", level: "error", description: "Rule 5712 fired (level 10) -> 'sshd: brute force trying to get access to the system.' Agent 007 (vpn-gateway-01)" },
      { timestamp: "2026-02-21T21:42:00Z", tag: "wazuh-analysisd", level: "info", description: "Rule 5706 fired (level 6) -> 'OpenSSH: authentication success.' Agent 005 (k8s-worker-01)" },
      { timestamp: "2026-02-21T21:40:15Z", tag: "wazuh-analysisd", level: "warning", description: "Rule 92655 fired (level 12) -> 'Docker: Container started with privileged mode.' Agent 005 (k8s-worker-01)" },
      { timestamp: "2026-02-21T21:38:22Z", tag: "wazuh-analysisd", level: "error", description: "Rule 100002 fired (level 10) -> 'Suricata: ET MALWARE Known Malicious User-Agent.' Agent 011 (firewall-01)" },
      { timestamp: "2026-02-21T21:35:00Z", tag: "wazuh-analysisd", level: "info", description: "Rule 31104 fired (level 6) -> 'Web server 404 error.' Agent 002 (web-server-prod-01)" },
      { timestamp: "2026-02-21T21:32:45Z", tag: "wazuh-analysisd", level: "warning", description: "Rule 18104 fired (level 12) -> 'Windows Audit: Logon failure - Unknown user or bad password.' Agent 004 (win-dc-01)" },
      { timestamp: "2026-02-21T21:30:10Z", tag: "wazuh-analysisd", level: "info", description: "Rule 5763 fired (level 10) -> 'sshd: Possible SSH scan.' Agent 007 (vpn-gateway-01)" },
      { timestamp: "2026-02-21T21:28:00Z", tag: "wazuh-analysisd", level: "info", description: "Rule 5502 fired (level 3) -> 'Login session closed.' Agent 009 (backup-server-01)" },
      { timestamp: "2026-02-21T21:25:30Z", tag: "wazuh-syscheckd", level: "warning", description: "Rule 550 fired (level 10) -> 'Integrity checksum changed (2nd time).' Agent 006 (mail-server-01) /etc/postfix/main.cf" },
      { timestamp: "2026-02-21T21:22:00Z", tag: "wazuh-analysisd", level: "error", description: "Rule 5710 fired (level 14) -> 'sshd: Attempt to login using a denied user.' Agent 009 (backup-server-01)" },
    ],
    total_affected_items: 15,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// VULNERABILITIES
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_VULNERABILITIES = {
  data: {
    affected_items: [
      { cve: "CVE-2024-6387", severity: "Critical", cvss2_score: 8.1, cvss3_score: 9.8, name: "openssh-server", version: "8.9p1-3ubuntu0.6", architecture: "amd64", status: "Active", title: "RegreSSHion: RCE in OpenSSH server", published: "2024-07-01", updated: "2024-07-15", detection_time: "2026-02-20T10:00:00Z", condition: "Package less than 9.8p1", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387" }] },
      { cve: "CVE-2024-3094", severity: "Critical", cvss2_score: 10.0, cvss3_score: 10.0, name: "xz-utils", version: "5.4.1-0.2", architecture: "amd64", status: "Active", title: "XZ Utils backdoor (supply chain compromise)", published: "2024-03-29", updated: "2024-04-10", detection_time: "2026-02-19T08:00:00Z", condition: "Package version 5.6.0 or 5.6.1", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3094" }] },
      { cve: "CVE-2023-44487", severity: "High", cvss2_score: 7.5, cvss3_score: 7.5, name: "nginx", version: "1.24.0-1", architecture: "amd64", status: "Active", title: "HTTP/2 Rapid Reset Attack", published: "2023-10-10", updated: "2024-01-05", detection_time: "2026-02-18T14:00:00Z", condition: "Package less than 1.25.3", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-44487" }] },
      { cve: "CVE-2024-21626", severity: "High", cvss2_score: 8.6, cvss3_score: 8.6, name: "runc", version: "1.1.5-1", architecture: "amd64", status: "Active", title: "runc container breakout through process.cwd", published: "2024-01-31", updated: "2024-02-15", detection_time: "2026-02-17T09:00:00Z", condition: "Package less than 1.1.12", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21626" }] },
      { cve: "CVE-2023-38545", severity: "High", cvss2_score: 9.8, cvss3_score: 9.8, name: "curl", version: "7.88.1-10", architecture: "amd64", status: "Fixed", title: "SOCKS5 heap buffer overflow", published: "2023-10-11", updated: "2023-12-01", detection_time: "2026-02-15T11:00:00Z", condition: "Package less than 8.4.0", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-38545" }] },
      { cve: "CVE-2024-0567", severity: "Medium", cvss2_score: 5.9, cvss3_score: 5.9, name: "gnutls28", version: "3.7.9-2", architecture: "amd64", status: "Active", title: "GnuTLS certificate verification bypass", published: "2024-01-16", updated: "2024-02-01", detection_time: "2026-02-16T13:00:00Z", condition: "Package less than 3.8.3", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2024-0567" }] },
      { cve: "CVE-2023-4911", severity: "High", cvss2_score: 7.8, cvss3_score: 7.8, name: "libc6", version: "2.35-0ubuntu3.6", architecture: "amd64", status: "Fixed", title: "Looney Tunables: glibc buffer overflow in ld.so", published: "2023-10-03", updated: "2023-11-15", detection_time: "2026-02-14T08:00:00Z", condition: "Package less than 2.38-4", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-4911" }] },
      { cve: "CVE-2024-1086", severity: "High", cvss2_score: 7.8, cvss3_score: 7.8, name: "linux-image", version: "5.15.0-91-generic", architecture: "amd64", status: "Active", title: "Linux kernel nf_tables use-after-free (LPE)", published: "2024-01-31", updated: "2024-03-20", detection_time: "2026-02-13T16:00:00Z", condition: "Package less than 6.8", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1086" }] },
      { cve: "CVE-2023-36664", severity: "Medium", cvss2_score: 5.5, cvss3_score: 5.5, name: "ghostscript", version: "10.0.0~dfsg-1", architecture: "amd64", status: "Active", title: "Ghostscript pipe command injection", published: "2023-06-25", updated: "2023-08-10", detection_time: "2026-02-12T10:00:00Z", condition: "Package less than 10.01.2", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-36664" }] },
      { cve: "CVE-2023-32233", severity: "Low", cvss2_score: 3.3, cvss3_score: 3.3, name: "linux-image", version: "5.15.0-91-generic", architecture: "amd64", status: "Fixed", title: "Linux kernel Netfilter nf_tables use-after-free", published: "2023-05-08", updated: "2023-07-01", detection_time: "2026-02-11T14:00:00Z", condition: "Package less than 6.4", external_references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-32233" }] },
    ],
    total_affected_items: 10,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// MITRE ATT&CK
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_MITRE_TACTICS = {
  data: {
    affected_items: [
      { name: "Initial Access", external_id: "TA0001", description: "The adversary is trying to get into your network." },
      { name: "Execution", external_id: "TA0002", description: "The adversary is trying to run malicious code." },
      { name: "Persistence", external_id: "TA0003", description: "The adversary is trying to maintain their foothold." },
      { name: "Privilege Escalation", external_id: "TA0004", description: "The adversary is trying to gain higher-level permissions." },
      { name: "Defense Evasion", external_id: "TA0005", description: "The adversary is trying to avoid being detected." },
      { name: "Credential Access", external_id: "TA0006", description: "The adversary is trying to steal account names and passwords." },
      { name: "Discovery", external_id: "TA0007", description: "The adversary is trying to figure out your environment." },
      { name: "Lateral Movement", external_id: "TA0008", description: "The adversary is trying to move through your environment." },
      { name: "Collection", external_id: "TA0009", description: "The adversary is trying to gather data of interest." },
      { name: "Command and Control", external_id: "TA0011", description: "The adversary is trying to communicate with compromised systems." },
      { name: "Exfiltration", external_id: "TA0010", description: "The adversary is trying to steal data." },
      { name: "Impact", external_id: "TA0040", description: "The adversary is trying to manipulate, interrupt, or destroy your systems." },
      { name: "Reconnaissance", external_id: "TA0043", description: "The adversary is trying to gather information to plan future operations." },
      { name: "Resource Development", external_id: "TA0042", description: "The adversary is trying to establish resources for operations." },
    ],
    total_affected_items: 14,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_MITRE_TECHNIQUES = {
  data: {
    affected_items: [
      { external_id: "T1110", name: "Brute Force", tactics: ["Credential Access"], description: "Adversaries may use brute force techniques to gain access to accounts." },
      { external_id: "T1110.001", name: "Password Guessing", tactics: ["Credential Access"], description: "Adversaries may guess passwords to attempt access." },
      { external_id: "T1003", name: "OS Credential Dumping", tactics: ["Credential Access"], description: "Adversaries may attempt to dump credentials from the OS." },
      { external_id: "T1190", name: "Exploit Public-Facing Application", tactics: ["Initial Access"], description: "Adversaries may exploit internet-facing applications." },
      { external_id: "T1078", name: "Valid Accounts", tactics: ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], description: "Adversaries may obtain and abuse credentials of existing accounts." },
      { external_id: "T1565.001", name: "Stored Data Manipulation", tactics: ["Impact"], description: "Adversaries may manipulate data stored to influence outcomes." },
      { external_id: "T1610", name: "Deploy Container", tactics: ["Execution"], description: "Adversaries may deploy a container to facilitate execution." },
      { external_id: "T1071.001", name: "Web Protocols", tactics: ["Command and Control"], description: "Adversaries may communicate using web protocols." },
      { external_id: "T1046", name: "Network Service Discovery", tactics: ["Discovery"], description: "Adversaries may scan for services running on remote hosts." },
      { external_id: "T1595.002", name: "Vulnerability Scanning", tactics: ["Reconnaissance"], description: "Adversaries may scan for vulnerabilities in victim systems." },
      { external_id: "T1059.004", name: "Unix Shell", tactics: ["Execution"], description: "Adversaries may abuse Unix shell commands." },
      { external_id: "T1021.004", name: "SSH", tactics: ["Lateral Movement"], description: "Adversaries may use SSH to login to remote machines." },
      { external_id: "T1548.001", name: "Setuid and Setgid", tactics: ["Privilege Escalation", "Defense Evasion"], description: "Adversaries may abuse setuid/setgid bits." },
      { external_id: "T1027", name: "Obfuscated Files or Information", tactics: ["Defense Evasion"], description: "Adversaries may obfuscate payloads." },
      { external_id: "T1560", name: "Archive Collected Data", tactics: ["Collection"], description: "Adversaries may compress and/or encrypt data prior to exfiltration." },
      { external_id: "T1041", name: "Exfiltration Over C2 Channel", tactics: ["Exfiltration"], description: "Adversaries may steal data by exfiltrating over C2." },
    ],
    total_affected_items: 16,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_MITRE_GROUPS = {
  data: {
    affected_items: [
      { name: "APT28", external_id: "G0007", description: "APT28 is a threat group attributed to Russia's GRU." },
      { name: "Lazarus Group", external_id: "G0032", description: "Lazarus Group is a North Korean state-sponsored cyber threat group." },
      { name: "APT29", external_id: "G0016", description: "APT29 is a threat group attributed to Russia's SVR." },
      { name: "FIN7", external_id: "G0046", description: "FIN7 is a financially-motivated threat group." },
      { name: "Cobalt Group", external_id: "G0080", description: "Cobalt Group is a financially motivated threat group." },
      { name: "Turla", external_id: "G0010", description: "Turla is a Russian-based threat group linked to the FSB." },
    ],
    total_affected_items: 6,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// SCA / COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_SCA_POLICIES = {
  data: {
    affected_items: [
      { policy_id: "cis_ubuntu22-04", name: "CIS Benchmark for Ubuntu 22.04", description: "CIS provides prescriptive guidance for establishing a secure configuration posture for Ubuntu 22.04.", references: "https://www.cisecurity.org/benchmark/ubuntu_linux", pass: 142, fail: 38, not_applicable: 12, score: 79, hash_file: "abc123def456", total_checks: 192, end_scan: "2026-02-21T20:00:00Z" },
      { policy_id: "pci_dss_v3.2.1", name: "PCI DSS v3.2.1", description: "Payment Card Industry Data Security Standard requirements.", references: "https://www.pcisecuritystandards.org/", pass: 87, fail: 23, not_applicable: 5, score: 79, hash_file: "def456ghi789", total_checks: 115, end_scan: "2026-02-21T20:00:00Z" },
      { policy_id: "hipaa_164", name: "HIPAA Security Rule", description: "Health Insurance Portability and Accountability Act security requirements.", references: "https://www.hhs.gov/hipaa/", pass: 52, fail: 8, not_applicable: 3, score: 87, hash_file: "ghi789jkl012", total_checks: 63, end_scan: "2026-02-21T20:00:00Z" },
      { policy_id: "nist_800_53", name: "NIST 800-53 Rev 5", description: "Security and Privacy Controls for Information Systems.", references: "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final", pass: 198, fail: 42, not_applicable: 15, score: 82, hash_file: "jkl012mno345", total_checks: 255, end_scan: "2026-02-21T20:00:00Z" },
      { policy_id: "gdpr_iv", name: "GDPR Technical Requirements", description: "General Data Protection Regulation technical and organizational measures.", references: "https://gdpr.eu/", pass: 34, fail: 6, not_applicable: 2, score: 85, hash_file: "mno345pqr678", total_checks: 42, end_scan: "2026-02-21T20:00:00Z" },
    ],
    total_affected_items: 5,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_SCA_CHECKS = {
  data: {
    affected_items: [
      { id: 28000, title: "Ensure permissions on /etc/passwd are configured", result: "passed", rationale: "The /etc/passwd file contains user account information.", remediation: "Run: chmod 644 /etc/passwd", compliance: [{ key: "cis", value: "6.1.2" }, { key: "pci_dss", value: "2.2" }], description: "Verify /etc/passwd permissions are 644 or more restrictive.", condition: "all", rules: [{ type: "file", rule: "f:/etc/passwd -> r:^-rw-r--r--" }] },
      { id: 28001, title: "Ensure permissions on /etc/shadow are configured", result: "failed", rationale: "The /etc/shadow file stores password hashes.", remediation: "Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow", compliance: [{ key: "cis", value: "6.1.3" }, { key: "pci_dss", value: "2.2" }], description: "Verify /etc/shadow permissions are 640 or more restrictive.", condition: "all", rules: [{ type: "file", rule: "f:/etc/shadow -> r:^-rw-r-----" }] },
      { id: 28002, title: "Ensure SSH root login is disabled", result: "passed", rationale: "Disabling root login forces admins to use named accounts.", remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config", compliance: [{ key: "cis", value: "5.3.10" }, { key: "pci_dss", value: "2.2.4" }, { key: "hipaa", value: "164.312.a.1" }], description: "Verify SSH does not permit root login.", condition: "all", rules: [{ type: "file", rule: "f:/etc/ssh/sshd_config -> r:^PermitRootLogin\\s+no" }] },
      { id: 28003, title: "Ensure firewall is active", result: "passed", rationale: "A firewall provides a first line of defense.", remediation: "Run: ufw enable", compliance: [{ key: "cis", value: "3.5.1.1" }, { key: "pci_dss", value: "1.1" }], description: "Verify the host firewall is active.", condition: "any", rules: [{ type: "command", rule: "c:ufw status -> r:^Status: active" }] },
      { id: 28004, title: "Ensure password expiration is 365 days or less", result: "failed", rationale: "Password aging reduces the window for credential compromise.", remediation: "Set PASS_MAX_DAYS 365 in /etc/login.defs", compliance: [{ key: "cis", value: "5.5.1.1" }, { key: "pci_dss", value: "8.2.4" }], description: "Verify PASS_MAX_DAYS is 365 or less.", condition: "all", rules: [{ type: "file", rule: "f:/etc/login.defs -> n:^PASS_MAX_DAYS\\s+(\\d+) compare <= 365" }] },
      { id: 28005, title: "Ensure audit log storage size is configured", result: "passed", rationale: "Audit logs must not fill the disk.", remediation: "Set max_log_file in /etc/audit/auditd.conf", compliance: [{ key: "cis", value: "4.1.2.1" }, { key: "pci_dss", value: "10.7" }], description: "Verify audit log max size is set.", condition: "all", rules: [{ type: "file", rule: "f:/etc/audit/auditd.conf -> r:^max_log_file\\s*=" }] },
      { id: 28006, title: "Ensure SSH Protocol is set to 2", result: "passed", rationale: "SSH v1 has known vulnerabilities.", remediation: "Set Protocol 2 in /etc/ssh/sshd_config", compliance: [{ key: "cis", value: "5.3.1" }, { key: "pci_dss", value: "4.1" }], description: "Verify SSH uses protocol version 2.", condition: "all", rules: [{ type: "file", rule: "f:/etc/ssh/sshd_config -> r:^Protocol\\s+2" }] },
      { id: 28007, title: "Ensure no unconfined daemons exist", result: "failed", rationale: "Unconfined daemons bypass mandatory access controls.", remediation: "Confine all daemons with AppArmor/SELinux profiles", compliance: [{ key: "cis", value: "1.7.1.4" }], description: "Verify no unconfined processes are running.", condition: "none", rules: [{ type: "command", rule: "c:aa-unconfined -> r:unconfined" }] },
    ],
    total_affected_items: 8,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// SYSCHECK / FIM
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_SYSCHECK_FILES = {
  data: {
    affected_items: [
      { file: "/etc/passwd", event: "modified", size: 2847, uid: "0", gid: "0", perm: "100644", uname: "root", gname: "root", mtime: "2026-02-21T18:30:00Z", inode: 524289, md5: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", sha1: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", date: "2026-02-21T18:30:00Z" },
      { file: "/etc/shadow", event: "modified", size: 1523, uid: "0", gid: "42", perm: "100640", uname: "root", gname: "shadow", mtime: "2026-02-21T17:45:00Z", inode: 524290, md5: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", sha1: "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c", sha256: "bcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab", date: "2026-02-21T17:45:00Z" },
      { file: "/etc/ssh/sshd_config", event: "modified", size: 3298, uid: "0", gid: "0", perm: "100644", uname: "root", gname: "root", mtime: "2026-02-21T16:20:00Z", inode: 524350, md5: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", sha1: "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d", sha256: "cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc", date: "2026-02-21T16:20:00Z" },
      { file: "/usr/bin/sudo", event: "added", size: 232416, uid: "0", gid: "0", perm: "104755", uname: "root", gname: "root", mtime: "2026-02-20T10:00:00Z", inode: 786433, md5: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", sha1: "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e", sha256: "def1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd", date: "2026-02-20T10:00:00Z" },
      { file: "/var/log/auth.log", event: "modified", size: 1048576, uid: "0", gid: "4", perm: "100640", uname: "root", gname: "adm", mtime: "2026-02-21T21:55:00Z", inode: 262145, md5: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", sha1: "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f", sha256: "ef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde", date: "2026-02-21T21:55:00Z" },
      { file: "/etc/crontab", event: "modified", size: 1042, uid: "0", gid: "0", perm: "100644", uname: "root", gname: "root", mtime: "2026-02-21T14:10:00Z", inode: 524400, md5: "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", sha1: "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a", sha256: "f1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", date: "2026-02-21T14:10:00Z" },
      { file: "/etc/hosts", event: "modified", size: 221, uid: "0", gid: "0", perm: "100644", uname: "root", gname: "root", mtime: "2026-02-19T09:30:00Z", inode: 524291, md5: "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", sha1: "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", sha256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1", date: "2026-02-19T09:30:00Z" },
      { file: "/tmp/.hidden_script.sh", event: "added", size: 4096, uid: "1000", gid: "1000", perm: "100755", uname: "user", gname: "user", mtime: "2026-02-21T20:00:00Z", inode: 131073, md5: "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", sha1: "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c", sha256: "234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12", date: "2026-02-21T20:00:00Z" },
      { file: "/etc/postfix/main.cf", event: "modified", size: 27832, uid: "0", gid: "0", perm: "100644", uname: "root", gname: "root", mtime: "2026-02-21T15:00:00Z", inode: 524500, md5: "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", sha1: "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d", sha256: "34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef123", date: "2026-02-21T15:00:00Z" },
      { file: "/usr/local/bin/backup.sh", event: "deleted", size: 0, uid: "0", gid: "0", perm: "100755", uname: "root", gname: "root", mtime: "2026-02-21T12:00:00Z", inode: 786500, md5: "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5", sha1: "0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e", sha256: "4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234", date: "2026-02-21T12:00:00Z" },
    ],
    total_affected_items: 10,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_SYSCHECK_LAST_SCAN = {
  data: {
    affected_items: [{ start: "2026-02-21T20:00:00Z", end: "2026-02-21T20:15:32Z" }],
    total_affected_items: 1,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// SYSCOLLECTOR (IT Hygiene)
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_PACKAGES = {
  data: {
    affected_items: [
      { name: "openssh-server", version: "1:8.9p1-3ubuntu0.6", architecture: "amd64", vendor: "Ubuntu Developers", format: "deb", description: "secure shell (SSH) server, for secure access from remote machines" },
      { name: "nginx", version: "1.24.0-1~jammy", architecture: "amd64", vendor: "Nginx, Inc.", format: "deb", description: "high performance web server" },
      { name: "curl", version: "7.88.1-10+deb12u5", architecture: "amd64", vendor: "Debian cURL Maintainers", format: "deb", description: "command line tool for transferring data with URL syntax" },
      { name: "openssl", version: "3.0.13-0ubuntu3.1", architecture: "amd64", vendor: "Ubuntu Developers", format: "deb", description: "Secure Sockets Layer toolkit - cryptographic utility" },
      { name: "docker-ce", version: "5:24.0.7-1~ubuntu.22.04~jammy", architecture: "amd64", vendor: "Docker, Inc.", format: "deb", description: "Docker: the open-source application container engine" },
      { name: "python3", version: "3.11.0-1+b1", architecture: "amd64", vendor: "Debian Python Team", format: "deb", description: "interactive high-level object-oriented language" },
      { name: "postgresql-15", version: "15.5-0+deb12u1", architecture: "amd64", vendor: "PostgreSQL Global Development Group", format: "deb", description: "The World's Most Advanced Open Source Relational Database" },
      { name: "fail2ban", version: "1.0.2-2", architecture: "all", vendor: "Debian Security Tools", format: "deb", description: "ban hosts that cause multiple authentication errors" },
      { name: "auditd", version: "1:3.0.9-1", architecture: "amd64", vendor: "Debian Audit Team", format: "deb", description: "User space tools for Linux kernel auditing" },
      { name: "clamav", version: "1.0.3+dfsg-1~deb12u1", architecture: "amd64", vendor: "ClamAV Team", format: "deb", description: "anti-virus utility for Unix" },
      { name: "rsyslog", version: "8.2302.0-1ubuntu2", architecture: "amd64", vendor: "Ubuntu Developers", format: "deb", description: "reliable system and kernel logging daemon" },
      { name: "iptables", version: "1.8.9-2", architecture: "amd64", vendor: "Debian Netfilter Team", format: "deb", description: "administration tools for packet filtering and NAT" },
    ],
    total_affected_items: 12,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_PORTS = {
  data: {
    affected_items: [
      { local: { ip: "0.0.0.0", port: 22 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 1234, process: "sshd" },
      { local: { ip: "0.0.0.0", port: 80 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 2345, process: "nginx" },
      { local: { ip: "0.0.0.0", port: 443 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 2345, process: "nginx" },
      { local: { ip: "127.0.0.1", port: 5432 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 3456, process: "postgres" },
      { local: { ip: "10.0.1.10", port: 22 }, remote: { ip: "10.0.7.50", port: 54321 }, protocol: "tcp", state: "established", pid: 1234, process: "sshd" },
      { local: { ip: "0.0.0.0", port: 1514 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 4567, process: "wazuh-remoted" },
      { local: { ip: "0.0.0.0", port: 1515 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 5678, process: "wazuh-authd" },
      { local: { ip: "0.0.0.0", port: 55000 }, remote: { ip: "0.0.0.0", port: 0 }, protocol: "tcp", state: "listening", pid: 6789, process: "wazuh-apid" },
    ],
    total_affected_items: 8,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_PROCESSES = {
  data: {
    affected_items: [
      { pid: 1, name: "systemd", state: "S", euser: "root", ppid: 0, priority: 20, nlwp: 1, cmd: "/sbin/init" },
      { pid: 1234, name: "sshd", state: "S", euser: "root", ppid: 1, priority: 20, nlwp: 1, cmd: "/usr/sbin/sshd -D" },
      { pid: 2345, name: "nginx", state: "S", euser: "www-data", ppid: 1, priority: 20, nlwp: 4, cmd: "nginx: worker process" },
      { pid: 3456, name: "postgres", state: "S", euser: "postgres", ppid: 1, priority: 20, nlwp: 1, cmd: "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main" },
      { pid: 4567, name: "wazuh-remoted", state: "S", euser: "wazuh", ppid: 1, priority: 20, nlwp: 8, cmd: "/var/ossec/bin/wazuh-remoted" },
      { pid: 5678, name: "wazuh-analysisd", state: "S", euser: "wazuh", ppid: 1, priority: 20, nlwp: 12, cmd: "/var/ossec/bin/wazuh-analysisd" },
      { pid: 6789, name: "wazuh-db", state: "S", euser: "wazuh", ppid: 1, priority: 20, nlwp: 4, cmd: "/var/ossec/bin/wazuh-db" },
      { pid: 7890, name: "fail2ban-server", state: "S", euser: "root", ppid: 1, priority: 20, nlwp: 3, cmd: "/usr/bin/python3 /usr/bin/fail2ban-server -xf start" },
      { pid: 8901, name: "auditd", state: "S", euser: "root", ppid: 1, priority: -4, nlwp: 2, cmd: "/sbin/auditd" },
      { pid: 9012, name: "dockerd", state: "S", euser: "root", ppid: 1, priority: 20, nlwp: 16, cmd: "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock" },
    ],
    total_affected_items: 10,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_NETIFACE = {
  data: {
    affected_items: [
      { name: "eth0", type: "ethernet", state: "up", mac: "02:42:ac:11:00:02", mtu: 1500, tx: { packets: 1284567, bytes: 892345678, errors: 0, dropped: 0 }, rx: { packets: 2345678, bytes: 1567890123, errors: 0, dropped: 12 } },
      { name: "lo", type: "loopback", state: "up", mac: "00:00:00:00:00:00", mtu: 65536, tx: { packets: 456789, bytes: 123456789, errors: 0, dropped: 0 }, rx: { packets: 456789, bytes: 123456789, errors: 0, dropped: 0 } },
      { name: "docker0", type: "ethernet", state: "up", mac: "02:42:f7:8a:3b:c1", mtu: 1500, tx: { packets: 89012, bytes: 45678901, errors: 0, dropped: 0 }, rx: { packets: 67890, bytes: 34567890, errors: 0, dropped: 0 } },
    ],
    total_affected_items: 3,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_NETADDR = {
  data: {
    affected_items: [
      { iface: "eth0", proto: "ipv4", address: "10.0.1.10", netmask: "255.255.255.0", broadcast: "10.0.1.255" },
      { iface: "eth0", proto: "ipv6", address: "fe80::42:acff:fe11:2", netmask: "ffff:ffff:ffff:ffff::", broadcast: "" },
      { iface: "lo", proto: "ipv4", address: "127.0.0.1", netmask: "255.0.0.0", broadcast: "" },
      { iface: "docker0", proto: "ipv4", address: "172.17.0.1", netmask: "255.255.0.0", broadcast: "172.17.255.255" },
    ],
    total_affected_items: 4,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_HOTFIXES = {
  data: {
    affected_items: [
      { hotfix: "KB5034441", scan: { time: "2026-02-21T20:00:00Z" } },
      { hotfix: "KB5034439", scan: { time: "2026-02-21T20:00:00Z" } },
      { hotfix: "KB5033375", scan: { time: "2026-02-21T20:00:00Z" } },
    ],
    total_affected_items: 3,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// CLUSTER
// ═══════════════════════════════════════════════════════════════════════
export const MOCK_CLUSTER_STATUS = {
  data: { enabled: "yes", running: "yes" },
};

export const MOCK_CLUSTER_NODES = {
  data: {
    affected_items: [
      { name: "node01", type: "master", ip: "10.0.0.2", version: "4.7.2" },
      { name: "node02", type: "worker", ip: "10.0.0.3", version: "4.7.2" },
      { name: "node03", type: "worker", ip: "10.0.0.4", version: "4.7.2" },
    ],
    total_affected_items: 3,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_DAEMON_STATS = {
  data: {
    affected_items: [
      { name: "wazuh-analysisd", events_received: 45230, events_dropped: 12, alerts_written: 8934, firewall_written: 1245, fts_written: 456, syscheck_events_decoded: 3421, syscheck_edps: 28, hostinfo_events_decoded: 0, rootcheck_events_decoded: 890, sca_events_decoded: 234 },
      { name: "wazuh-remoted", queue_size: 128, total_queue_size: 131072, tcp_sessions: 12, evt_count: 89456, ctrl_msg_count: 2345, discarded_count: 3, msg_sent: 91234, recv_bytes: 456789012 },
      { name: "wazuh-db", queries_received: 234567, queries_breakdown: { agent: 123456, global: 67890, task: 12345, mitre: 8901, wazuh: 21975 } },
    ],
    total_affected_items: 3,
    total_failed_items: 0,
    failed_items: [],
  },
};

export const MOCK_CONFIG_VALIDATION = {
  data: {
    affected_items: [{ status: "OK" }],
    total_affected_items: 1,
    total_failed_items: 0,
    failed_items: [],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// HELPER: use real data if available, fallback to mock
// ═══════════════════════════════════════════════════════════════════════
export function useFallback<T>(apiData: T | undefined, mockData: T, isConfigured: boolean): T {
  if (isConfigured && apiData !== undefined) return apiData;
  return mockData;
}
