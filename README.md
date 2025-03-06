
# Wazuh as an Intrusion Detection and Prevention System (IDS/IPS)

# 1. Project Overview
This project focuses on implementing Wazuh as an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS). we will integrate Suricata as the primary Network-based IDS (NIDS) to analyze network traffic and detect threats.

# Why Wazuh for IDS/IPS? 

* Host-based Intrusion Detection System (HIDS): Monitors logs, file integrity, processes, and system activity.

* Network-based Intrusion Detection System (NIDS) with Suricata: Detects malicious network traffic.

* Intrusion Prevention System (IPS) with Active Response: Blocks threats using firewall rules.

* Centralized Log Management: Uses Elastic Stack (Elasticsearch, Logstash, Kibana) for real-time security monitoring.


# 2. Project Objectives :
1.  **Host-Based IDS (HIDS)**: 
* System logs (Linux, Windows, macOS)
* File Integrity Monitoring (FIM)
* SSH, sudo, and login attempts
* Malware or suspicious process activity

2. **Network-Based IDS (NIDS)** :
* Detect port scans, exploit attempts, and malware communication. 
* Inspect network traffic for suspicious patterns.
* Generate alerts for malicious behavior.

3.  **Intrusion Prevention System (IPS)** :
* Block malicious IPs using iptables (Linux) or Windows Firewall.
* Stop brute-force login attempts.
* Disable compromised user accounts




 




# 3. Installation Guide
**Step 1: Install Wazuh Server.**

Wazuh provides an automated script to install the Wazuh Manager, Elastic Stack, and Dashboard:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh --wazuh-server
```
This script will:
* Install Wazuh Manager (Core IDS system).
* Install Elasticsearch (Log storage).
* Install Kibana (Visualization).
* Install Wazuh Dashboard (UI for alerts and monitoring).

**Step 2: Check Wazuh Services.**

After installation, verify that all Wazuh services are running:

```bash
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana
sudo systemctl status filebeat
```
If any service is not running, start it manually:
```bash
sudo systemctl start wazuh-manager
sudo systemctl start elasticsearch
sudo systemctl start kibana
sudo systemctl start filebeat
```
Enable the services to start on boot:

```bash
sudo systemctl enable wazuh-manager elasticsearch kibana filebeat
```

**1.2 Install Wazuh Dashboard**

Access the dashboard at:
```bash
https://<server-ip>:5601  //your localhost ip address
```
Login with default credentials (admin / SecretPassword) and change the password immediately.



## Step 2: Install Wazuh Agents (HIDS)
Install Wazuh agents on Linux and Windows endpoints for host-based monitoring.

**Windows**
1. Download the agent from:
https://packages.wazuh.com/4.x/windows/wazuh-agent.msi 

2. Install the agent and set the Manager IP to your Wazuh server.
3. Start the agent service from the Windows Services panel.



## Step 3: Install Suricata for Network Intrusion Detection (NIDS)
we will use Suricata to analyze network traffic.

**3.1 Install Suricata**

Run the following on your Wazuh server or a dedicated sensor:
```bash
sudo apt update && sudo apt install -y suricata
```
Verify installation:
```bash
suricata --build-info
```

**3.2 Configure Suricata**

Edit the Suricata configuration file to enable logging:

```bash 
sudo nano /etc/suricata/suricata.yaml
```
Ensure these options are enabled:

```bash
outputs:
  - eve-log:
      enabled: yes
      filetype: json
      filename: /var/log/suricata/eve.json
```
**3.3 Start Suricata**
```bash
sudo systemctl enable --now suricata
```
**Step 4: Integrate Suricata Logs with Wazuh**

We need to forward Suricata logs to Wazuh.

**4.1 Install Filebeat on the Wazuh Server**
```bash
curl -sO https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.3-amd64.deb
sudo dpkg -i filebeat-7.17.3-amd64.deb
```

**4.2 Configure Filebeat for Suricata Logs**

Edit Filebeat’s configuration:
```bash
sudo nano /etc/filebeat/filebeat.yml
```
Add the Suricata log path:
```bash
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true

```

Restart Filebeat: 
```bash
sudo systemctl restart filebeat
```

**Step 5: Enable Intrusion Prevention (IPS)**

Configure Wazuh to block malicious IPs detected by Suricata.

**5.1 Enable Active Response**

Edit the Wazuh agent configuration:

```bash
sudo nano /var/ossec/etc/ossec.conf
```
**Enable Active Response:**

```xml
<active-response>
  <command>firewalld</command>
  <location>local</location>
  <level>6</level>
</active-response>
```

**5.2 Restart Wazuh Agent**

Run a port scan from another system:

```bash
nmap -Pn <WAZUH_SERVER_IP>
```

If detected, Wazuh will block the attacker’s IP automatically.



# 4. Expected Outcomes
Real-time threat detection from logs and network traffic.

Automated blocking of malicious activity.

Centralized security monitoring via the Wazuh Dashboard.

Reduced attack surface for enhanced cybersecurity.


# 5. Conclusion
In this project, we successfully deployed **Wazuh as an Intrusion Detection and Prevention System (IDS/IPS)**. Instead, we integrated **Suricata** for network traffic analysis, while Wazuh handled **host-based intrusion detection (HIDS)**, log analysis, and automated threat response.


**Key Achievements**

✅ **Installed and configured Wazuh Server** to collect and analyze security logs.

✅ **Deployed Wazuh Agents** on Linux and Windows endpoints for real-time monitoring.

✅ **Integrated Suricata (NIDS)** for detecting network threats and logging suspicious activities.


✅ **Enabled Active Response (IPS)** to automatically block malicious IPs and prevent attacks.

✅ **Configured a centralized security dashboard** for real-time alerting and monitoring.




**Future Improvements**

🚀 **Fine-tune Wazuh rules** to reduce false positives.

🚀 **Integrate additional security tools** (e.g., Threat Intelligence feeds, Sysmon for Windows).

🚀 **Automate alerts via email or Slack** for quicker incident response.

With this setup, your network is better protected against cyber threats, offering real-time intrusion detection and automated threat mitigation. 







