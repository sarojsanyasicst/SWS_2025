# Pracrical 3

## Evaluate Firewall Rules and IDS Alerts for Simulated Attack Traffic

**Module Code:** SWS303  
**Duration:** 5 Hours  
**Platform:** Ubuntu 22.04 Desktop inside VirtualBox  
**Tools Used:** iptables, Snort 3, nmap, hydra, iodine, ssh

---

## Learning Objectives

- Understand how network segmentation enhances security.
- Configure and evaluate firewall rules using iptables.
- Simulate egress-busting and tunneling traffic within a controlled environment.
- Create and tune Snort signatures to detect simulated attack traffic.
- Capture and analyze packets to verify detection and blocking behavior.

---

## Environment Setup

### Network Topology

```
+----------------+            +------------------+
|  Kali (Attacker)|--internal--| Ubuntu (Victim/IDS)|--host-only--| Host Machine |
+----------------+            +------------------+
```

- **Attacker VM:** Simulates malicious traffic (nmap, hydra, iodine).
- **Victim/Firewall VM:** Runs iptables firewall and Snort IDS.
- **Host Machine:** Used for monitoring/log collection.

**Network Mode:** Host-only + Internal Network

---

## 1 – Network Segmentation and iptables Firewall Setup

### 1.1 Objectives

- Design segmented networks in VirtualBox.
- Configure iptables to control inter-zone communication.
- Verify allowed and denied traffic.

### 1.2 Steps

**1.2.1 Configure Virtual Networks:**

- In VirtualBox, create:
  - _Internal Network:_ `intnet`
  - _Host-only Network:_ `vboxnet0`
- Connect:
  - Ubuntu IDS VM → both `intnet` and `vboxnet0`
  - Kali Attacker → `intnet`

**1.2.2 Baseline iptables Rules (on Ubuntu IDS):**

```bash
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback and established
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from host-only network
sudo iptables -A INPUT -i enp0s8 -p tcp --dport 22 -j ACCEPT

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
```

**1.2.3.Verification Commands:**

```bash
sudo iptables -L -v -n
sudo conntrack -L
```

**1.2.4. Expected Output:**

- SSH allowed only from host-only interface.
- Ping from attacker VM fails.
- Dropped packets logged in `/var/log/syslog`.

---

## 2 – Detecting Egress Busting

### 2.1 Objectives

- Simulate internal host attempting to bypass egress controls.
- Detect and log using Snort.

### 2.2 Steps

**2.2.1. Restrict Egress Traffic:**

```bash
sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

**2.2.2 Simulate DNS over HTTP Attempt (on attacker):**

```bash
curl -x http://attacker_ip:80 http://example.com
### Use Iodine or Dnscat2 for real dns tunneling demo
```

**2.2.3. Snort Rule to Detect Suspicious DNS over HTTP:**

```bash
alert tcp any any -> any 80 (msg:"Suspicious DNS over HTTP"; content:"/dns-query"; nocase; sid:1000001; rev:1;)
```

**2.2.4.Verification:**

```bash
sudo tail -f /var/log/snort/alert
```

**2.2.5. Expected Output:**

- Snort generates an alert for traffic containing `/dns-query` over port 80.

---

## 3 – Port Forwarding & Tunneling

### 3.1. Objectives

- Demonstrate SSH tunneling and detect it with Snort.

### 3.2. Steps

**3.2.1. Simulate SSH Tunnel (on attacker):**

```bash
ssh -L 8080:example.com:80 user@victim_ip
```

**3.2.2. Snort Rule for Unusual SSH Tunnel Activity:**

```bash
alert tcp any any -> any 22 (msg:"Possible SSH Tunnel"; flow:to_server,established; detection_filter:track by_src, count 10, seconds 60; sid:1000002; rev:1;)
```

**3.2.3. Expected Result:**

- Alert generated when multiple SSH connections occur rapidly.

---

## 4 – Signature-based Detections

### 4.1. Objectives

- Write Snort rules to detect attack traffic and tune false positives.

### 4.2. Sample Rules

**4.2.1. Detect Nmap Scan:**

```bash
alert tcp any any -> any any (msg:"Nmap Scan Detected"; flags:S; threshold:type both, track by_src, count 10, seconds 5; sid:1000003; rev:1;)
```

**4.2.2. Detect Brute Force (Hydra):**

```bash
alert tcp any any -> any 22 (msg:"SSH Brute Force"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 10; sid:1000004; rev:1;)
```

### 4.3. Verification

```bash
sudo snort -A fast -q -c /etc/snort/snort.conf -i eth1
tail -f /var/log/snort/alert
```

### 4.4. Expected Output

- Alerts generated for Nmap and Hydra activity.
- False positives minimized by detection filters.

---

## 5 - Evidence Collection & Analysis

### 5.1. Packet Capture

```bash
sudo tcpdump -i eth1 -w attack_traffic.pcap
```

### 5.2. Log Analysis

- Check `/var/log/snort/alert`
- Use Wireshark to open captured `.pcap` file.

---

## Assessment Questions

1. Explain why network segmentation is important for intrusion detection.
2. What iptables rule would allow DNS but block HTTPS?
3. Why might an attacker use port forwarding?
4. How does Snort detect tunneling or exfiltration?
5. Suggest one method to reduce false positives in Snort rules.

---

## Troubleshooting Appendix

| Issue                         | Cause               | Fix                                          |
| ----------------------------- | ------------------- | -------------------------------------------- |
| Snort won’t start             | Incorrect interface | Use `snort -i <iface>`                       |
| iptables rules not persisting | Not saved           | Use `iptables-save > /etc/iptables/rules.v4` |
| No alerts generated           | Rule path incorrect | Verify `/etc/snort/rules/local.rules`        |

---

#### Note:

This is just a simple guide for you to get the overview of the practical.
You Should perform more realistic demo using industry stndard tools.
