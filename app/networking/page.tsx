import { Server } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { InfoIcon } from "lucide-react"
import Link from "next/link"
import { ExternalLink } from "lucide-react"

export default function NetworkingPage() {
  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-6">
        <Server className="h-8 w-8 text-primary" />
        <h1 className="text-4xl font-bold">🌐 Networking Basics for Security Engineers</h1>
      </div>

      <p className="text-xl text-muted-foreground mb-8">
        Understanding networking fundamentals is crucial for security engineers. This guide covers essential networking
        concepts, protocols, tools, and security implications.
      </p>

      <Tabs defaultValue="concepts" className="mb-12">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="concepts">Key Concepts</TabsTrigger>
          <TabsTrigger value="protocols">Protocols & Services</TabsTrigger>
          <TabsTrigger value="tools">Security Tools</TabsTrigger>
          <TabsTrigger value="practice">Practice Labs</TabsTrigger>
        </TabsList>

        <TabsContent value="concepts" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">OSI Model</h2>
            <p>
              The OSI (Open Systems Interconnection) model is a conceptual framework that standardizes the functions of
              a telecommunication or computing system into seven abstraction layers. Security controls exist at each
              layer.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Layer 7: Application</CardTitle>
                  <CardDescription>Network process to application</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Protocols:</strong> HTTP, SMTP, FTP, DNS
                  </p>
                  <p>
                    <strong>Security concerns:</strong> Input validation, authentication, authorization
                  </p>
                  <p>
                    <strong>Security tools:</strong> WAF, API gateways
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Layer 6: Presentation</CardTitle>
                  <CardDescription>Data representation and encryption</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Functions:</strong> Encryption, compression, translation
                  </p>
                  <p>
                    <strong>Security concerns:</strong> Weak encryption, data leakage
                  </p>
                  <p>
                    <strong>Security tools:</strong> TLS/SSL, encryption libraries
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Layer 5: Session</CardTitle>
                  <CardDescription>Interhost communication</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Functions:</strong> Session establishment, maintenance, termination
                  </p>
                  <p>
                    <strong>Security concerns:</strong> Session hijacking, replay attacks
                  </p>
                  <p>
                    <strong>Security tools:</strong> Session management frameworks
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Layer 4: Transport</CardTitle>
                  <CardDescription>End-to-end connections and reliability</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Protocols:</strong> TCP, UDP
                  </p>
                  <p>
                    <strong>Security concerns:</strong> DoS attacks, port scanning
                  </p>
                  <p>
                    <strong>Security tools:</strong> Firewalls, IPS
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Layer 3: Network</CardTitle>
                  <CardDescription>Path determination and logical addressing</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Protocols:</strong> IP, ICMP, routing protocols
                  </p>
                  <p>
                    <strong>Security concerns:</strong> IP spoofing, routing attacks
                  </p>
                  <p>
                    <strong>Security tools:</strong> Routers, firewalls
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Layer 2: Data Link</CardTitle>
                  <CardDescription>Physical addressing</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Protocols:</strong> Ethernet, ARP, MAC
                  </p>
                  <p>
                    <strong>Security concerns:</strong> ARP poisoning, MAC flooding
                  </p>
                  <p>
                    <strong>Security tools:</strong> Switches, port security
                  </p>
                </CardContent>
              </Card>

              <Card className="md:col-span-2">
                <CardHeader>
                  <CardTitle>Layer 1: Physical</CardTitle>
                  <CardDescription>Media, signal and binary transmission</CardDescription>
                </CardHeader>
                <CardContent>
                  <p>
                    <strong>Components:</strong> Cables, hubs, repeaters
                  </p>
                  <p>
                    <strong>Security concerns:</strong> Wiretapping, physical tampering, jamming
                  </p>
                  <p>
                    <strong>Security tools:</strong> Physical security controls, signal jammers
                  </p>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Security Perspective</AlertTitle>
              <AlertDescription>
                Security engineers must understand how attacks and defenses operate at different OSI layers. For
                example, a DDoS attack might target Layer 3/4, while an SQL injection targets Layer 7.
              </AlertDescription>
            </Alert>
          </section>

          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-8">TCP/IP Model</h2>
            <p>
              The TCP/IP model is a more practical, condensed version of the OSI model with four layers. Most modern
              networks are based on this model.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardHeader>
                  <CardTitle>Application Layer</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Combines OSI layers 5-7 (Application, Presentation, Session)</p>
                  <p>
                    <strong>Protocols:</strong> HTTP, FTP, SMTP, DNS, SSH, Telnet
                  </p>
                  <p>
                    <strong>Security focus:</strong> Application vulnerabilities, authentication, data validation
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Transport Layer</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Equivalent to OSI layer 4 (Transport)</p>
                  <p>
                    <strong>Protocols:</strong> TCP, UDP
                  </p>
                  <p>
                    <strong>Security focus:</strong> Port scanning, session hijacking, DoS attacks
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Internet Layer</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Equivalent to OSI layer 3 (Network)</p>
                  <p>
                    <strong>Protocols:</strong> IP, ICMP, ARP
                  </p>
                  <p>
                    <strong>Security focus:</strong> IP spoofing, routing attacks, ICMP attacks
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Network Interface Layer</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Combines OSI layers 1-2 (Physical, Data Link)</p>
                  <p>
                    <strong>Protocols:</strong> Ethernet, Token Ring, Frame Relay
                  </p>
                  <p>
                    <strong>Security focus:</strong> MAC spoofing, ARP poisoning, physical access
                  </p>
                </CardContent>
              </Card>
            </div>
          </section>

          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-8">IP Addressing & Subnetting</h2>
            <p>Understanding IP addressing and subnetting is crucial for network segmentation and security.</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-xl font-semibold mb-2">IPv4 Addressing</h3>
                <ul className="space-y-2 list-disc pl-5">
                  <li>32-bit addresses represented in dotted decimal (e.g., 192.168.1.1)</li>
                  <li>Network portion vs. host portion determined by subnet mask</li>
                  <li>Special addresses: loopback (127.0.0.1), private ranges, broadcast</li>
                  <li>NAT/PAT for translating between private and public addresses</li>
                </ul>
              </div>

              <div>
                <h3 className="text-xl font-semibold mb-2">IPv6 Addressing</h3>
                <ul className="space-y-2 list-disc pl-5">
                  <li>128-bit addresses represented in hexadecimal (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)</li>
                  <li>No need for NAT due to vast address space</li>
                  <li>Security implications: more difficult to scan, but dual-stack issues</li>
                  <li>Privacy extensions to prevent tracking</li>
                </ul>
              </div>

              <div className="md:col-span-2">
                <h3 className="text-xl font-semibold mb-2">CIDR Notation & Subnetting</h3>
                <p className="mb-2">
                  CIDR (Classless Inter-Domain Routing) notation represents IP addresses with their subnet mask (e.g.,
                  192.168.1.0/24).
                </p>
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="bg-muted">
                      <th className="border p-2 text-left">CIDR</th>
                      <th className="border p-2 text-left">Subnet Mask</th>
                      <th className="border p-2 text-left">Hosts</th>
                      <th className="border p-2 text-left">Common Use</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td className="border p-2">/24</td>
                      <td className="border p-2">255.255.255.0</td>
                      <td className="border p-2">254</td>
                      <td className="border p-2">Small LAN</td>
                    </tr>
                    <tr>
                      <td className="border p-2">/16</td>
                      <td className="border p-2">255.255.0.0</td>
                      <td className="border p-2">65,534</td>
                      <td className="border p-2">Organization</td>
                    </tr>
                    <tr>
                      <td className="border p-2">/8</td>
                      <td className="border p-2">255.0.0.0</td>
                      <td className="border p-2">16,777,214</td>
                      <td className="border p-2">Large network</td>
                    </tr>
                    <tr>
                      <td className="border p-2">/30</td>
                      <td className="border p-2">255.255.255.252</td>
                      <td className="border p-2">2</td>
                      <td className="border p-2">Point-to-point</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Security Implications</AlertTitle>
              <AlertDescription>
                Proper subnetting enables network segmentation, a key security principle. It allows for isolation of
                sensitive systems, implementation of security zones, and containment of breaches.
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="protocols" className="space-y-6">
          <section>
            <h2 className="text-2xl font-bold">Common Protocols & Security Implications</h2>
            <p className="text-muted-foreground mb-6">
              Understanding network protocols and their security implications is essential for identifying
              vulnerabilities and implementing proper controls.
            </p>

            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Web Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">HTTP (Port 80)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Hypertext Transfer Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Plaintext protocol for web communication</li>
                        <li>
                          <strong>Security issues:</strong> No encryption, susceptible to eavesdropping, MITM attacks
                        </li>
                        <li>
                          <strong>Security controls:</strong> Migrate to HTTPS, implement HSTS
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">HTTPS (Port 443)</h3>
                      <p className="text-sm text-muted-foreground mb-1">HTTP Secure</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Encrypted version of HTTP using TLS/SSL</li>
                        <li>
                          <strong>Security issues:</strong> Certificate validation, outdated TLS versions
                        </li>
                        <li>
                          <strong>Security controls:</strong> Proper certificate management, modern TLS configuration
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">WebSockets (WS/WSS)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Full-duplex communication channels</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Persistent connection between client and server</li>
                        <li>
                          <strong>Security issues:</strong> Cross-site WebSocket hijacking, lack of same-origin policy
                        </li>
                        <li>
                          <strong>Security controls:</strong> Origin validation, proper authentication
                        </li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Name Resolution Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">DNS (Port 53)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Domain Name System</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Translates domain names to IP addresses</li>
                        <li>
                          <strong>Security issues:</strong> Cache poisoning, DNS tunneling, zone transfers
                        </li>
                        <li>
                          <strong>Security controls:</strong> DNSSEC, DNS filtering, proper zone configuration
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">DNS Resolution Process</h3>
                      <ol className="list-decimal pl-5 space-y-1">
                        <li>Client queries local DNS resolver</li>
                        <li>If not in cache, resolver queries root servers</li>
                        <li>Root servers direct to TLD servers (.com, .org, etc.)</li>
                        <li>TLD servers direct to authoritative nameservers</li>
                        <li>Authoritative nameserver provides IP address</li>
                        <li>Result is cached at various levels</li>
                      </ol>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Remote Access Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">SSH (Port 22)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Secure Shell</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Encrypted protocol for remote administration</li>
                        <li>
                          <strong>Security issues:</strong> Brute force attacks, key management, outdated versions
                        </li>
                        <li>
                          <strong>Security controls:</strong> Key-based authentication, fail2ban, proper configuration
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">Telnet (Port 23)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Teletype Network</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Legacy plaintext protocol for remote access</li>
                        <li>
                          <strong>Security issues:</strong> No encryption, credentials sent in cleartext
                        </li>
                        <li>
                          <strong>Security controls:</strong> Replace with SSH, disable on all systems
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">RDP (Port 3389)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Remote Desktop Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Microsoft&apos;s protocol for remote desktop access</li>
                        <li>
                          <strong>Security issues:</strong> BlueKeep and related vulnerabilities, brute force
                        </li>
                        <li>
                          <strong>Security controls:</strong> Network Level Authentication, patching, firewall rules
                        </li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Email Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">SMTP (Port 25)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Simple Mail Transfer Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for sending email</li>
                        <li>
                          <strong>Security issues:</strong> Email spoofing, relay abuse, plaintext transmission
                        </li>
                        <li>
                          <strong>Security controls:</strong> SPF, DKIM, DMARC, STARTTLS
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">IMAP (Port 143/993)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Internet Message Access Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for retrieving email (keeps mail on server)</li>
                        <li>
                          <strong>Security issues:</strong> Plaintext authentication (143), credential theft
                        </li>
                        <li>
                          <strong>Security controls:</strong> Use IMAPS (993) with TLS, strong authentication
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">POP3 (Port 110/995)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Post Office Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for retrieving email (downloads to client)</li>
                        <li>
                          <strong>Security issues:</strong> Plaintext authentication (110), local storage risks
                        </li>
                        <li>
                          <strong>Security controls:</strong> Use POP3S (995) with TLS, client-side encryption
                        </li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>File Transfer Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">FTP (Port 21)</h3>
                      <p className="text-sm text-muted-foreground mb-1">File Transfer Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for transferring files</li>
                        <li>
                          <strong>Security issues:</strong> Plaintext authentication, no encryption, active/passive mode
                          complexities
                        </li>
                        <li>
                          <strong>Security controls:</strong> Replace with SFTP or FTPS, implement strict access
                          controls
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">SFTP (Port 22)</h3>
                      <p className="text-sm text-muted-foreground mb-1">SSH File Transfer Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Secure file transfer using SSH</li>
                        <li>
                          <strong>Security issues:</strong> Same as SSH (brute force, key management)
                        </li>
                        <li>
                          <strong>Security controls:</strong> Key-based authentication, proper permissions
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">SMB (Port 445)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Server Message Block</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for shared access to files and printers</li>
                        <li>
                          <strong>Security issues:</strong> EternalBlue, SMBGhost, legacy version vulnerabilities
                        </li>
                        <li>
                          <strong>Security controls:</strong> Disable SMBv1, patch regularly, firewall restrictions
                        </li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Network Management Protocols</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold">SNMP (Port 161/162)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Simple Network Management Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for network device management</li>
                        <li>
                          <strong>Security issues:</strong> Default community strings, information disclosure
                        </li>
                        <li>
                          <strong>Security controls:</strong> Use SNMPv3 with authentication and encryption, ACLs
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">ICMP</h3>
                      <p className="text-sm text-muted-foreground mb-1">Internet Control Message Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for network diagnostics (ping, traceroute)</li>
                        <li>
                          <strong>Security issues:</strong> ICMP tunneling, ping floods, Smurf attacks
                        </li>
                        <li>
                          <strong>Security controls:</strong> ICMP filtering, rate limiting
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="text-lg font-semibold">NTP (Port 123)</h3>
                      <p className="text-sm text-muted-foreground mb-1">Network Time Protocol</p>
                      <ul className="list-disc pl-5 space-y-1">
                        <li>Protocol for time synchronization</li>
                        <li>
                          <strong>Security issues:</strong> NTP amplification attacks, time poisoning
                        </li>
                        <li>
                          <strong>Security controls:</strong> Restrict to trusted servers, implement authentication
                        </li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        </TabsContent>

        <TabsContent value="tools" className="space-y-6">
          <section>
            <h2 className="text-2xl font-bold">Essential Networking Tools for Security Engineers</h2>
            <p className="text-muted-foreground mb-6">
              These tools are essential for network security analysis, monitoring, and testing.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Wireshark</CardTitle>
                  <CardDescription>Network Protocol Analyzer</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>Deep packet inspection</li>
                      <li>Protocol analysis and decoding</li>
                      <li>Capture filters and display filters</li>
                      <li>Traffic visualization</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>Analyzing suspicious network traffic</li>
                      <li>Identifying malware communication</li>
                      <li>Troubleshooting network issues</li>
                      <li>Detecting protocol anomalies</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Display filter for HTTP traffic
                        <br />
                        http
                        <br />
                        <br /># Display filter for specific IP
                        <br />
                        ip.addr == 192.168.1.1
                        <br />
                        <br /># Display filter for DNS queries
                        <br />
                        dns.qry.name contains &quot;example.com&quot;
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>tcpdump</CardTitle>
                  <CardDescription>Command-line Packet Analyzer</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>Lightweight command-line tool</li>
                      <li>Powerful capture filters</li>
                      <li>Works on headless systems</li>
                      <li>Can save captures for later analysis</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>Remote server traffic analysis</li>
                      <li>Automated traffic capture</li>
                      <li>Incident response</li>
                      <li>Network troubleshooting</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Capture traffic on interface eth0
                        <br />
                        tcpdump -i eth0
                        <br />
                        <br /># Capture HTTP traffic
                        <br />
                        tcpdump -i eth0 port 80
                        <br />
                        <br /># Save capture to file
                        <br />
                        tcpdump -i eth0 -w capture.pcap
                        <br />
                        <br /># Read from capture file
                        <br />
                        tcpdump -r capture.pcap
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Nmap</CardTitle>
                  <CardDescription>Network Discovery and Security Auditing</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>Port scanning</li>
                      <li>OS detection</li>
                      <li>Service/version detection</li>
                      <li>Scripting engine (NSE)</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>Network reconnaissance</li>
                      <li>Vulnerability scanning</li>
                      <li>Security auditing</li>
                      <li>Asset discovery</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Basic scan
                        <br />
                        nmap 192.168.1.0/24
                        <br />
                        <br /># Comprehensive scan
                        <br />
                        nmap -sV -sC -O -p- 192.168.1.1
                        <br />
                        <br /># Stealth scan
                        <br />
                        nmap -sS 192.168.1.1
                        <br />
                        <br /># Vulnerability scanning
                        <br />
                        nmap --script vuln 192.168.1.1
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Netcat</CardTitle>
                  <CardDescription>Network Swiss Army Knife</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>Port scanning</li>
                      <li>Port listening</li>
                      <li>File transfer</li>
                      <li>Banner grabbing</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>Testing network connectivity</li>
                      <li>Service enumeration</li>
                      <li>Simple backdoor detection</li>
                      <li>Network debugging</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Connect to a port
                        <br />
                        nc 192.168.1.1 80
                        <br />
                        <br /># Listen on a port
                        <br />
                        nc -lvp 4444
                        <br />
                        <br /># Port scanning
                        <br />
                        nc -zv 192.168.1.1 20-80
                        <br />
                        <br /># Banner grabbing
                        <br />
                        echo &quot;&quot; | nc -v 192.168.1.1 22
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>dig/nslookup</CardTitle>
                  <CardDescription>DNS Query Tools</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>DNS record lookup</li>
                      <li>DNS server testing</li>
                      <li>DNS zone transfer</li>
                      <li>Reverse DNS lookup</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>DNS reconnaissance</li>
                      <li>Identifying DNS misconfigurations</li>
                      <li>Verifying DNS security controls</li>
                      <li>Investigating DNS-based attacks</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Basic DNS lookup
                        <br />
                        dig example.com
                        <br />
                        <br /># Query specific record type
                        <br />
                        dig example.com MX
                        <br />
                        <br /># Reverse DNS lookup
                        <br />
                        dig -x 8.8.8.8
                        <br />
                        <br /># Query specific DNS server
                        <br />
                        dig @8.8.8.8 example.com
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>traceroute/tracert</CardTitle>
                  <CardDescription>Route Tracing Utility</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <h3 className="font-semibold">Key Features:</h3>
                    <ul className="list-disc pl-5">
                      <li>Path discovery</li>
                      <li>Network latency measurement</li>
                      <li>Routing problem identification</li>
                      <li>Network topology mapping</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Security Use Cases:</h3>
                    <ul className="list-disc pl-5">
                      <li>Network reconnaissance</li>
                      <li>Identifying network boundaries</li>
                      <li>Detecting routing anomalies</li>
                      <li>Investigating network issues</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold">Essential Commands:</h3>
                    <div className="bg-muted p-2 rounded-md">
                      <code>
                        # Basic traceroute (Linux/macOS)
                        <br />
                        traceroute example.com
                        <br />
                        <br /># Basic tracert (Windows)
                        <br />
                        tracert example.com
                        <br />
                        <br /># Specify max hops
                        <br />
                        traceroute -m 15 example.com
                        <br />
                        <br /># Use TCP instead of UDP/ICMP
                        <br />
                        traceroute -T example.com
                      </code>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        </TabsContent>

        <TabsContent value="practice" className="space-y-6">
          <section>
            <h2 className="text-2xl font-bold">Hands-On Network Security Labs</h2>
            <p className="text-muted-foreground mb-6">
              Practice is essential for mastering networking concepts. These labs will help you build practical skills.
            </p>

            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Lab 1: Network Traffic Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold">Objective:</h3>
                      <p>
                        Learn to capture and analyze network traffic to identify protocols, patterns, and potential
                        security issues.
                      </p>
                    </div>

                    <div>
                      <h3 className="font-semibold">Tools Needed:</h3>
                      <ul className="list-disc pl-5">
                        <li>Wireshark</li>
                        <li>tcpdump</li>
                        <li>Virtual machines or physical network</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold">Steps:</h3>
                      <ol className="list-decimal pl-5 space-y-2">
                        <li>
                          <p className="font-medium">Set up your environment</p>
                          <p className="text-sm text-muted-foreground">
                            Create a small network with 2-3 VMs or use your home network.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Capture baseline traffic</p>
                          <p className="text-sm text-muted-foreground">
                            Use Wireshark to capture normal network activity for 5-10 minutes.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Generate specific traffic</p>
                          <p className="text-sm text-muted-foreground">
                            Perform various network activities: web browsing, DNS lookups, file transfers, etc.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Analyze the capture</p>
                          <p className="text-sm text-muted-foreground">
                            Identify different protocols, examine packet structures, and use display filters to isolate
                            traffic.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Identify security concerns</p>
                          <p className="text-sm text-muted-foreground">
                            Look for plaintext credentials, unencrypted data, or suspicious connections.
                          </p>
                        </li>
                      </ol>
                    </div>

                    <div>
                      <h3 className="font-semibold">Challenge Tasks:</h3>
                      <ul className="list-disc pl-5">
                        <li>Identify all DNS queries in the capture</li>
                        <li>Extract HTTP headers from web traffic</li>
                        <li>Find all devices on the network and their MAC addresses</li>
                        <li>Detect any cleartext passwords or sensitive information</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Lab 2: Network Scanning and Enumeration</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold">Objective:</h3>
                      <p>Learn to perform network reconnaissance and identify potential vulnerabilities.</p>
                    </div>

                    <div>
                      <h3 className="font-semibold">Tools Needed:</h3>
                      <ul className="list-disc pl-5">
                        <li>Nmap</li>
                        <li>Netcat</li>
                        <li>Virtual machines or practice environment</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold">Steps:</h3>
                      <ol className="list-decimal pl-5 space-y-2">
                        <li>
                          <p className="font-medium">Set up target environment</p>
                          <p className="text-sm text-muted-foreground">
                            Create a lab with multiple VMs running different services (web, FTP, SSH, etc.).
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Perform host discovery</p>
                          <p className="text-sm text-muted-foreground">
                            Use Nmap to identify live hosts on the network.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Conduct port scanning</p>
                          <p className="text-sm text-muted-foreground">
                            Use different scan types (SYN, TCP, UDP) to identify open ports.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Service enumeration</p>
                          <p className="text-sm text-muted-foreground">Identify running services and their versions.</p>
                        </li>
                        <li>
                          <p className="font-medium">OS fingerprinting</p>
                          <p className="text-sm text-muted-foreground">Determine operating systems of target hosts.</p>
                        </li>
                        <li>
                          <p className="font-medium">Banner grabbing</p>
                          <p className="text-sm text-muted-foreground">
                            Use Netcat to grab service banners for further information.
                          </p>
                        </li>
                      </ol>
                    </div>

                    <div>
                      <h3 className="font-semibold">Challenge Tasks:</h3>
                      <ul className="list-disc pl-5">
                        <li>Create a network map of all discovered hosts</li>
                        <li>Identify potentially vulnerable services based on version information</li>
                        <li>Perform stealth scanning and compare results with regular scans</li>
                        <li>Use NSE scripts to gather additional information</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Lab 3: Network Security Monitoring</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold">Objective:</h3>
                      <p>Set up a basic network security monitoring system to detect and analyze suspicious traffic.</p>
                    </div>

                    <div>
                      <h3 className="font-semibold">Tools Needed:</h3>
                      <ul className="list-disc pl-5">
                        <li>Security Onion or similar NSM distribution</li>
                        <li>Virtual machines for testing</li>
                        <li>Traffic generation tools</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold">Steps:</h3>
                      <ol className="list-decimal pl-5 space-y-2">
                        <li>
                          <p className="font-medium">Install Security Onion</p>
                          <p className="text-sm text-muted-foreground">
                            Set up Security Onion in a VM with proper network configuration.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Configure sensors</p>
                          <p className="text-sm text-muted-foreground">
                            Set up network interfaces for monitoring and configure basic rules.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Generate normal traffic</p>
                          <p className="text-sm text-muted-foreground">
                            Create baseline network activity to establish normal patterns.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Simulate attack traffic</p>
                          <p className="text-sm text-muted-foreground">
                            Generate suspicious traffic like port scans, brute force attempts, etc.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Analyze alerts</p>
                          <p className="text-sm text-muted-foreground">
                            Review generated alerts and understand their significance.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Tune detection</p>
                          <p className="text-sm text-muted-foreground">
                            Adjust rules to reduce false positives and improve detection.
                          </p>
                        </li>
                      </ol>
                    </div>

                    <div>
                      <h3 className="font-semibold">Challenge Tasks:</h3>
                      <ul className="list-disc pl-5">
                        <li>Create custom rules to detect specific attack patterns</li>
                        <li>Perform network forensics on captured suspicious traffic</li>
                        <li>Set up dashboards for effective monitoring</li>
                        <li>Create an incident response playbook based on detected events</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Lab 4: Network Segmentation and Firewalls</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold">Objective:</h3>
                      <p>Learn to implement network segmentation and configure firewalls to control traffic flow.</p>
                    </div>

                    <div>
                      <h3 className="font-semibold">Tools Needed:</h3>
                      <ul className="list-disc pl-5">
                        <li>pfSense or OPNsense virtual appliance</li>
                        <li>Multiple VMs for different network segments</li>
                        <li>Network testing tools</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold">Steps:</h3>
                      <ol className="list-decimal pl-5 space-y-2">
                        <li>
                          <p className="font-medium">Design network architecture</p>
                          <p className="text-sm text-muted-foreground">
                            Plan a segmented network with at least 3 zones (e.g., DMZ, internal, management).
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Set up pfSense/OPNsense</p>
                          <p className="text-sm text-muted-foreground">
                            Configure the firewall appliance with multiple interfaces.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Configure VLANs</p>
                          <p className="text-sm text-muted-foreground">Set up VLANs for network segmentation.</p>
                        </li>
                        <li>
                          <p className="font-medium">Implement firewall rules</p>
                          <p className="text-sm text-muted-foreground">
                            Create rules to control traffic between segments based on least privilege.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Test connectivity</p>
                          <p className="text-sm text-muted-foreground">
                            Verify that allowed traffic passes and denied traffic is blocked.
                          </p>
                        </li>
                        <li>
                          <p className="font-medium">Implement IDS/IPS</p>
                          <p className="text-sm text-muted-foreground">
                            Configure Suricata or Snort on the firewall for intrusion detection.
                          </p>
                        </li>
                      </ol>
                    </div>

                    <div>
                      <h3 className="font-semibold">Challenge Tasks:</h3>
                      <ul className="list-disc pl-5">
                        <li>Implement a zero-trust model where all traffic must be explicitly allowed</li>
                        <li>Set up a honeypot in a separate segment to detect unauthorized access attempts</li>
                        <li>Configure VPN access for secure remote connectivity</li>
                        <li>Document your network architecture and security controls</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        </TabsContent>
      </Tabs>

      <section className="mt-12">
        <h2 className="text-2xl font-bold mb-4">Additional Resources</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Books</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="https://nostarch.com/networkprotocols"
                    className="text-primary hover:underline flex items-center"
                  >
                    Attacking Network Protocols
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.oreilly.com/library/view/practical-packet-analysis/9781492029274/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Practical Packet Analysis
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.amazon.com/TCP-Illustrated-Vol-Addison-Wesley-Professional/dp/0321336313"
                    className="text-primary hover:underline flex items-center"
                  >
                    TCP/IP Illustrated
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Online Courses</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="https://www.coursera.org/learn/computer-networking"
                    className="text-primary hover:underline flex items-center"
                  >
                    Computer Networking (Coursera)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.cybrary.it/course/comptia-network-plus/"
                    className="text-primary hover:underline flex items-center"
                  >
                    CompTIA Network+ (Cybrary)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.sans.org/cyber-security-courses/network-penetration-testing-ethical-hacking/"
                    className="text-primary hover:underline flex items-center"
                  >
                    SANS SEC560: Network Penetration Testing
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Practice Platforms</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="https://tryhackme.com/room/introtonetworking"
                    className="text-primary hover:underline flex items-center"
                  >
                    TryHackMe - Intro to Networking
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link href="https://www.hackthebox.com/" className="text-primary hover:underline flex items-center">
                    HackTheBox Network Challenges
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.netacad.com/courses/packet-tracer"
                    className="text-primary hover:underline flex items-center"
                  >
                    Cisco Packet Tracer
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  )
}
