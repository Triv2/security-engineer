import { Terminal } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { InfoIcon, ShieldAlert } from "lucide-react"
import Link from "next/link"
import { ExternalLink } from "lucide-react"
import { CodeBlock } from "@/components/code-block"

export default function LinuxPage() {
  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-6">
        <Terminal className="h-8 w-8 text-primary" />
        <h1 className="text-4xl font-bold">🐧 Linux Security</h1>
      </div>

      <p className="text-xl text-muted-foreground mb-8">
        Linux systems form the backbone of modern infrastructure. This guide covers essential security concepts,
        hardening techniques, and tools to secure Linux environments.
      </p>

      <Tabs defaultValue="fundamentals" className="mb-12">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="fundamentals">Fundamentals</TabsTrigger>
          <TabsTrigger value="hardening">Hardening</TabsTrigger>
          <TabsTrigger value="access-control">Access Control</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="tools">Security Tools</TabsTrigger>
        </TabsList>

        <TabsContent value="fundamentals" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Linux Security Fundamentals</h2>
            <p>
              Understanding the core security concepts in Linux is essential for building secure systems. Linux security
              is built on a foundation of proper configuration, access controls, and monitoring.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Linux File System Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Linux file system implements security through permissions and ownership. Every file and
                    directory has associated permissions that control who can read, write, or execute it.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Permission Types</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Read (r):</strong> View file contents or list directory contents
                      </li>
                      <li>
                        <strong>Write (w):</strong> Modify file contents or create/delete files in a directory
                      </li>
                      <li>
                        <strong>Execute (x):</strong> Run a file as a program or access a directory
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Permission Classes</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>User (u):</strong> The owner of the file
                      </li>
                      <li>
                        <strong>Group (g):</strong> Users who are members of the file&apos;s group
                      </li>
                      <li>
                        <strong>Others (o):</strong> All other users
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Special Permissions</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>SUID (Set User ID):</strong> Executes with the permissions of the file owner
                      </li>
                      <li>
                        <strong>SGID (Set Group ID):</strong> Executes with the permissions of the file group
                      </li>
                      <li>
                        <strong>Sticky Bit:</strong> Restricts file deletion in directories
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# View file permissions
ls -l /path/to/file

# Change file permissions
chmod 750 /path/to/file  # rwxr-x---

# Change file ownership
chown user:group /path/to/file

# Find SUID files (potential security risk)
find / -type f -perm -4000 -ls 2>/dev/null

# Find world-writable files
find / -type f -perm -o+w -ls 2>/dev/null`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>User and Group Management</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Proper user and group management is fundamental to Linux security. Each user should have the minimum
                    privileges needed to perform their tasks.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">User Types</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Root (UID 0):</strong> Superuser with unlimited privileges
                      </li>
                      <li>
                        <strong>System Users (UID 1-999):</strong> Service accounts for system processes
                      </li>
                      <li>
                        <strong>Regular Users (UID 1000+):</strong> Normal user accounts
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Important Files</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>/etc/passwd:</strong> User account information
                      </li>
                      <li>
                        <strong>/etc/shadow:</strong> Encrypted passwords
                      </li>
                      <li>
                        <strong>/etc/group:</strong> Group definitions
                      </li>
                      <li>
                        <strong>/etc/sudoers:</strong> Sudo configuration
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# Add a new user
useradd -m -s /bin/bash username

# Set/change password
passwd username

# Add user to group
usermod -aG groupname username

# View user groups
groups username

# Lock a user account
usermod -L username

# Delete a user
userdel -r username  # -r removes home directory`}
                    />
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Security Best Practice</AlertTitle>
                    <AlertDescription>
                      Never use the root account for daily operations. Create individual user accounts and use sudo for
                      privileged operations. This provides accountability and reduces the risk of accidental system
                      damage.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Process Isolation and Control</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Linux provides several mechanisms to isolate and control processes, preventing them from interfering
                    with each other or accessing unauthorized resources.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Process Security Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Process Ownership:</strong> Each process runs with the permissions of a specific user
                      </li>
                      <li>
                        <strong>Process Capabilities:</strong> Fine-grained control over privileged operations
                      </li>
                      <li>
                        <strong>cgroups:</strong> Control resource allocation to process groups
                      </li>
                      <li>
                        <strong>namespaces:</strong> Isolate process views of system resources
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Containerization</h3>
                    <p>
                      Modern Linux systems use containerization technologies like Docker and LXC to provide stronger
                      process isolation:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Isolated file systems</li>
                      <li>Network namespace separation</li>
                      <li>Resource limitations</li>
                      <li>Reduced attack surface</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# View running processes
ps aux

# View process details
ps -p PID -f

# Check process capabilities
getpcaps PID

# Set process capabilities
setcap cap_net_bind_service=+ep /path/to/binary

# View cgroup information
systemd-cgls

# Kill a process
kill PID  # SIGTERM (graceful)
kill -9 PID  # SIGKILL (force)`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Linux Kernel Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Linux kernel provides various security mechanisms to protect the system at the lowest level.
                    Understanding and configuring these features is essential for robust security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Kernel Security Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Secure Boot:</strong> Ensures only signed kernels and modules are loaded
                      </li>
                      <li>
                        <strong>Module Signing:</strong> Prevents loading of unsigned kernel modules
                      </li>
                      <li>
                        <strong>Kernel Address Space Layout Randomization (KASLR):</strong> Randomizes kernel memory
                        addresses
                      </li>
                      <li>
                        <strong>Kernel Page Table Isolation (KPTI):</strong> Mitigates Meltdown vulnerability
                      </li>
                      <li>
                        <strong>seccomp:</strong> Restricts system calls available to processes
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Kernel Hardening Parameters</h3>
                    <p>
                      The <code>/etc/sysctl.conf</code> file and <code>/etc/sysctl.d/</code> directory contain kernel
                      parameters that can be tuned for security:
                    </p>
                    <CodeBlock
                      code={`# Disable IP forwarding
net.ipv4.ip_forward = 0

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Restrict core dumps
fs.suid_dumpable = 0

# Apply changes
sysctl -p`}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Security in Depth</AlertTitle>
              <AlertDescription>
                Linux security should be implemented in layers. No single security control is sufficient. Combine proper
                file permissions, user management, process controls, and kernel security features for a comprehensive
                security posture.
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="hardening" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Linux System Hardening</h2>
            <p>
              System hardening involves configuring a Linux system to minimize its attack surface and reduce
              vulnerabilities. This section covers essential hardening techniques for different components of a Linux
              system.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Secure Boot and Disk Encryption</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Securing the boot process and encrypting storage are fundamental steps to protect against physical
                    access threats and data theft.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">UEFI Secure Boot</h3>
                    <p>
                      Secure Boot ensures that only signed bootloaders and kernels can be loaded, preventing boot-time
                      malware:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enable Secure Boot in UEFI/BIOS</li>
                      <li>Use signed kernels and modules</li>
                      <li>Configure GRUB with a password</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Full Disk Encryption</h3>
                    <p>Encrypt disks to protect data at rest:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>LUKS (Linux Unified Key Setup):</strong> Standard for disk encryption
                      </li>
                      <li>
                        <strong>dm-crypt:</strong> Transparent disk encryption subsystem
                      </li>
                      <li>Encrypt swap partitions to prevent memory leaks</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Implementation</h3>
                    <CodeBlock
                      code={`# Check Secure Boot status
mokutil --sb-state

# Set up disk encryption during installation
# Or encrypt an existing partition:
cryptsetup luksFormat /dev/sdXY

# Open encrypted partition
cryptsetup luksOpen /dev/sdXY encrypted_volume

# Create filesystem
mkfs.ext4 /dev/mapper/encrypted_volume

# Mount encrypted volume
mount /dev/mapper/encrypted_volume /mnt/secure

# Add to /etc/crypttab for auto-mounting
# encrypted_volume /dev/sdXY none luks`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Service Hardening</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Properly configuring and securing services reduces the attack surface and prevents unauthorized
                    access.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Service Management</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Disable unnecessary services</li>
                      <li>Run services with minimal privileges</li>
                      <li>Use systemd security features</li>
                      <li>Implement proper service isolation</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Systemd Security Features</h3>
                    <p>Systemd provides several security directives for service units:</p>
                    <CodeBlock
                      code={`[Service]
# Run as specific user/group
User=serviceuser
Group=servicegroup

# Restrict capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Restrict file system access
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/service

# Restrict process interaction
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true

# Network namespacing
PrivateNetwork=true`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# List all services
systemctl list-unit-files --type=service

# Disable and stop a service
systemctl disable --now unnecessary-service

# Check service status
systemctl status important-service

# View service security settings
systemctl show important-service | grep Protect

# Edit a service file
systemctl edit important-service --full`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Network Hardening</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Securing network configurations is essential to protect against remote attacks and unauthorized
                    access.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Firewall Configuration</h3>
                    <p>
                      Linux provides several firewall solutions, with <code>iptables</code> and <code>firewalld</code>{" "}
                      being the most common:
                    </p>
                    <CodeBlock
                      code={`# Basic iptables rules
# Flush existing rules
iptables -F

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (restrict if possible)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4

# Using firewalld (CentOS/RHEL/Fedora)
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --remove-service=telnet
firewall-cmd --reload`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">SSH Hardening</h3>
                    <p>
                      Secure Shell (SSH) is a common entry point for attacks. Harden it by editing{" "}
                      <code>/etc/ssh/sshd_config</code>:
                    </p>
                    <CodeBlock
                      code={`# Disable root login
PermitRootLogin no

# Use strong authentication
PasswordAuthentication no
PubkeyAuthentication yes

# Restrict users
AllowUsers user1 user2

# Use strong ciphers and MACs
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Limit login attempts
MaxAuthTries 3

# Enable logging
LogLevel VERBOSE

# Restart SSH after changes
systemctl restart sshd`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Network Hardening Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>fail2ban:</strong> Block IP addresses after failed login attempts
                      </li>
                      <li>
                        <strong>TCP Wrappers:</strong> Control access to network services
                      </li>
                      <li>
                        <strong>PortSentry:</strong> Detect and respond to port scans
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Package and Software Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Properly managing software and keeping it updated is critical for maintaining a secure Linux system.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Package Management Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use only official or trusted repositories</li>
                      <li>Verify package signatures</li>
                      <li>Regularly update packages</li>
                      <li>Remove unnecessary packages</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# Debian/Ubuntu
# Update package lists
apt update

# Upgrade packages
apt upgrade

# Security updates only
apt upgrade -s | grep "^Inst" | grep -i security

# List installed packages
dpkg -l

# Remove package
apt remove --purge package-name

# RHEL/CentOS/Fedora
# Update package lists
dnf check-update

# Apply security updates
dnf update --security

# List installed packages
rpm -qa

# Remove package
dnf remove package-name`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Automatic Updates</h3>
                    <p>Configure automatic security updates to ensure timely patching:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Debian/Ubuntu:</strong> unattended-upgrades package
                      </li>
                      <li>
                        <strong>RHEL/CentOS:</strong> dnf-automatic package
                      </li>
                    </ul>
                    <CodeBlock
                      code={`# Debian/Ubuntu
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# RHEL/CentOS
dnf install dnf-automatic
systemctl enable --now dnf-automatic.timer`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card className="md:col-span-2">
                <CardHeader>
                  <CardTitle>CIS Benchmarks and Security Baselines</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Center for Internet Security (CIS) provides comprehensive benchmarks for securing Linux systems.
                    These benchmarks offer a standardized approach to system hardening.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h3 className="font-semibold mb-2">CIS Benchmark Categories</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>Initial Setup</li>
                        <li>Services</li>
                        <li>Network Configuration</li>
                        <li>Logging and Auditing</li>
                        <li>Access, Authentication, and Authorization</li>
                        <li>System Maintenance</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Implementation Tools</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>OpenSCAP:</strong> Security compliance scanning
                        </li>
                        <li>
                          <strong>Lynis:</strong> Security auditing tool
                        </li>
                        <li>
                          <strong>Ansible:</strong> Automation for applying security baselines
                        </li>
                        <li>
                          <strong>Chef InSpec:</strong> Compliance as code
                        </li>
                      </ul>
                    </div>
                  </div>

                  <Alert>
                    <InfoIcon className="h-4 w-4" />
                    <AlertTitle>CIS Benchmark Resources</AlertTitle>
                    <AlertDescription>
                      <p className="mb-2">
                        CIS provides distribution-specific benchmarks for various Linux distributions:
                      </p>
                      <ul className="list-disc pl-5">
                        <li>
                          <Link
                            href="https://www.cisecurity.org/benchmark/ubuntu_linux/"
                            className="text-primary hover:underline flex items-center"
                          >
                            CIS Ubuntu Linux Benchmark
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                        <li>
                          <Link
                            href="https://www.cisecurity.org/benchmark/red_hat_linux/"
                            className="text-primary hover:underline flex items-center"
                          >
                            CIS Red Hat Enterprise Linux Benchmark
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                        <li>
                          <Link
                            href="https://www.cisecurity.org/benchmark/debian_linux/"
                            className="text-primary hover:underline flex items-center"
                          >
                            CIS Debian Linux Benchmark
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </div>
          </section>
        </TabsContent>

        <TabsContent value="access-control" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Advanced Access Control</h2>
            <p>
              Linux provides several advanced access control mechanisms beyond traditional file permissions. These
              systems allow for more granular and flexible security policies.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>SELinux (Security-Enhanced Linux)</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    SELinux is a mandatory access control (MAC) system implemented in the Linux kernel. It provides
                    fine-grained control over what processes can access which resources.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Concepts</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Type Enforcement:</strong> Processes and objects have security types
                      </li>
                      <li>
                        <strong>Role-Based Access Control:</strong> Users are assigned roles
                      </li>
                      <li>
                        <strong>Multi-Level Security:</strong> Objects have security levels
                      </li>
                      <li>
                        <strong>Policy:</strong> Rules defining allowed interactions
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">SELinux Modes</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Enforcing:</strong> Policy is enforced, violations are denied
                      </li>
                      <li>
                        <strong>Permissive:</strong> Policy violations are logged but not enforced
                      </li>
                      <li>
                        <strong>Disabled:</strong> SELinux is turned off
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# Check SELinux status
getenforce

# Set SELinux mode
setenforce 1  # Enforcing
setenforce 0  # Permissive

# View file context
ls -Z /path/to/file

# Set file context
chcon -t httpd_sys_content_t /path/to/file

# Restore default contexts
restorecon -Rv /path

# View process context
ps -eZ | grep httpd

# View SELinux policy violations
ausearch -m AVC,USER_AVC -ts today

# Troubleshoot issues
sealert -a /var/log/audit/audit.log`}
                    />
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>SELinux Best Practices</AlertTitle>
                    <AlertDescription>
                      <ul className="list-disc pl-5">
                        <li>Don&apos;t disable SELinux; use permissive mode for troubleshooting</li>
                        <li>Use audit2allow to create custom policies for legitimate access needs</li>
                        <li>Regularly review and analyze SELinux denial logs</li>
                        <li>Test policy changes in permissive mode before enforcing</li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>AppArmor</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    AppArmor is a Mandatory Access Control system that restricts programs&apos; capabilities with per
                    Mandatory Access Control system that restricts programs&apos; capabilities with per-program profiles.
                    It&apos;s commonly used in Ubuntu and Debian-based distributions.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Concepts</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Profiles:</strong> Define what resources a program can access
                      </li>
                      <li>
                        <strong>Paths:</strong> Control file system access
                      </li>
                      <li>
                        <strong>Capabilities:</strong> Control privileged operations
                      </li>
                      <li>
                        <strong>Network Access:</strong> Control network operations
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Profile Modes</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Enforce:</strong> Block access to disallowed resources
                      </li>
                      <li>
                        <strong>Complain:</strong> Allow but log access to disallowed resources
                      </li>
                      <li>
                        <strong>Unconfined:</strong> No restrictions applied
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Commands</h3>
                    <CodeBlock
                      code={`# Check AppArmor status
aa-status

# List profiles
aa-status | grep "profiles loaded"

# Put profile in complain mode
aa-complain /path/to/bin

# Put profile in enforce mode
aa-enforce /path/to/bin

# Generate a profile
aa-genprof /path/to/bin

# Update a profile
aa-logprof

# View AppArmor logs
dmesg | grep apparmor
cat /var/log/audit/audit.log | grep apparmor`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Profile</h3>
                    <CodeBlock
                      code={`# /etc/apparmor.d/usr.bin.example
#include <tunables/global>

/usr/bin/example {
  #include <abstractions/base>
  #include <abstractions/user-tmp>

  # Files the program can read
  /etc/example/config r,
  /var/lib/example/** r,

  # Files the program can write
  /var/log/example/*.log w,
  
  # Network access
  network inet tcp,
  
  # Capabilities
  capability net_bind_service,
}`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Sudo and Privileged Access</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Properly configuring sudo is essential for secure privileged access management. It allows users to
                    execute commands with elevated privileges while maintaining accountability.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Sudo Configuration</h3>
                    <p>
                      The sudo configuration is stored in <code>/etc/sudoers</code> and files in{" "}
                      <code>/etc/sudoers.d/</code>. Always edit these files using <code>visudo</code> to prevent syntax
                      errors.
                    </p>
                    <CodeBlock
                      code={`# Basic sudo configuration examples

# Allow user to run any command
username ALL=(ALL:ALL) ALL

# Allow user to run specific commands without password
username ALL=(ALL) NOPASSWD: /bin/ls, /usr/bin/apt update

# Allow group to run specific commands
%sysadmin ALL=(ALL) /usr/bin/systemctl restart apache2

# Restrict commands to specific hosts
username host1,host2=(ALL) ALL

# Include command path restrictions
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Log all sudo commands
Defaults log_output
Defaults!/usr/bin/sudoreplay !log_output
Defaults!/usr/local/bin/sudoreplay !log_output
Defaults!REBOOT !log_output`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Sudo Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use the principle of least privilege</li>
                      <li>Specify exact commands rather than wildcards</li>
                      <li>Enable command logging</li>
                      <li>Set short timeout periods</li>
                      <li>Require re-authentication for critical commands</li>
                      <li>Use command restrictions and path controls</li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Security Warning</AlertTitle>
                    <AlertDescription>
                      Be extremely cautious with NOPASSWD options. They can lead to privilege escalation if the allowed
                      commands have vulnerabilities or can be manipulated to execute arbitrary code.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>PAM (Pluggable Authentication Modules)</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    PAM provides a flexible framework for authentication in Linux. It allows for customized
                    authentication policies and integration with various authentication methods.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">PAM Configuration</h3>
                    <p>
                      PAM configuration files are located in <code>/etc/pam.d/</code> and define authentication
                      requirements for different services.
                    </p>
                    <CodeBlock
                      code={`# Example PAM configuration for SSH (/etc/pam.d/sshd)

# Authentication modules
auth       required     pam_securetty.so
auth       required     pam_unix.so nullok
auth       required     pam_nologin.so

# Account management
account    required     pam_unix.so
account    required     pam_time.so

# Password management
password   required     pam_unix.so nullok obscure min=8 max=100 sha512

# Session management
session    required     pam_unix.so
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_lastlog.so showfailed`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Common PAM Modules</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>pam_unix.so:</strong> Traditional password authentication
                      </li>
                      <li>
                        <strong>pam_ldap.so:</strong> LDAP authentication
                      </li>
                      <li>
                        <strong>pam_google_authenticator.so:</strong> Two-factor authentication
                      </li>
                      <li>
                        <strong>pam_limits.so:</strong> Resource limits
                      </li>
                      <li>
                        <strong>pam_faillock.so:</strong> Account lockout after failed attempts
                      </li>
                      <li>
                        <strong>pam_time.so:</strong> Time-based access control
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Implementing 2FA with PAM</h3>
                    <p>Example of setting up Google Authenticator for SSH:</p>
                    <CodeBlock
                      code={`# Install Google Authenticator PAM module
apt install libpam-google-authenticator

# Configure PAM for SSH
# Add to /etc/pam.d/sshd:
auth required pam_google_authenticator.so

# Enable challenge-response in SSH
# Edit /etc/ssh/sshd_config:
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive

# Restart SSH
systemctl restart sshd

# Set up for a user
su - username
google-authenticator`}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>
          </section>
        </TabsContent>

        <TabsContent value="monitoring" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Security Monitoring and Auditing</h2>
            <p>
              Effective security monitoring and auditing are essential for detecting and responding to security
              incidents. Linux provides various tools and frameworks for comprehensive monitoring.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Linux Auditing Framework</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Linux Audit Framework provides a way to track security-relevant events on a system. It can
                    monitor file access, command execution, system calls, and more.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Components</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>auditd:</strong> Audit daemon that writes audit records to disk
                      </li>
                      <li>
                        <strong>auditctl:</strong> Tool for controlling the audit system
                      </li>
                      <li>
                        <strong>ausearch:</strong> Tool for searching audit logs
                      </li>
                      <li>
                        <strong>aureport:</strong> Tool for generating reports from audit logs
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Setting Up Audit Rules</h3>
                    <CodeBlock
                      code={`# Install audit
apt install auditd audispd-plugins

# Start and enable the service
systemctl enable --now auditd

# Basic audit rules (/etc/audit/rules.d/audit.rules)

# Monitor file access
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Monitor command execution
-a exit,always -F arch=b64 -S execve -k exec

# Monitor privileged commands
-a exit,always -F path=/usr/bin/sudo -F perm=x -k sudo_log

# Monitor system calls
-a exit,always -F arch=b64 -S mount -k mount

# Monitor network configuration
-w /etc/sysconfig/network -p wa -k network
-w /etc/hosts -p wa -k network

# Load new rules
auditctl -R /etc/audit/rules.d/audit.rules`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Analyzing Audit Logs</h3>
                    <CodeBlock
                      code={`# Search for file access events
ausearch -f /etc/passwd

# Search for events by user
ausearch -ua root

# Search for events by key
ausearch -k identity

# Generate summary reports
aureport --summary
aureport --executable
aureport --auth
aureport --login

# Generate timeline of events
ausearch -ts today -i | less`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>System Logging and Log Analysis</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Proper logging and log analysis are critical for security monitoring. Linux provides several logging
                    systems, with rsyslog and journald being the most common.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Log Files</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>/var/log/auth.log or /var/log/secure:</strong> Authentication events
                      </li>
                      <li>
                        <strong>/var/log/syslog or /var/log/messages:</strong> General system logs
                      </li>
                      <li>
                        <strong>/var/log/kern.log:</strong> Kernel messages
                      </li>
                      <li>
                        <strong>/var/log/audit/audit.log:</strong> Audit framework logs
                      </li>
                      <li>
                        <strong>/var/log/apache2/ or /var/log/httpd/:</strong> Web server logs
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Log Management</h3>
                    <CodeBlock
                      code={`# Configure rsyslog for remote logging
# Add to /etc/rsyslog.conf:
*.* @logserver.example.com:514  # UDP
*.* @@logserver.example.com:514  # TCP with TLS

# Configure log rotation
# Edit /etc/logrotate.conf or files in /etc/logrotate.d/

# Example logrotate configuration
/var/log/syslog {
    rotate 7
    daily
    missingok
    notifempty
    delaycompress
    compress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Log Analysis Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>journalctl:</strong> Query the systemd journal
                      </li>
                      <li>
                        <strong>grep, awk, sed:</strong> Command-line text processing
                      </li>
                      <li>
                        <strong>logwatch:</strong> Summarize log entries
                      </li>
                      <li>
                        <strong>fail2ban:</strong> Scan logs and ban suspicious IPs
                      </li>
                      <li>
                        <strong>ELK Stack:</strong> Elasticsearch, Logstash, Kibana for advanced log analysis
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Common Log Analysis Commands</h3>
                    <CodeBlock
                      code={`# View systemd journal
journalctl -u ssh

# View logs for a specific time period
journalctl --since "2023-01-01" --until "2023-01-02"

# View logs for a specific user
journalctl _UID=1000

# Search for failed login attempts
grep "Failed password" /var/log/auth.log

# Count login failures by IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# Monitor logs in real-time
tail -f /var/log/auth.log`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>File Integrity Monitoring</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    File integrity monitoring (FIM) tools detect unauthorized changes to critical system files and
                    configurations, helping to identify potential security breaches.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">AIDE (Advanced Intrusion Detection Environment)</h3>
                    <p>AIDE is a popular open-source file integrity checker:</p>
                    <CodeBlock
                      code={`# Install AIDE
apt install aide

# Configure AIDE
# Edit /etc/aide/aide.conf

# Example configuration
# Define what to check
/etc/passwd CONTENT_EX
/etc/shadow CONTENT_EX
/etc/group CONTENT_EX
/etc/sudoers CONTENT_EX
/bin/ CONTENT_EX
/sbin/ CONTENT_EX
/usr/bin/ CONTENT_EX
/usr/sbin/ CONTENT_EX

# Initialize the database
aide --init

# Move the initial database to the active location
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check for changes
aide --check

# Update the database after legitimate changes
aide --update`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Other FIM Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Tripwire:</strong> Commercial and open-source versions available
                      </li>
                      <li>
                        <strong>Samhain:</strong> Centralized file integrity checking
                      </li>
                      <li>
                        <strong>OSSEC:</strong> Host-based intrusion detection with FIM capabilities
                      </li>
                      <li>
                        <strong>auditd:</strong> Can be configured for basic file monitoring
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Store the baseline database on read-only media or a separate system</li>
                      <li>Run checks regularly via cron jobs</li>
                      <li>Configure email alerts for detected changes</li>
                      <li>Focus on critical system files to reduce noise</li>
                      <li>Update the baseline after legitimate changes</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Intrusion Detection and Prevention</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) monitor for and respond to
                    suspicious activities and potential security breaches.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">OSSEC (Open Source HIDS)</h3>
                    <p>OSSEC is a popular host-based intrusion detection system:</p>
                    <CodeBlock
                      code={`# Install OSSEC
wget https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
tar -xzf 3.7.0.tar.gz
cd ossec-hids-3.7.0
./install.sh

# Basic configuration is done during installation
# Additional configuration in /var/ossec/etc/ossec.conf

# Start OSSEC
/var/ossec/bin/ossec-control start

# Check status
/var/ossec/bin/ossec-control status

# Add an agent (if using server-agent model)
/var/ossec/bin/manage_agents`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Fail2ban</h3>
                    <p>
                      Fail2ban scans log files and bans IPs that show malicious signs like too many failed login
                      attempts:
                    </p>
                    <CodeBlock
                      code={`# Install Fail2ban
apt install fail2ban

# Configure Fail2ban
# Create /etc/fail2ban/jail.local

[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

# Restart Fail2ban
systemctl restart fail2ban

# Check status
fail2ban-client status
fail2ban-client status sshd

# Unban an IP
fail2ban-client set sshd unbanip 192.168.1.100`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Other IDS/IPS Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Wazuh:</strong> Fork of OSSEC with additional features
                      </li>
                      <li>
                        <strong>Snort/Suricata:</strong> Network-based IDS/IPS
                      </li>
                      <li>
                        <strong>CrowdSec:</strong> Collaborative IPS with community threat intelligence
                      </li>
                      <li>
                        <strong>AIDE + custom scripts:</strong> Simple DIY approach
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Comprehensive Monitoring Strategy</AlertTitle>
              <AlertDescription>
                <p>An effective security monitoring strategy combines multiple approaches:</p>
                <ul className="list-disc pl-5 mt-2">
                  <li>System logging for general events</li>
                  <li>Audit framework for detailed activity tracking</li>
                  <li>File integrity monitoring for detecting unauthorized changes</li>
                  <li>Intrusion detection for identifying attack patterns</li>
                  <li>Centralized log collection for correlation and analysis</li>
                  <li>Regular review and alerting for timely response</li>
                </ul>
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="tools" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Essential Linux Security Tools</h2>
            <p>
              A variety of specialized security tools are available for Linux systems. These tools help with
              vulnerability assessment, security auditing, malware detection, and more.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Lynis - Security Auditing Tool</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Lynis is an open-source security auditing tool for Unix/Linux systems. It performs comprehensive
                    security scans and provides recommendations for hardening.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>System security scan</li>
                      <li>Compliance testing (PCI, HIPAA, ISO27001)</li>
                      <li>Vulnerability detection</li>
                      <li>Configuration assessment</li>
                      <li>Security patch verification</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Installation and Usage</h3>
                    <CodeBlock
                      code={`# Install Lynis
apt install lynis

# Run a system scan
lynis audit system

# Run a specific test
lynis audit system --tests-from-group malware

# Generate a report
lynis audit system --report-file /tmp/lynis-report.dat

# View Lynis documentation
man lynis`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Output</h3>
                    <div className="bg-muted p-2 rounded-md text-xs">
                      <pre>
                        {`[+] Boot and services
[+] Checking GRUB bootloader                               [ ENABLED ]
[+] Checking presence GRUB password                        [ WARNING ]
[+] Check running services (systemd)                       [ DONE ]
[+] Check enabled services at boot (systemd)               [ DONE ]
[+] Check startup files (permissions)                      [ OK ]`}
                      </pre>
                    </div>
                  </div>

                  <Alert>
                    <InfoIcon className="h-4 w-4" />
                    <AlertTitle>Best Practice</AlertTitle>
                    <AlertDescription>
                      Run Lynis regularly (e.g., weekly via cron) and compare results over time to track security
                      improvements and regressions.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>ClamAV - Antivirus for Linux</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    ClamAV is an open-source antivirus engine designed for detecting trojans, viruses, malware, and
                    other malicious threats on Linux systems.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>On-demand scanning</li>
                      <li>Automatic signature updates</li>
                      <li>File format recognition</li>
                      <li>Archive scanning (zip, rar, etc.)</li>
                      <li>Integration with mail servers</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Installation and Usage</h3>
                    <CodeBlock
                      code={`# Install ClamAV
apt install clamav clamav-daemon

# Update virus definitions
freshclam

# Scan a specific file
clamscan /path/to/file

# Scan a directory recursively
clamscan -r /path/to/directory

# Scan and remove infected files
clamscan -r --remove /path/to/directory

# Scan with detailed output
clamscan -r --infected --bell -i /path/to/directory`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Automated Scanning</h3>
                    <p>Set up regular scans with cron:</p>
                    <CodeBlock
                      code={`# Add to /etc/cron.daily/clamav
#!/bin/bash
LOGFILE="/var/log/clamav/scan_$(date +'%Y-%m-%d').log"
DIRECTORIES="/home /var/www /tmp"

# Update virus definitions
freshclam --quiet

# Scan directories
clamscan -ri $DIRECTORIES >> $LOGFILE

# Email results if infections found
if grep -q "Infected files: [1-9]" $LOGFILE; then
    mail -s "ClamAV - Infections Found" admin@example.com < $LOGFILE
fi

exit 0`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Rootkit Detection Tools</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Rootkits are particularly dangerous as they can hide their presence from standard system tools.
                    Specialized rootkit detection tools help identify these threats.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Chkrootkit</h3>
                    <p>A tool to locally check for signs of a rootkit:</p>
                    <CodeBlock
                      code={`# Install chkrootkit
apt install chkrootkit

# Run a scan
chkrootkit

# Run specific tests
chkrootkit -x

# Exclude tests
chkrootkit -e "bindshell sniffer"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Rkhunter</h3>
                    <p>Rootkit Hunter scans for rootkits, backdoors, and local exploits:</p>
                    <CodeBlock
                      code={`# Install rkhunter
apt install rkhunter

# Update rkhunter database
rkhunter --update

# Check system
rkhunter --check

# Check with more detailed output
rkhunter --check --skip-keypress --report-warnings-only

# Update file properties database
rkhunter --propupd`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Run both tools for better coverage</li>
                      <li>Schedule regular scans</li>
                      <li>Update detection databases regularly</li>
                      <li>Investigate all warnings (many may be false positives)</li>
                      <li>Create a baseline on clean systems</li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Important Note</AlertTitle>
                    <AlertDescription>
                      If you suspect a rootkit infection, don&apos;t trust the infected system. Boot from a clean live CD/USB
                      and scan the system from there, as rootkits can hide from detection tools running on the
                      compromised system.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>OpenSCAP - Compliance Checking</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    OpenSCAP is a collection of tools for automated vulnerability scanning, configuration compliance,
                    and security policy enforcement.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Compliance checking against security standards (DISA STIG, PCI-DSS, etc.)</li>
                      <li>Vulnerability assessment</li>
                      <li>Security configuration assessment</li>
                      <li>Detailed reports in various formats</li>
                      <li>Integration with configuration management tools</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Installation and Usage</h3>
                    <CodeBlock
                      code={`# Install OpenSCAP
apt install openscap-scanner scap-security-guide

# List available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu20-ds.xml

# Run a scan with a specific profile
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml \
  --report scan-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu20-ds.xml

# Generate a remediation script
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --output fix-script.sh \
  scan-results.xml`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Available Security Profiles</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>CIS (Center for Internet Security) Benchmarks</li>
                      <li>DISA STIG (Security Technical Implementation Guides)</li>
                      <li>PCI-DSS (Payment Card Industry Data Security Standard)</li>
                      <li>NIST 800-53 Controls</li>
                      <li>HIPAA (Health Insurance Portability and Accountability Act)</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card className="md:col-span-2">
                <CardHeader>
                  <CardTitle>Additional Security Tools</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div>
                      <h3 className="font-semibold mb-2">Network Security</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Nmap:</strong> Network discovery and security auditing
                        </li>
                        <li>
                          <strong>Wireshark:</strong> Network protocol analyzer
                        </li>
                        <li>
                          <strong>tcpdump:</strong> Command-line packet analyzer
                        </li>
                        <li>
                          <strong>Snort/Suricata:</strong> Network intrusion detection/prevention
                        </li>
                        <li>
                          <strong>OpenVAS:</strong> Vulnerability scanner
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">System Security</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Tiger:</strong> Security audit and intrusion detection
                        </li>
                        <li>
                          <strong>Unhide:</strong> Forensic tool to find hidden processes
                        </li>
                        <li>
                          <strong>Firejail:</strong> Security sandbox program
                        </li>
                        <li>
                          <strong>BleachBit:</strong> System cleaner to protect privacy
                        </li>
                        <li>
                          <strong>Inspec:</strong> Infrastructure testing framework
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Encryption & Privacy</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>GnuPG:</strong> Encryption and signing tool
                        </li>
                        <li>
                          <strong>VeraCrypt:</strong> Disk encryption software
                        </li>
                        <li>
                          <strong>KeePassXC:</strong> Password manager
                        </li>
                        <li>
                          <strong>Tomb:</strong> File encryption tool
                        </li>
                        <li>
                          <strong>CryptSetup:</strong> Disk encryption with LUKS
                        </li>
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
                    href="https://nostarch.com/linuxsecurity"
                    className="text-primary hover:underline flex items-center"
                  >
                    Linux Hardening in Hostile Networks
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.oreilly.com/library/view/practical-linux-security/9781484266892/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Practical Linux Security Cookbook
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.packtpub.com/product/mastering-linux-security-and-hardening-second-edition/9781838981778"
                    className="text-primary hover:underline flex items-center"
                  >
                    Mastering Linux Security and Hardening
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
                    href="https://www.cybrary.it/course/linux-security/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Linux Security (Cybrary)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.udemy.com/course/linux-security/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Linux Security and Hardening (Udemy)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.sans.org/cyber-security-courses/securing-linux-unix/"
                    className="text-primary hover:underline flex items-center"
                  >
                    SANS SEC506: Securing Linux/Unix
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security Standards</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="https://www.cisecurity.org/benchmark/linux"
                    className="text-primary hover:underline flex items-center"
                  >
                    CIS Linux Benchmarks
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://public.cyber.mil/stigs/downloads/"
                    className="text-primary hover:underline flex items-center"
                  >
                    DISA STIGs for Linux
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://nvd.nist.gov/ncp/repository"
                    className="text-primary hover:underline flex items-center"
                  >
                    NIST National Checklist Program
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
