import { WindowsIcon } from "@/components/windows-icon"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { InfoIcon, ShieldAlert } from "lucide-react"
import Link from "next/link"
import { ExternalLink } from "lucide-react"
import { CodeBlock } from "@/components/code-block"

export default function WindowsPage() {
  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-6">
        <WindowsIcon className="h-8 w-8 text-primary" />
        <h1 className="text-4xl font-bold">🪟 Windows Security</h1>
      </div>

      <p className="text-xl text-muted-foreground mb-8">
        Windows systems are prevalent in enterprise environments and require robust security measures. This guide covers
        essential Windows security concepts, hardening techniques, and tools.
      </p>

      <Tabs defaultValue="fundamentals" className="mb-12">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="fundamentals">Fundamentals</TabsTrigger>
          <TabsTrigger value="active-directory">Active Directory</TabsTrigger>
          <TabsTrigger value="hardening">Hardening</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="tools">Security Tools</TabsTrigger>
        </TabsList>

        <TabsContent value="fundamentals" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Windows Security Fundamentals</h2>
            <p>
              Understanding the core security concepts in Windows is essential for building secure systems. Windows
              security is built on a foundation of authentication, access controls, and policy management.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Authentication Mechanisms</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows supports multiple authentication protocols and mechanisms to verify user identities and
                    control access to resources.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">NTLM Authentication</h3>
                    <p>
                      NT LAN Manager (NTLM) is a challenge-response authentication protocol used in Windows
                      environments:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Used for local authentication and legacy systems</li>
                      <li>Stores password hashes in the SAM database</li>
                      <li>Vulnerable to pass-the-hash attacks</li>
                      <li>NTLMv2 provides improved security over original NTLM</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Kerberos Authentication</h3>
                    <p>Kerberos is the default authentication protocol for Active Directory domains:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Ticket-based authentication system</li>
                      <li>Uses Key Distribution Center (KDC) for authentication</li>
                      <li>Provides mutual authentication</li>
                      <li>Vulnerable to pass-the-ticket and Golden Ticket attacks</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Hello</h3>
                    <p>Modern biometric and multi-factor authentication for Windows:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Facial recognition, fingerprint, and PIN</li>
                      <li>Uses asymmetric key pairs instead of passwords</li>
                      <li>Integrates with hardware security features (TPM)</li>
                      <li>Supports FIDO2 security keys</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Credential Manager</h3>
                    <p>Windows Credential Manager stores user credentials for websites, applications, and networks:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# List stored credentials
cmdkey /list

# Add a new credential
cmdkey /add:server /user:username /pass:password

# Delete a credential
cmdkey /delete:server

# PowerShell equivalent
Get-StoredCredential
New-StoredCredential -Target "server" -Username "username" -Password "password"
Remove-StoredCredential -Target "server"`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows File System Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    NTFS (New Technology File System) provides robust security features for controlling access to files
                    and folders in Windows.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">NTFS Permissions</h3>
                    <p>NTFS permissions control access to files and folders:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Full Control:</strong> Complete access to files and folders
                      </li>
                      <li>
                        <strong>Modify:</strong> Read, write, and delete files
                      </li>
                      <li>
                        <strong>Read & Execute:</strong> View and run files
                      </li>
                      <li>
                        <strong>List Folder Contents:</strong> View folder contents
                      </li>
                      <li>
                        <strong>Read:</strong> View file contents
                      </li>
                      <li>
                        <strong>Write:</strong> Create new files and modify existing ones
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Access Control Lists (ACLs)</h3>
                    <p>ACLs define who can access resources and what actions they can perform:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>DACL (Discretionary Access Control List):</strong> Controls access to objects
                      </li>
                      <li>
                        <strong>SACL (System Access Control List):</strong> Controls auditing of access attempts
                      </li>
                      <li>
                        <strong>ACE (Access Control Entry):</strong> Individual permission entry in an ACL
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Managing NTFS Permissions</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# View NTFS permissions
icacls C:\path\to\folder

# Grant permissions
icacls C:\path\to\folder /grant "Username:(OI)(CI)F"

# Remove permissions
icacls C:\path\to\folder /remove "Username"

# PowerShell equivalent
Get-Acl -Path "C:\path\to\folder" | Format-List

# Set permissions with PowerShell
$acl = Get-Acl -Path "C:\path\to\folder"
$permission = "Domain\Username","FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl | Set-Acl -Path "C:\path\to\folder"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Special NTFS Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>EFS (Encrypting File System):</strong> File-level encryption
                      </li>
                      <li>
                        <strong>Alternate Data Streams:</strong> Hidden data attached to files
                      </li>
                      <li>
                        <strong>Object Inheritance:</strong> Permissions flow down to child objects
                      </li>
                      <li>
                        <strong>Ownership:</strong> Control over who owns files and folders
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Registry Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Windows Registry is a hierarchical database that stores configuration settings and options. It&apos;s
                    a critical component for Windows security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Registry Structure</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>HKEY_LOCAL_MACHINE (HKLM):</strong> System-wide settings
                      </li>
                      <li>
                        <strong>HKEY_CURRENT_USER (HKCU):</strong> User-specific settings
                      </li>
                      <li>
                        <strong>HKEY_USERS (HKU):</strong> All user profiles
                      </li>
                      <li>
                        <strong>HKEY_CLASSES_ROOT (HKCR):</strong> File association and COM objects
                      </li>
                      <li>
                        <strong>HKEY_CURRENT_CONFIG (HKCC):</strong> Current hardware profile
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Registry Security Concerns</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>AutoRun and startup entries for persistence</li>
                      <li>Stored credentials and sensitive data</li>
                      <li>Security policy settings</li>
                      <li>Service configurations</li>
                      <li>Application settings that may contain vulnerabilities</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Registry Permissions</h3>
                    <p>Like files, registry keys have ACLs that control access:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# View registry permissions
Get-Acl -Path "HKLM:\SOFTWARE\Microsoft\Windows" | Format-List

# Set registry permissions
$acl = Get-Acl -Path "HKLM:\SOFTWARE\MyApp"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule("Username","ReadKey","Allow")
$acl.SetAccessRule($rule)
$acl | Set-Acl -Path "HKLM:\SOFTWARE\MyApp"

# Check for insecure registry permissions
Get-ChildItem "HKLM:\SOFTWARE" -Recurse | Get-Acl | Where-Object {$_.AccessToString -match "Everyone.*FullControl"}`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security-Critical Registry Keys</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code> - Startup programs
                      </li>
                      <li>
                        <code>HKLM\SYSTEM\CurrentControlSet\Services</code> - Windows services
                      </li>
                      <li>
                        <code>HKLM\SOFTWARE\Policies</code> - Group Policy settings
                      </li>
                      <li>
                        <code>HKLM\SAM</code> - Security Accounts Manager database
                      </li>
                      <li>
                        <code>HKLM\SECURITY</code> - Security policy settings
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>User Account Control (UAC)</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    User Account Control (UAC) is a security feature that helps prevent unauthorized changes to the
                    operating system by requiring administrator approval for certain actions.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">How UAC Works</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Standard users run with limited privileges by default</li>
                      <li>Admin users run with standard privileges until elevation is needed</li>
                      <li>Elevation prompts require explicit approval</li>
                      <li>Applications run in either elevated or non-elevated context</li>
                      <li>Secure Desktop isolates the UAC prompt from other applications</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">UAC Settings</h3>
                    <p>UAC can be configured through Group Policy or the Control Panel:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# View current UAC settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Change UAC settings (requires restart)
# 0 = Never notify, 1 = Notify only when apps try to make changes (no prompt for user changes)
# 2 = Always notify
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# Enable or disable UAC (0 = disabled, 1 = enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">UAC Bypass Techniques</h3>
                    <p>Security engineers should be aware of common UAC bypass methods:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Auto-elevation of trusted executables</li>
                      <li>DLL hijacking of system processes</li>
                      <li>Token manipulation</li>
                      <li>COM object elevation</li>
                      <li>File system and registry virtualization weaknesses</li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Security Best Practice</AlertTitle>
                    <AlertDescription>
                      Never disable UAC in production environments. Configure it to always notify when programs try to
                      make changes to the computer. Use standard user accounts for daily operations and only elevate
                      privileges when necessary.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Security in Depth</AlertTitle>
              <AlertDescription>
                Windows security should be implemented in layers. No single security control is sufficient. Combine
                proper authentication, file system security, registry protection, and user account controls for a
                comprehensive security posture.
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="active-directory" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Active Directory Security</h2>
            <p>
              Active Directory (AD) is the backbone of enterprise Windows environments. Securing AD is critical as it
              controls authentication, authorization, and resource access across the organization.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Active Directory Structure</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Understanding the structure of Active Directory is essential for implementing proper security
                    controls.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Components</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Domains:</strong> Administrative boundaries for users and resources
                      </li>
                      <li>
                        <strong>Forests:</strong> Collections of domains with trust relationships
                      </li>
                      <li>
                        <strong>Domain Controllers:</strong> Servers that authenticate users and store directory data
                      </li>
                      <li>
                        <strong>Organizational Units (OUs):</strong> Containers for organizing objects
                      </li>
                      <li>
                        <strong>Groups:</strong> Collections of users or computers for permission assignment
                      </li>
                      <li>
                        <strong>Group Policy Objects (GPOs):</strong> Collections of policy settings
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Boundaries</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Forest:</strong> The ultimate security boundary in AD
                      </li>
                      <li>
                        <strong>Domain:</strong> Administrative boundary with its own security policies
                      </li>
                      <li>
                        <strong>OU:</strong> Administrative unit for delegating permissions and applying GPOs
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Trust Relationships</h3>
                    <p>Trusts define how authentication works between domains and forests:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Two-way trusts:</strong> Both domains trust each other
                      </li>
                      <li>
                        <strong>One-way trusts:</strong> One domain trusts another, but not vice versa
                      </li>
                      <li>
                        <strong>Transitive trusts:</strong> Trust extends to other trusted domains
                      </li>
                      <li>
                        <strong>Non-transitive trusts:</strong> Trust limited to directly connected domains
                      </li>
                      <li>
                        <strong>External trusts:</strong> Connections to domains outside the forest
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Privileged Access Management</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Protecting privileged accounts is critical for AD security. These accounts have extensive access and
                    are prime targets for attackers.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Critical AD Accounts and Groups</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Enterprise Admins:</strong> Full control over all domains in the forest
                      </li>
                      <li>
                        <strong>Domain Admins:</strong> Full control over a specific domain
                      </li>
                      <li>
                        <strong>Schema Admins:</strong> Can modify the AD schema
                      </li>
                      <li>
                        <strong>Administrators:</strong> Local admin rights on domain controllers
                      </li>
                      <li>
                        <strong>Backup Operators:</strong> Can bypass file security to perform backups
                      </li>
                      <li>
                        <strong>Account Operators:</strong> Can create and modify user accounts
                      </li>
                      <li>
                        <strong>Server Operators:</strong> Can manage domain servers
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Tiered Administration Model</h3>
                    <p>Microsoft recommends a tiered approach to separate administrative privileges:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Tier 0:</strong> Domain controllers, AD, and identity systems
                      </li>
                      <li>
                        <strong>Tier 1:</strong> Server operating systems and applications
                      </li>
                      <li>
                        <strong>Tier 2:</strong> Workstations and devices
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Privileged Access Workstations (PAWs)</h3>
                    <p>Dedicated, hardened workstations for administrative tasks:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>No internet or email access</li>
                      <li>Restricted network connectivity</li>
                      <li>Enhanced security controls</li>
                      <li>Limited software installation</li>
                      <li>Regular patching and monitoring</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Just-In-Time (JIT) Administration</h3>
                    <p>Provide temporary elevated access only when needed:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Time-limited privileged access</li>
                      <li>Approval workflows for elevation</li>
                      <li>Detailed logging of privileged activities</li>
                      <li>Automatic removal of privileges after use</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Group Policy Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Group Policy Objects (GPOs) are powerful tools for implementing and enforcing security settings
                    across an AD environment.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Security Policies</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Password Policies:</strong> Length, complexity, history, age
                      </li>
                      <li>
                        <strong>Account Lockout Policies:</strong> Thresholds, duration, reset time
                      </li>
                      <li>
                        <strong>Audit Policies:</strong> Success/failure logging for security events
                      </li>
                      <li>
                        <strong>User Rights Assignment:</strong> Control who can perform specific actions
                      </li>
                      <li>
                        <strong>Security Options:</strong> Various security settings for the system
                      </li>
                      <li>
                        <strong>Software Restriction Policies:</strong> Control what software can run
                      </li>
                      <li>
                        <strong>AppLocker:</strong> Advanced application control
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">GPO Management Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use descriptive names for GPOs</li>
                      <li>Document GPO purposes and settings</li>
                      <li>Test GPOs before deployment</li>
                      <li>Use security filtering to target specific groups</li>
                      <li>Implement GPO change control processes</li>
                      <li>Regularly audit GPO settings</li>
                      <li>Use GPO modeling and results tools for troubleshooting</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Baseline GPOs</h3>
                    <p>Microsoft provides security baseline GPOs that can be imported and customized:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <Link
                          href="https://www.microsoft.com/en-us/download/details.aspx?id=55319"
                          className="text-primary hover:underline flex items-center"
                        >
                          Microsoft Security Compliance Toolkit
                          <ExternalLink className="h-3 w-3 ml-1" />
                        </Link>
                      </li>
                      <li>Includes baselines for Windows, Office, Edge, etc.</li>
                      <li>Provides Policy Analyzer tool for comparing policies</li>
                      <li>Updated regularly with new security recommendations</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">GPO Analysis Commands</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# List all GPOs in the domain
Get-GPO -All

# Get detailed information about a specific GPO
Get-GPO -Name "Security Baseline"

# Get GPO settings report
Get-GPOReport -Name "Security Baseline" -ReportType HTML -Path "C:\GPOReport.html"

# Find which GPOs have a specific setting
Find-GPO -Query "password complexity"

# Check which GPOs apply to a computer
Get-GPResultantSetOfPolicy -Computer "Workstation01" -ReportType HTML -Path "C:\RSoPReport.html"`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Active Directory Attack Vectors</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Understanding common AD attack vectors is essential for implementing effective defenses. These are
                    the techniques attackers use to compromise AD environments.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Credential Theft Attacks</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Pass-the-Hash:</strong> Using NTLM hashes without knowing the password
                      </li>
                      <li>
                        <strong>Pass-the-Ticket:</strong> Using Kerberos tickets to authenticate
                      </li>
                      <li>
                        <strong>Kerberoasting:</strong> Requesting and cracking service account tickets
                      </li>
                      <li>
                        <strong>AS-REP Roasting:</strong> Exploiting accounts with &quot;Do not require Kerberos
                        preauthentication&quot;
                      </li>
                      <li>
                        <strong>LSASS Memory Dumping:</strong> Extracting credentials from memory
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Privilege Escalation</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Kerberos Delegation:</strong> Exploiting unconstrained or constrained delegation
                      </li>
                      <li>
                        <strong>Group Policy Abuse:</strong> Modifying GPOs to execute code
                      </li>
                      <li>
                        <strong>ACL Abuse:</strong> Exploiting misconfigured permissions
                      </li>
                      <li>
                        <strong>Shadow Admins:</strong> Accounts with indirect administrative privileges
                      </li>
                      <li>
                        <strong>AdminSDHolder:</strong> Manipulating protected object permissions
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Persistence Mechanisms</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Golden Ticket:</strong> Forged Kerberos TGT using the KRBTGT hash
                      </li>
                      <li>
                        <strong>Silver Ticket:</strong> Forged Kerberos service ticket
                      </li>
                      <li>
                        <strong>DCShadow:</strong> Registering a rogue domain controller
                      </li>
                      <li>
                        <strong>Directory Service Restore Mode (DSRM):</strong> Abusing the DSRM password
                      </li>
                      <li>
                        <strong>Group Policy Preferences:</strong> Finding credentials in GPP files
                      </li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Defense Strategies</AlertTitle>
                    <AlertDescription>
                      <ul className="list-disc pl-5">
                        <li>Implement the principle of least privilege</li>
                        <li>Use Protected Users security group for sensitive accounts</li>
                        <li>Implement time-bound privileged access</li>
                        <li>Enable advanced audit policies</li>
                        <li>Use credential guard and device guard</li>
                        <li>Regularly rotate KRBTGT password</li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Active Directory Security Assessment</AlertTitle>
              <AlertDescription>
                Regularly assess your Active Directory security posture using tools like Microsoft&apos;s Active Directory
                Assessment Tool, PingCastle, or BloodHound. These tools can identify misconfigurations, excessive
                privileges, and potential attack paths that might not be obvious through manual inspection.
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="hardening" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Windows System Hardening</h2>
            <p>
              System hardening involves configuring Windows systems to minimize their attack surface and reduce
              vulnerabilities. This section covers essential hardening techniques for different components of Windows.
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
                    <p>Secure Boot ensures that only signed bootloaders and operating systems can be loaded:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enable Secure Boot in UEFI/BIOS</li>
                      <li>Use TPM (Trusted Platform Module) for enhanced security</li>
                      <li>Prevents bootkits and rootkits that modify the boot process</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">BitLocker Drive Encryption</h3>
                    <p>BitLocker provides full volume encryption to protect data at rest:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Check BitLocker status
Get-BitLockerVolume

# Enable BitLocker on system drive with TPM
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector

# Enable BitLocker with password
Enable-BitLocker -MountPoint "D:" -EncryptionMethod XtsAes256 -PasswordProtector

# Back up BitLocker recovery key to AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $(Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId

# Check BitLocker policy settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">BitLocker Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use TPM 2.0 with PIN for system drives</li>
                      <li>Use XTS-AES 256 encryption algorithm</li>
                      <li>Enable pre-boot authentication for higher security</li>
                      <li>Back up recovery keys to secure location (not on the same drive)</li>
                      <li>Encrypt all fixed data drives, not just the system drive</li>
                      <li>Use Group Policy to enforce BitLocker settings</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Defender Security Features</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows Defender provides a suite of security features that should be properly configured for
                    optimal protection.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Antivirus</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Check Windows Defender status
Get-MpComputerStatus

# Update signatures
Update-MpSignature

# Run a quick scan
Start-MpScan -ScanType QuickScan

# Run a full scan
Start-MpScan -ScanType FullScan

# Configure real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud-based protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Firewall</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Check firewall status
Get-NetFirewallProfile

# Enable firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block all inbound connections by default
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# Create a new firewall rule
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow

# Remove a firewall rule
Remove-NetFirewallRule -DisplayName "Allow SSH"

# Export firewall rules
Export-NetFirewallRule -FilePath "C:\firewall_rules.xml"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Exploit Guard</h3>
                    <p>Exploit Guard provides advanced protection against various attack techniques:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Exploit Protection:</strong> Mitigations for memory-based attacks
                      </li>
                      <li>
                        <strong>Attack Surface Reduction:</strong> Rules to block risky behaviors
                      </li>
                      <li>
                        <strong>Network Protection:</strong> Blocks connections to malicious sites
                      </li>
                      <li>
                        <strong>Controlled Folder Access:</strong> Prevents ransomware file encryption
                      </li>
                    </ul>
                    <CodeBlock
                      language="powershell"
                      code={`# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add a protected folder
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Important_Data"

# Allow an application through Controlled Folder Access
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Program Files\App\app.exe"

# Enable Network Protection
Set-MpPreference -EnableNetworkProtection Enabled

# Enable Attack Surface Reduction rules
Set-MpPreference -AttackSurfaceReductionRules_Ids <rule_id> -AttackSurfaceReductionRules_Actions Enabled`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Services and Features</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Properly configuring Windows services and features is essential for reducing the attack surface of
                    Windows systems.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Managing Windows Services</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# List all running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# List all auto-start services
Get-Service | Where-Object {$_.StartType -eq "Automatic"}

# Disable an unnecessary service
Set-Service -Name "ServiceName" -StartupType Disabled
Stop-Service -Name "ServiceName"

# Configure service recovery options
sc.exe failure "ServiceName" reset= 86400 actions= restart/60000/restart/60000/restart/60000

# Set service permissions
$sd = Get-ServiceAcl -Name "ServiceName"
$rule = New-AccessControlEntry -Principal "Users" -ServiceRights ReadControl,QueryConfig,QueryStatus
$sd.Access.AddAccessRule($rule)
Set-ServiceAcl -Name "ServiceName" -AclObject $sd`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Features and Roles</h3>
                    <p>Only install necessary Windows features and roles:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# List all installed features
Get-WindowsFeature | Where-Object {$_.Installed -eq $true}

# Install a feature
Install-WindowsFeature -Name "RSAT-AD-Tools"

# Remove an unnecessary feature
Remove-WindowsFeature -Name "Windows-Defender-GUI"

# List all optional features
Get-WindowsOptionalFeature -Online

# Disable an optional feature
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Recommended Services to Disable</h3>
                    <p>Consider disabling these services in non-essential scenarios:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Remote Registry:</strong> Allows remote registry editing
                      </li>
                      <li>
                        <strong>Print Spooler:</strong> If printing is not needed (PrintNightmare vulnerability)
                      </li>
                      <li>
                        <strong>UPnP Device Host:</strong> Automatic device discovery
                      </li>
                      <li>
                        <strong>Xbox Services:</strong> Gaming-related services
                      </li>
                      <li>
                        <strong>Windows Remote Management:</strong> If remote management is not needed
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Features to Disable</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>SMBv1:</strong> Legacy protocol with security vulnerabilities
                      </li>
                      <li>
                        <strong>PowerShell v2:</strong> Older version with fewer security features
                      </li>
                      <li>
                        <strong>LLMNR/NetBIOS:</strong> Can be exploited for credential theft
                      </li>
                      <li>
                        <strong>WebDAV:</strong> If not needed for web authoring
                      </li>
                      <li>
                        <strong>WPAD:</strong> Web Proxy Auto-Discovery Protocol
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Update and Patch Management</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Keeping Windows systems updated is one of the most important security measures. Proper patch
                    management helps protect against known vulnerabilities.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Update Configuration</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Check Windows Update settings
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

# Check for updates
Get-WindowsUpdate

# Install all available updates
Install-WindowsUpdate -AcceptAll

# View update history
Get-WUHistory

# Configure automatic updates via registry
# 2=Notify before download, 3=Auto download and notify, 4=Auto download and schedule install
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4

# Set automatic updates to install during scheduled time
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">WSUS Configuration</h3>
                    <p>
                      For enterprise environments, Windows Server Update Services (WSUS) provides centralized update
                      management:
                    </p>
                    <CodeBlock
                      language="powershell"
                      code={`# Configure WSUS server
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://wsus-server:8530"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://wsus-server:8530"

# Set client to use WSUS instead of Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1

# Force update detection
wuauclt /detectnow
UsoClient StartScan`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Patch Management Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Establish a regular patching schedule</li>
                      <li>Test patches in a non-production environment first</li>
                      <li>Prioritize security updates over feature updates</li>
                      <li>Document patch exceptions with compensating controls</li>
                      <li>Implement a vulnerability management program</li>
                      <li>Monitor for failed updates and remediate promptly</li>
                      <li>Consider third-party patch management tools for non-Microsoft applications</li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Critical Security Note</AlertTitle>
                    <AlertDescription>
                      For internet-facing servers and critical systems, consider implementing an emergency patching
                      process for zero-day vulnerabilities. Don&apos;t wait for the regular patch cycle when critical
                      vulnerabilities are being actively exploited.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card className="md:col-span-2">
                <CardHeader>
                  <CardTitle>Windows Security Baselines</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Microsoft provides security baselines that offer a comprehensive set of recommended security
                    settings for Windows systems.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <h3 className="font-semibold mb-2">Security Baseline Components</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>Account Policies</li>
                        <li>Local Policies</li>
                        <li>Event Log Settings</li>
                        <li>Restricted Groups</li>
                        <li>Registry Settings</li>
                        <li>File System Permissions</li>
                        <li>Audit Policies</li>
                        <li>User Rights Assignments</li>
                        <li>Security Options</li>
                        <li>Windows Firewall Settings</li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Implementation Tools</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Security Compliance Toolkit (SCT):</strong> Microsoft&apos;s official toolkit
                        </li>
                        <li>
                          <strong>Group Policy:</strong> Deploy settings via GPOs
                        </li>
                        <li>
                          <strong>Microsoft Endpoint Manager:</strong> Deploy to managed devices
                        </li>
                        <li>
                          <strong>PowerShell DSC:</strong> Desired State Configuration
                        </li>
                        <li>
                          <strong>LGPO.exe:</strong> Local Group Policy Object utility
                        </li>
                      </ul>
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Implementing Security Baselines</h3>
                    <ol className="space-y-1 list-decimal pl-5">
                      <li>Download the Microsoft Security Compliance Toolkit</li>
                      <li>Import the baseline GPOs into your Group Policy Management Console</li>
                      <li>Review and customize settings as needed for your environment</li>
                      <li>Test the baseline in a non-production environment</li>
                      <li>Create a deployment plan (phased approach recommended)</li>
                      <li>Deploy to production</li>
                      <li>Monitor for issues and adjust as needed</li>
                      <li>Document exceptions and compensating controls</li>
                    </ol>
                  </div>

                  <Alert>
                    <InfoIcon className="h-4 w-4" />
                    <AlertTitle>Security Baseline Resources</AlertTitle>
                    <AlertDescription>
                      <p className="mb-2">
                        Microsoft provides security baselines for various Windows versions and products:
                      </p>
                      <ul className="list-disc pl-5">
                        <li>
                          <Link
                            href="https://www.microsoft.com/en-us/download/details.aspx?id=55319"
                            className="text-primary hover:underline flex items-center"
                          >
                            Microsoft Security Compliance Toolkit
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                        <li>
                          <Link
                            href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines"
                            className="text-primary hover:underline flex items-center"
                          >
                            Windows Security Baselines Documentation
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                        <li>
                          <Link
                            href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10"
                            className="text-primary hover:underline flex items-center"
                          >
                            Security Compliance Toolkit Documentation
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

        <TabsContent value="monitoring" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Windows Security Monitoring</h2>
            <p>
              Effective security monitoring is essential for detecting and responding to security incidents in Windows
              environments. This section covers Windows Event Logging, auditing, and monitoring tools.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Windows Event Logging</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows Event Logs are the primary source of security information in Windows systems. Proper
                    configuration and monitoring of these logs is critical for security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Event Logs</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Security:</strong> Authentication events, privilege use, policy changes
                      </li>
                      <li>
                        <strong>System:</strong> System-level events, service starts/stops, driver loading
                      </li>
                      <li>
                        <strong>Application:</strong> Application-specific events
                      </li>
                      <li>
                        <strong>PowerShell:</strong> PowerShell script execution and module loading
                      </li>
                      <li>
                        <strong>AppLocker:</strong> Application execution control
                      </li>
                      <li>
                        <strong>Windows Defender:</strong> Malware detection and remediation
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Event Log Configuration</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# View event log properties
Get-EventLog -List

# View event log settings
wevtutil gl Security

# Set log size
wevtutil sl Security /ms:1073741824

# Set retention policy (archive when full)
wevtutil sl Security /rt:true

# Configure log forwarding
wevtutil sl Security /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;OU)(A;;0x1;;;S-1-5-21-123456789-123456789-123456789-123456)

# Enable advanced audit policies
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# View current audit policy
auditpol /get /category:*`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Critical Events to Monitor</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>4624/4625:</strong> Successful/failed logon
                      </li>
                      <li>
                        <strong>4720/4722/4724:</strong> Account creation/enabled/password change
                      </li>
                      <li>
                        <strong>4728/4732/4756:</strong> Member added to security-enabled group
                      </li>
                      <li>
                        <strong>4776:</strong> Credential validation
                      </li>
                      <li>
                        <strong>4648:</strong> Logon with explicit credentials
                      </li>
                      <li>
                        <strong>4672:</strong> Special privileges assigned to new logon
                      </li>
                      <li>
                        <strong>7045/4697:</strong> Service installation
                      </li>
                      <li>
                        <strong>4698/4699/4700/4701/4702:</strong> Scheduled task operations
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Querying Event Logs</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Get recent security events
Get-WinEvent -LogName Security -MaxEvents 100

# Search for failed logon attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}

# Search for account lockouts
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740}

# Search for PowerShell script execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}

# Search for events with specific text
Get-WinEvent -FilterHashtable @{LogName='Security'} | Where-Object {$_.Message -like "*administrator*"}

# Export events to CSV
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Export-Csv -Path "C:\FailedLogins.csv" -NoTypeInformation`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Advanced Auditing Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows Advanced Audit Policy Configuration provides granular control over what security events are
                    logged. Proper audit configuration is essential for effective security monitoring.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Audit Policy Categories</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Account Logon:</strong> Authentication events
                      </li>
                      <li>
                        <strong>Account Management:</strong> Account creation, modification, deletion
                      </li>
                      <li>
                        <strong>Detailed Tracking:</strong> Process creation and termination
                      </li>
                      <li>
                        <strong>DS Access:</strong> Active Directory access
                      </li>
                      <li>
                        <strong>Logon/Logoff:</strong> Session creation and termination
                      </li>
                      <li>
                        <strong>Object Access:</strong> File, registry, and other object access
                      </li>
                      <li>
                        <strong>Policy Change:</strong> Changes to security policies
                      </li>
                      <li>
                        <strong>Privilege Use:</strong> Use of user rights
                      </li>
                      <li>
                        <strong>System:</strong> System-level events
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Recommended Audit Policies</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable

# Detailed Tracking
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Object Access
auditpol /set /subcategory:"File System" /success:disable /failure:enable
auditpol /set /subcategory:"Registry" /success:disable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:disable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Object-Level Auditing</h3>
                    <p>Configure auditing for specific files, folders, and registry keys:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Enable auditing on a sensitive folder
$acl = Get-Acl -Path "C:\Sensitive"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone","ReadData","None","None","Success")
$acl.AddAuditRule($rule)
$acl | Set-Acl -Path "C:\Sensitive"

# Enable auditing on a registry key
$acl = Get-Acl -Path "HKLM:\SOFTWARE\Sensitive"
$rule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone","ReadKey","None","None","Success")
$acl.AddAuditRule($rule)
$acl | Set-Acl -Path "HKLM:\SOFTWARE\Sensitive"`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Sysmon Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    System Monitor (Sysmon) is a Windows system service that monitors and logs system activity to the
                    Windows event log. It provides detailed information about process creations, network connections,
                    and changes to file creation time.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Installing Sysmon</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"

# Install Sysmon with default configuration
C:\Sysmon\Sysmon64.exe -i

# Install Sysmon with custom configuration
C:\Sysmon\Sysmon64.exe -i C:\Sysmon\sysmonconfig.xml

# Update Sysmon configuration
C:\Sysmon\Sysmon64.exe -c C:\Sysmon\sysmonconfig.xml

# Uninstall Sysmon
C:\Sysmon\Sysmon64.exe -u`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Sysmon Events</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Event ID 1:</strong> Process creation
                      </li>
                      <li>
                        <strong>Event ID 2:</strong> File creation time changed
                      </li>
                      <li>
                        <strong>Event ID 3:</strong> Network connection
                      </li>
                      <li>
                        <strong>Event ID 4:</strong> Sysmon service state changed
                      </li>
                      <li>
                        <strong>Event ID 5:</strong> Process terminated
                      </li>
                      <li>
                        <strong>Event ID 6:</strong> Driver loaded
                      </li>
                      <li>
                        <strong>Event ID 7:</strong> Image loaded
                      </li>
                      <li>
                        <strong>Event ID 8:</strong> CreateRemoteThread
                      </li>
                      <li>
                        <strong>Event ID 9:</strong> RawAccessRead
                      </li>
                      <li>
                        <strong>Event ID 10:</strong> ProcessAccess
                      </li>
                      <li>
                        <strong>Event ID 11:</strong> FileCreate
                      </li>
                      <li>
                        <strong>Event ID 12/13/14:</strong> Registry operations
                      </li>
                      <li>
                        <strong>Event ID 15:</strong> FileCreateStreamHash
                      </li>
                      <li>
                        <strong>Event ID 16:</strong> ServiceConfigurationChange
                      </li>
                      <li>
                        <strong>Event ID 17/18:</strong> PipeEvent
                      </li>
                      <li>
                        <strong>Event ID 19/20/21:</strong> WmiEvent
                      </li>
                      <li>
                        <strong>Event ID 22:</strong> DNSQuery
                      </li>
                      <li>
                        <strong>Event ID 23:</strong> FileDelete
                      </li>
                      <li>
                        <strong>Event ID 24:</strong> ClipboardChange
                      </li>
                      <li>
                        <strong>Event ID 25:</strong> ProcessTampering
                      </li>
                      <li>
                        <strong>Event ID 26:</strong> FileDeleteDetected
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Querying Sysmon Events</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# View all Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"

# View process creation events
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1}

# View network connection events
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3}

# Search for specific process
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | Where-Object {$_.Message -like "*cmd.exe*"}

# Search for connections to specific IP
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3} | Where-Object {$_.Message -like "*10.0.0.1*"}`}
                    />
                  </div>

                  <Alert>
                    <InfoIcon className="h-4 w-4" />
                    <AlertTitle>Sysmon Configuration Resources</AlertTitle>
                    <AlertDescription>
                      <p>For effective Sysmon deployment, use community-maintained configuration files:</p>
                      <ul className="list-disc pl-5 mt-2">
                        <li>
                          <Link
                            href="https://github.com/SwiftOnSecurity/sysmon-config"
                            className="text-primary hover:underline flex items-center"
                          >
                            SwiftOnSecurity Sysmon Config
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                        <li>
                          <Link
                            href="https://github.com/olafhartong/sysmon-modular"
                            className="text-primary hover:underline flex items-center"
                          >
                            Sysmon Modular
                            <ExternalLink className="h-3 w-3 ml-1" />
                          </Link>
                        </li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Event Forwarding</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows Event Forwarding (WEF) allows you to collect events from multiple Windows systems in a
                    centralized location, making it easier to monitor and analyze security events across your
                    environment.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Setting Up Event Forwarding</h3>
                    <p>Configure the collector server:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Enable Windows Remote Management
winrm quickconfig

# Configure the event collector service
wecutil qc

# Create a subscription
wecutil cs "C:\Subscriptions\SecurityEvents.xml"

# View subscriptions
wecutil gs

# Check subscription status
wecutil gr "SecurityEvents"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Configure Source Computers</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Configure via Group Policy
# Computer Configuration > Policies > Administrative Templates > Windows Components > Event Forwarding
# Enable "Configure target Subscription Manager"
# Value: Server=http://collector.domain.com:5985/wsman/SubscriptionManager/WEC

# Configure via PowerShell
$Uri = "Server=http://collector.domain.com:5985/wsman/SubscriptionManager/WEC"
$Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
New-Item -Path $Key -Force
New-ItemProperty -Path $Key -Name 1 -Value $Uri -PropertyType String -Force

# Configure Windows Remote Management
winrm quickconfig

# Configure the Windows Event Collector service to start automatically
Set-Service -Name Wecsvc -StartupType Automatic
Start-Service -Name Wecsvc`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Sample Subscription XML</h3>
                    <CodeBlock
                      language="xml"
                      code={`<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>SecurityEvents</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>Collects security events from domain computers</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>Normal</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>5</MaxItems>
      <MaxLatencyTime>900000</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="900000"/>
    </PushSettings>
  </Delivery>
  <Query>
    <![CDATA[
      <QueryList>
        <Query Id="0">
          <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728)]]</Select>
          <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
          <Select Path="System">*[System[(EventID=7045)]]</Select>
        </Query>
      </QueryList>
    ]]>
  </Query>
  <ReadExistingEvents>false</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers>
    <AllowedSubjectList/>
  </AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>O:NSG:BAD:P(A;;GA;;;DC)S:</AllowedSourceDomainComputers>
</Subscription>`}
                    />
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Security Considerations</AlertTitle>
                    <AlertDescription>
                      <ul className="list-disc pl-5">
                        <li>Use HTTPS (port 5986) instead of HTTP (port 5985) for encrypted transport</li>
                        <li>Implement proper access controls on the collector server</li>
                        <li>Be selective about which events to forward to avoid overwhelming the collector</li>
                        <li>Consider using source-initiated subscriptions for better scalability</li>
                        <li>Monitor the health of the event forwarding infrastructure</li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Comprehensive Monitoring Strategy</AlertTitle>
              <AlertDescription>
                <p>An effective Windows security monitoring strategy combines multiple approaches:</p>
                <ul className="list-disc pl-5 mt-2">
                  <li>Windows Event Logging for system and security events</li>
                  <li>Sysmon for detailed process and network monitoring</li>
                  <li>Windows Event Forwarding for centralized collection</li>
                  <li>Security Information and Event Management (SIEM) for correlation and analysis</li>
                  <li>Endpoint Detection and Response (EDR) for advanced threat detection</li>
                  <li>Regular review of logs and alerts</li>
                  <li>Automated response to common security events</li>
                </ul>
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="tools" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Windows Security Tools</h2>
            <p>
              A variety of specialized security tools are available for Windows systems. These tools help with
              vulnerability assessment, security auditing, malware detection, and more.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Sysinternals Suite</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The Sysinternals Suite is a collection of advanced system utilities and technical information
                    created by Mark Russinovich. These tools are essential for Windows security professionals.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Sysinternals Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Process Explorer:</strong> Advanced task manager
                      </li>
                      <li>
                        <strong>Process Monitor:</strong> Real-time file, registry, and process monitoring
                      </li>
                      <li>
                        <strong>Autoruns:</strong> Startup program viewer
                      </li>
                      <li>
                        <strong>TCPView:</strong> Network connection viewer
                      </li>
                      <li>
                        <strong>PsExec:</strong> Remote command execution
                      </li>
                      <li>
                        <strong>Sysmon:</strong> System activity monitoring
                      </li>
                      <li>
                        <strong>AccessChk:</strong> Permission checking utility
                      </li>
                      <li>
                        <strong>LogonSessions:</strong> List active logon sessions
                      </li>
                      <li>
                        <strong>ProcDump:</strong> Process dump utility
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Using Sysinternals Tools</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Access tools directly from web
\\live.sysinternals.com\tools\procexp.exe

# Download the entire suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\SysinternalsSuite.zip"
Expand-Archive -Path "C:\SysinternalsSuite.zip" -DestinationPath "C:\SysinternalsSuite"

# Run Process Explorer
C:\SysinternalsSuite\procexp.exe

# Run Autoruns with admin privileges
Start-Process -FilePath "C:\SysinternalsSuite\autoruns.exe" -Verb RunAs

# Use PsExec to run commands remotely
C:\SysinternalsSuite\psexec.exe \\remotemachine -u domain\(username) -p password cmd.exe

# Check permissions with AccessChk
C:\SysinternalsSuite\accesschk.exe -s -d C:\Windows\System32

# View logon sessions
C:\SysinternalsSuite\logonsessions.exe -p`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Use Cases</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Identifying malicious processes and their relationships</li>
                      <li>Detecting persistence mechanisms with Autoruns</li>
                      <li>Monitoring file and registry access in real-time</li>
                      <li>Analyzing network connections for suspicious activity</li>
                      <li>Checking for permission misconfigurations</li>
                      <li>Creating memory dumps for malware analysis</li>
                      <li>Investigating user sessions and process ownership</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>PowerShell Security Tools</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    PowerShell provides powerful capabilities for security professionals. Several PowerShell modules and
                    scripts are available specifically for security tasks.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">PowerShell Security Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Script Block Logging:</strong> Records PowerShell script blocks
                      </li>
                      <li>
                        <strong>Transcription:</strong> Records PowerShell session input/output
                      </li>
                      <li>
                        <strong>Constrained Language Mode:</strong> Restricts PowerShell capabilities
                      </li>
                      <li>
                        <strong>AMSI Integration:</strong> Anti-malware scanning of scripts
                      </li>
                      <li>
                        <strong>Just Enough Administration (JEA):</strong> Role-based administration
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Enabling PowerShell Security Features</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Enable Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWORD -Force

# Enable PowerShell Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PowerShellLogs" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWORD -Force

# Set PowerShell Execution Policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Enable Protected Event Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" -Name "EnableProtectedEventLogging" -Value 1 -Type DWORD -Force`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Useful PowerShell Security Modules</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>PowerSploit:</strong> Penetration testing framework
                      </li>
                      <li>
                        <strong>PSReflect:</strong> Reflection for accessing Win32 APIs
                      </li>
                      <li>
                        <strong>PowerUp:</strong> Privilege escalation checks
                      </li>
                      <li>
                        <strong>PowerView:</strong> Active Directory enumeration
                      </li>
                      <li>
                        <strong>Invoke-Obfuscation:</strong> Script obfuscation (for testing defenses)
                      </li>
                      <li>
                        <strong>PoshC2:</strong> Command and control framework
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Auditing with PowerShell</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Check for administrative users
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, PrincipalSource

# Find files with sensitive data
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | Select-String -Pattern "password|credential|secret" | Export-Csv -Path "C:\sensitive_data.csv" -NoTypeInformation

# Check for unquoted service paths
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch '^"' -and $_.PathName -match ' '} | Select-Object Name, DisplayName, PathName

# Find scheduled tasks that run as SYSTEM
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"} | Format-Table TaskName, TaskPath, State

# Check for users who haven't changed passwords in 90 days
Get-LocalUser | Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-90)} | Format-Table Name, Enabled, PasswordLastSet`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Windows Defender Advanced Tools</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Windows Defender includes several advanced security tools that provide enhanced protection and
                    analysis capabilities.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Application Guard</h3>
                    <p>Application Guard uses hardware virtualization to isolate untrusted websites and documents:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Install Windows Defender Application Guard
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard

# Configure Application Guard settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWORD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowClipboardOperation" -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPrinting" -Value 0 -Type DWORD`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Credential Guard</h3>
                    <p>Credential Guard uses virtualization-based security to isolate credential information:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Enable Credential Guard using Group Policy
# Computer Configuration > Administrative Templates > System > Device Guard
# "Turn On Virtualization Based Security" = Enabled
# "Select Platform Security Level" = Secure Boot and DMA Protection
# "Credential Guard Configuration" = Enabled with UEFI lock

# Enable Credential Guard using PowerShell
$securitySettings = Get-WmiObject -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard
if ($securitySettings.VirtualizationBasedSecurityStatus -eq 0) {
    Write-Host "Virtualization Based Security is not running. Check hardware requirements."
} else {
    # Enable Credential Guard
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 3 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -PropertyType DWORD -Force
}`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender Application Control (WDAC)</h3>
                    <p>WDAC (formerly Device Guard) provides application whitelisting capabilities:</p>
                    <CodeBlock
                      language="powershell"
                      code={`# Create a new WDAC policy
New-CIPolicy -Level PcaCertificate -FilePath C:\Windows\Temp\policy.xml -UserPEs -ScanPath C:\Windows

# Convert policy to binary format
ConvertFrom-CIPolicy -XmlFilePath C:\Windows\Temp\policy.xml -BinaryFilePath C:\Windows\System32\CodeIntegrity\CiPolicies\Active\policy.bin

# Deploy the policy
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = "C:\Windows\Temp\policy.xml"}

# Check WDAC status
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName Win32_SystemCodeIntegrityPolicy | Format-List *`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Windows Defender for Endpoint</h3>
                    <p>
                      Windows Defender for Endpoint (formerly Advanced Threat Protection) provides advanced threat
                      detection and response capabilities:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Endpoint behavioral sensors</li>
                      <li>Cloud security analytics</li>
                      <li>Threat intelligence</li>
                      <li>Automated investigation and remediation</li>
                      <li>Secure score and vulnerability management</li>
                      <li>Integration with Microsoft 365 Defender</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Third-Party Security Tools</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Several third-party tools complement Windows&apos; built-in security features and provide additional
                    capabilities for security professionals.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <h3 className="font-semibold mb-2">Vulnerability Assessment</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Nessus:</strong> Comprehensive vulnerability scanner
                        </li>
                        <li>
                          <strong>OpenVAS:</strong> Open-source vulnerability scanner
                        </li>
                        <li>
                          <strong>Microsoft Baseline Security Analyzer:</strong> Security configuration assessment
                        </li>
                        <li>
                          <strong>Nexpose:</strong> Vulnerability management solution
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Penetration Testing</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Metasploit:</strong> Exploitation framework
                        </li>
                        <li>
                          <strong>Mimikatz:</strong> Credential extraction tool
                        </li>
                        <li>
                          <strong>BloodHound:</strong> Active Directory attack path visualization
                        </li>
                        <li>
                          <strong>Responder:</strong> LLMNR/NBT-NS/mDNS poisoner
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Forensics and Incident Response</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Volatility:</strong> Memory forensics framework
                        </li>
                        <li>
                          <strong>KAPE:</strong> Kroll Artifact Parser and Extractor
                        </li>
                        <li>
                          <strong>Redline:</strong> Memory and file analysis
                        </li>
                        <li>
                          <strong>Autopsy:</strong> Digital forensics platform
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Monitoring and Analysis</h3>
                      <ul className="space-y-1 list-disc pl-5">
                        <li>
                          <strong>Splunk:</strong> Log management and analysis
                        </li>
                        <li>
                          <strong>ELK Stack:</strong> Elasticsearch, Logstash, Kibana
                        </li>
                        <li>
                          <strong>Graylog:</strong> Log management platform
                        </li>
                        <li>
                          <strong>Wazuh:</strong> Security monitoring solution
                        </li>
                      </ul>
                    </div>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Assessment Frameworks</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>CIS-CAT:</strong> CIS Configuration Assessment Tool
                      </li>
                      <li>
                        <strong>Microsoft Security Compliance Toolkit:</strong> Security baseline assessment
                      </li>
                      <li>
                        <strong>PingCastle:</strong> Active Directory security assessment
                      </li>
                      <li>
                        <strong>PowerShell Empire:</strong> Post-exploitation framework
                      </li>
                    </ul>
                  </div>

                  <Alert>
                    <ShieldAlert className="h-4 w-4" />
                    <AlertTitle>Ethical Use Warning</AlertTitle>
                    <AlertDescription>
                      Many security tools can be used for both defensive and offensive purposes. Always ensure you have
                      proper authorization before using these tools in any environment. Use them ethically and legally
                      to improve security posture, not to compromise systems without permission.
                    </AlertDescription>
                  </Alert>
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
                    href="https://www.microsoftpressstore.com/store/windows-server-2022-security-best-practices-9780137918645"
                    className="text-primary hover:underline flex items-center"
                  >
                    Windows Server Security Best Practices
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.packtpub.com/product/mastering-windows-security-and-hardening-second-edition/9781839216411"
                    className="text-primary hover:underline flex items-center"
                  >
                    Mastering Windows Security and Hardening
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.wiley.com/en-us/Active+Directory+For+Dummies%2C+3rd+Edition-p-9781119795780"
                    className="text-primary hover:underline flex items-center"
                  >
                    Active Directory For Dummies
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
                    href="https://www.pluralsight.com/paths/securing-windows-server"
                    className="text-primary hover:underline flex items-center"
                  >
                    Securing Windows Server (Pluralsight)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.udemy.com/course/windows-security/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Windows Security Fundamentals (Udemy)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.sans.org/cyber-security-courses/securing-windows-with-powershell/"
                    className="text-primary hover:underline flex items-center"
                  >
                    SANS SEC505: Securing Windows with PowerShell
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
                    href="https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
                    className="text-primary hover:underline flex items-center"
                  >
                    CIS Windows Benchmarks
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://public.cyber.mil/stigs/downloads/"
                    className="text-primary hover:underline flex items-center"
                  >
                    DISA STIGs for Windows
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines"
                    className="text-primary hover:underline flex items-center"
                  >
                    Microsoft Security Baselines
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
