import { Cloud } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { InfoIcon, ShieldAlert } from "lucide-react"
import Link from "next/link"
import { ExternalLink } from "lucide-react"
import { CodeBlock } from "@/components/code-block"

export default function CloudPage() {
  return (
    <div className="max-w-5xl mx-auto">
      <div className="flex items-center gap-3 mb-6">
        <Cloud className="h-8 w-8 text-primary" />
        <h1 className="text-4xl font-bold">☁️ Cloud Security</h1>
      </div>

      <p className="text-xl text-muted-foreground mb-8">
        Cloud computing has transformed how organizations build and deploy applications. This guide covers essential
        cloud security concepts, best practices, and tools to secure cloud environments across major providers.
      </p>

      <Tabs defaultValue="fundamentals" className="mb-12">
        <TabsList className="grid w-full grid-cols-5">
          <TabsTrigger value="fundamentals">Fundamentals</TabsTrigger>
          <TabsTrigger value="identity">Identity & Access</TabsTrigger>
          <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
          <TabsTrigger value="data">Data Protection</TabsTrigger>
          <TabsTrigger value="devsecops">DevSecOps</TabsTrigger>
        </TabsList>

        <TabsContent value="fundamentals" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Cloud Security Fundamentals</h2>
            <p>
              Understanding the core security concepts in cloud computing is essential for building secure cloud
              environments. Cloud security requires a different approach compared to traditional on-premises security.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Shared Responsibility Model</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    The shared responsibility model defines the security responsibilities divided between cloud providers
                    and customers. Understanding this model is crucial for effective cloud security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Provider Responsibilities</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Physical security of data centers</li>
                      <li>Network infrastructure security</li>
                      <li>Hypervisor security</li>
                      <li>Storage infrastructure security</li>
                      <li>Service availability and reliability</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Customer Responsibilities</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Identity and access management</li>
                      <li>Data classification and protection</li>
                      <li>Operating system security (for IaaS)</li>
                      <li>Network and firewall configuration</li>
                      <li>Application security</li>
                      <li>Client and endpoint security</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Responsibility by Service Model</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>IaaS (Infrastructure as a Service):</strong> Customer manages OS, middleware,
                        applications, data
                      </li>
                      <li>
                        <strong>PaaS (Platform as a Service):</strong> Customer manages applications and data
                      </li>
                      <li>
                        <strong>SaaS (Software as a Service):</strong> Customer primarily manages data and access
                      </li>
                    </ul>
                  </div>

                  <div className="mt-4">
                    {/* <img
                      src="/placeholder.svg?height=300&width=500"
                      alt="Shared Responsibility Model Diagram"
                      className="rounded-md border"
                    /> */}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Cloud Security Principles</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Key principles that should guide your approach to cloud security across all environments and
                    providers.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Defense in Depth</h3>
                    <p>
                      Implement multiple layers of security controls throughout your cloud environment to protect
                      against various threats:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Identity and access controls</li>
                      <li>Network security</li>
                      <li>Application security</li>
                      <li>Data protection</li>
                      <li>Monitoring and detection</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Least Privilege</h3>
                    <p>
                      Grant only the minimum permissions necessary for users and services to perform their required
                      functions:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Role-based access control (RBAC)</li>
                      <li>Just-in-time access</li>
                      <li>Regular access reviews</li>
                      <li>Service-specific permissions</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Zero Trust</h3>
                    <p>
                      Assume no implicit trust based on network location; verify every access request regardless of
                      source:
                    </p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>&quot;Never trust, always verify&quot;</li>
                      <li>Strong authentication for all access</li>
                      <li>Micro-segmentation</li>
                      <li>Continuous validation</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Automation and Infrastructure as Code</h3>
                    <p>Automate security controls and configurations to ensure consistency and reduce human error:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Security as code</li>
                      <li>Automated compliance checks</li>
                      <li>Immutable infrastructure</li>
                      <li>Automated incident response</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Cloud Security Threats</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Cloud environments face unique security threats that differ from traditional on-premises
                    environments. Understanding these threats is essential for effective defense.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Misconfiguration</h3>
                    <p>The most common cause of cloud security incidents:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Exposed storage buckets</li>
                      <li>Overly permissive IAM policies</li>
                      <li>Unpatched systems</li>
                      <li>Default credentials</li>
                      <li>Open security groups/firewall rules</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Account Compromise</h3>
                    <p>Attackers targeting cloud service accounts:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Credential theft</li>
                      <li>API key exposure</li>
                      <li>Phishing attacks</li>
                      <li>Password spraying</li>
                      <li>Privilege escalation</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Insecure APIs</h3>
                    <p>Vulnerabilities in cloud service APIs:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Weak authentication</li>
                      <li>Lack of encryption</li>
                      <li>Insufficient rate limiting</li>
                      <li>Inadequate input validation</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Advanced Threats</h3>
                    <p>Sophisticated attacks targeting cloud environments:</p>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Supply chain attacks</li>
                      <li>Container escape vulnerabilities</li>
                      <li>Side-channel attacks</li>
                      <li>Malicious insider threats</li>
                      <li>Advanced persistent threats (APTs)</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Cloud Security Compliance</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Cloud environments must comply with various regulatory requirements and industry standards.
                    Understanding these frameworks is essential for maintaining compliance in the cloud.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key Compliance Frameworks</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>GDPR:</strong> European data protection regulation
                      </li>
                      <li>
                        <strong>HIPAA:</strong> US healthcare data protection
                      </li>
                      <li>
                        <strong>PCI DSS:</strong> Payment card industry security standard
                      </li>
                      <li>
                        <strong>SOC 2:</strong> Service organization controls
                      </li>
                      <li>
                        <strong>ISO 27001/27017/27018:</strong> Information security standards
                      </li>
                      <li>
                        <strong>FedRAMP:</strong> US government cloud security standard
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Compliance Challenges in the Cloud</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Data residency and sovereignty requirements</li>
                      <li>Shared responsibility understanding</li>
                      <li>Dynamic and ephemeral resources</li>
                      <li>Third-party service integration</li>
                      <li>Continuous compliance monitoring</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Compliance Tools and Approaches</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Cloud provider compliance programs and certifications</li>
                      <li>Automated compliance scanning and reporting</li>
                      <li>Continuous compliance monitoring</li>
                      <li>Compliance as code</li>
                      <li>Third-party compliance tools</li>
                    </ul>
                  </div>

                  <Alert>
                    <InfoIcon className="h-4 w-4" />
                    <AlertTitle>Provider Compliance Programs</AlertTitle>
                    <AlertDescription>
                      <p className="mb-2">Major cloud providers offer compliance programs to help customers:</p>
                      <ul className="list-disc pl-5">
                        <li>AWS Artifact</li>
                        <li>Microsoft Azure Compliance</li>
                        <li>Google Cloud Compliance Resource Center</li>
                      </ul>
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Cloud Security Alliance (CSA)</AlertTitle>
              <AlertDescription>
                The Cloud Security Alliance provides valuable resources for cloud security, including the Cloud Controls
                Matrix (CCM) and Security Guidance for Critical Areas of Focus in Cloud Computing. These resources offer
                comprehensive guidance for securing cloud environments across different service models and providers.
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="identity" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Identity and Access Management</h2>
            <p>
              Identity and Access Management (IAM) is the foundation of cloud security. Properly managing identities and
              access controls is critical for protecting cloud resources from unauthorized access.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>IAM Best Practices</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Implementing these IAM best practices will help secure your cloud environment across all major
                    providers.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Principle of Least Privilege</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Grant only the permissions necessary for the task</li>
                      <li>Use role-based access control (RBAC)</li>
                      <li>Implement just-in-time access</li>
                      <li>Regularly review and revoke unnecessary permissions</li>
                      <li>Use permission boundaries to limit maximum privileges</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Strong Authentication</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enforce multi-factor authentication (MFA) for all users</li>
                      <li>Use strong password policies</li>
                      <li>Implement conditional access policies</li>
                      <li>Consider passwordless authentication methods</li>
                      <li>Secure API keys and service accounts</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Centralized Identity Management</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use single sign-on (SSO) across cloud services</li>
                      <li>Integrate with enterprise identity providers</li>
                      <li>Implement federated identity management</li>
                      <li>Centralize user lifecycle management</li>
                      <li>Maintain a single source of truth for identities</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Regular Access Reviews</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Conduct periodic access reviews</li>
                      <li>Implement automated access certification</li>
                      <li>Remove access when no longer needed</li>
                      <li>Audit privileged access regularly</li>
                      <li>Document access review processes</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>AWS IAM Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    AWS Identity and Access Management (IAM) provides fine-grained access control to AWS resources.
                    Properly configuring IAM is essential for AWS security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Key IAM Components</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Users:</strong> Individual identities for people or services
                      </li>
                      <li>
                        <strong>Groups:</strong> Collections of users with shared permissions
                      </li>
                      <li>
                        <strong>Roles:</strong> Identities that can be assumed by users or services
                      </li>
                      <li>
                        <strong>Policies:</strong> Documents defining permissions
                      </li>
                      <li>
                        <strong>Permission boundaries:</strong> Limits on maximum permissions
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">AWS IAM Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Lock down the root account with MFA</li>
                      <li>Use IAM roles for EC2 instances and services</li>
                      <li>Implement AWS Organizations for multi-account management</li>
                      <li>Use Service Control Policies (SCPs) to restrict permissions</li>
                      <li>Enable AWS CloudTrail for IAM activity logging</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example IAM Policy</h3>
                    <CodeBlock
                      language="json"
                      code={`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket",
        "arn:aws:s3:::example-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "192.0.2.0/24"
        }
      }
    }
  ]
}`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">AWS IAM Security Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>IAM Access Analyzer:</strong> Identifies resources shared with external entities
                      </li>
                      <li>
                        <strong>AWS Config:</strong> Monitors IAM policy compliance
                      </li>
                      <li>
                        <strong>AWS Security Hub:</strong> Aggregates security findings
                      </li>
                      <li>
                        <strong>Amazon Detective:</strong> Analyzes access patterns
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Azure Identity Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Microsoft Azure provides comprehensive identity management through Azure Active Directory (Azure AD)
                    and Role-Based Access Control (RBAC).
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Azure Identity Components</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Azure Active Directory:</strong> Cloud identity service
                      </li>
                      <li>
                        <strong>Azure RBAC:</strong> Role-based access control for Azure resources
                      </li>
                      <li>
                        <strong>Managed Identities:</strong> Automatically managed identities for Azure services
                      </li>
                      <li>
                        <strong>Conditional Access:</strong> Context-based access control
                      </li>
                      <li>
                        <strong>Privileged Identity Management (PIM):</strong> Just-in-time privileged access
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Azure Identity Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use Azure AD for centralized identity management</li>
                      <li>Implement Conditional Access policies</li>
                      <li>Enable MFA for all users, especially administrators</li>
                      <li>Use Privileged Identity Management for just-in-time access</li>
                      <li>Implement custom RBAC roles for least privilege</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Azure RBAC Assignment</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Assign a built-in role to a user
New-AzRoleAssignment -SignInName user@example.com `+
`-RoleDefinitionName "Reader" `+
`-ResourceGroupName "example-rg"

# Create a custom role
$role = Get-AzRoleDefinition "Virtual Machine Contributor"
$role.Id = $null
$role.Name = "Custom VM Operator"
$role.Description = "Can monitor and restart virtual machines."
$role.Actions.Clear()
$role.Actions.Add("Microsoft.Storage/*/read")
$role.Actions.Add("Microsoft.Network/*/read")
$role.Actions.Add("Microsoft.Compute/*/read")
$role.Actions.Add("Microsoft.Compute/virtualMachines/start/action")
$role.Actions.Add("Microsoft.Compute/virtualMachines/restart/action")
$role.AssignableScopes.Clear()
$role.AssignableScopes.Add("/subscriptions/00000000-0000-0000-0000-000000000000")
New-AzRoleDefinition -Role $role`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Azure Identity Security Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Azure AD Identity Protection:</strong> Risk-based identity protection
                      </li>
                      <li>
                        <strong>Azure AD Privileged Identity Management:</strong> Just-in-time privileged access
                      </li>
                      <li>
                        <strong>Azure AD Access Reviews:</strong> Regular access certification
                      </li>
                      <li>
                        <strong>Microsoft Defender for Identity:</strong> Advanced identity threat protection
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Google Cloud IAM</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Google Cloud Platform (GCP) provides Identity and Access Management (IAM) to control access to GCP
                    resources with fine-grained permissions.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">GCP IAM Components</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Members:</strong> Users, service accounts, groups, domains
                      </li>
                      <li>
                        <strong>Roles:</strong> Collections of permissions
                      </li>
                      <li>
                        <strong>Permissions:</strong> Determine allowed operations on resources
                      </li>
                      <li>
                        <strong>Bindings:</strong> Connect members to roles on resources
                      </li>
                      <li>
                        <strong>Policy:</strong> Collection of bindings
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">GCP IAM Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use predefined roles when possible</li>
                      <li>Create custom roles for specific needs</li>
                      <li>Use service accounts with minimal permissions</li>
                      <li>Implement resource hierarchy (organization, folders, projects)</li>
                      <li>Use Cloud Identity for centralized identity management</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example GCP IAM Commands</h3>
                    <CodeBlock
                      language="bash"
                      code={`# List IAM policies for a project
gcloud projects get-iam-policy PROJECT_ID

# Grant a role to a user
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:user@example.com" \
  --role="roles/compute.viewer"

# Create a custom role
gcloud iam roles create customRole \
  --project=PROJECT_ID \
  --title="Custom Role" \
  --description="Custom role for specific permissions" \
  --permissions="compute.instances.get,compute.instances.list"

# Create a service account
gcloud iam service-accounts create my-service-account \
  --display-name="My Service Account"`}
                    />
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">GCP Identity Security Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Cloud Identity:</strong> Identity management service
                      </li>
                      <li>
                        <strong>Security Command Center:</strong> Security and risk management
                      </li>
                      <li>
                        <strong>Policy Intelligence:</strong> Recommends IAM policy improvements
                      </li>
                      <li>
                        <strong>Access Transparency:</strong> Logs of provider access to your content
                      </li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle>Critical IAM Security Practices</AlertTitle>
              <AlertDescription>
                <ul className="list-disc pl-5">
                  <li>
                    <strong>Enforce MFA:</strong> Require multi-factor authentication for all users, especially those
                    with administrative privileges
                  </li>
                  <li>
                    <strong>Rotate credentials:</strong> Regularly rotate access keys, certificates, and other
                    credentials
                  </li>
                  <li>
                    <strong>Monitor privileged accounts:</strong> Implement enhanced monitoring for accounts with
                    elevated privileges
                  </li>
                  <li>
                    <strong>Implement break-glass procedures:</strong> Create emergency access protocols for critical
                    situations
                  </li>
                </ul>
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="infrastructure" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Cloud Infrastructure Security</h2>
            <p>
              Securing cloud infrastructure involves protecting compute resources, networks, and storage from threats
              while maintaining availability and performance.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Network Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Cloud network security involves protecting the virtual networks, subnets, and connections in your
                    cloud environment.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Network Segmentation</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Implement virtual private clouds (VPCs) or virtual networks</li>
                      <li>Use subnets to isolate workloads</li>
                      <li>Create network security groups or firewall rules</li>
                      <li>Implement transit gateways for controlled cross-VPC communication</li>
                      <li>Use private endpoints for service connections</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Traffic Filtering</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Implement security groups or network ACLs</li>
                      <li>Use web application firewalls (WAFs)</li>
                      <li>Deploy next-generation firewalls</li>
                      <li>Implement DDoS protection</li>
                      <li>Use traffic flow logs for monitoring</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Secure Connectivity</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use VPN or direct connect for hybrid connectivity</li>
                      <li>Implement private access for cloud services</li>
                      <li>Use service endpoints or private links</li>
                      <li>Encrypt data in transit</li>
                      <li>Implement bastion hosts for secure administrative access</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example AWS Network Security Configuration</h3>
                    <CodeBlock
                      language="bash"
                      code={`# Create a VPC with private and public subnets
aws ec2 create-vpc --cidr-block 10.0.0.0/16

# Create a security group
aws ec2 create-security-group \
  --group-name "web-sg" \
  --description "Web server security group" \
  --vpc-id vpc-12345678

# Add inbound rules to security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 443 \
  --cidr 0.0.0.0/0

# Create network ACL
aws ec2 create-network-acl \
  --vpc-id vpc-12345678

# Add network ACL entry
aws ec2 create-network-acl-entry \
  --network-acl-id acl-12345678 \
  --ingress \
  --rule-number 100 \
  --protocol 6 \
  --port-range From=443,To=443 \
  --cidr-block 0.0.0.0/0 \
  --rule-action allow`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Compute Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Securing cloud compute resources involves protecting virtual machines, containers, and serverless
                    functions from threats and vulnerabilities.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Virtual Machine Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use hardened base images or golden images</li>
                      <li>Implement regular patching and updates</li>
                      <li>Enable host-based firewalls</li>
                      <li>Use anti-malware solutions</li>
                      <li>Implement disk encryption</li>
                      <li>Use secure boot and measured boot where available</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Container Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Scan container images for vulnerabilities</li>
                      <li>Use minimal base images</li>
                      <li>Implement pod security policies or admission controllers</li>
                      <li>Run containers with least privilege</li>
                      <li>Implement network policies for pod-to-pod communication</li>
                      <li>Use secrets management for sensitive data</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Serverless Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Implement function-level IAM roles</li>
                      <li>Validate and sanitize all inputs</li>
                      <li>Minimize function permissions</li>
                      <li>Set appropriate function timeouts</li>
                      <li>Scan dependencies for vulnerabilities</li>
                      <li>Implement proper error handling</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Azure VM Security Configuration</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Create a VM with security extensions
New-AzVm `+
`-ResourceGroupName "secure-rg" `+
`-Name "secure-vm" `+
`-Location "eastus" `+
`-VirtualNetworkName "secure-vnet" `+
`-SubnetName "secure-subnet" `+
`-SecurityGroupName "secure-nsg" `+
`-PublicIpAddressName "secure-ip" `+
`-OpenPorts 22,443 `+
`-Image "UbuntuLTS"

# Enable disk encryption
$KeyVault = Get-AzKeyVault -VaultName "secure-kv" -ResourceGroupName "secure-rg"
Set-AzVMDiskEncryptionExtension `+
`-ResourceGroupName "secure-rg" `+
`-VMName "secure-vm" `+
`-DiskEncryptionKeyVaultUrl $KeyVault.VaultUri `+
`-DiskEncryptionKeyVaultId $KeyVault.ResourceId

# Install Microsoft Antimalware extension
Set-AzVMExtension `+
`-ResourceGroupName "secure-rg" `+
`-VMName "secure-vm" `+
`-Name "IaaSAntimalware" `+
`-Publisher "Microsoft.Azure.Security" `+
`-ExtensionType "IaaSAntimalware" `+
`-TypeHandlerVersion "1.3" `+
`-SettingString '{"AntimalwareEnabled": true}'`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Storage Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Cloud storage security involves protecting data at rest in various storage services, including
                    object storage, block storage, and file storage.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Data Encryption</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enable encryption at rest for all storage services</li>
                      <li>Use customer-managed keys where possible</li>
                      <li>Implement envelope encryption for sensitive data</li>
                      <li>Rotate encryption keys regularly</li>
                      <li>Use secure key management services</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Access Controls</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Implement least privilege access to storage resources</li>
                      <li>Use resource-based policies (bucket policies, ACLs)</li>
                      <li>Implement private access for storage services</li>
                      <li>Use signed URLs for temporary access</li>
                      <li>Implement storage firewalls or network rules</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Data Protection</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enable versioning for object storage</li>
                      <li>Implement backup and recovery processes</li>
                      <li>Use object lock or immutability for compliance</li>
                      <li>Implement lifecycle policies for data retention</li>
                      <li>Enable access logging for storage services</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example GCP Storage Security Configuration</h3>
                    <CodeBlock
                      language="bash"
                      code={`# Create a bucket with default encryption
gsutil mb -l us-central1 -c standard gs://secure-bucket

# Enable default encryption with customer-managed key
gsutil kms encryption -k projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/my-key gs://secure-bucket

# Set bucket IAM policy
cat > bucket-policy.json << EOF
{
  "bindings": [
    {
      "members": ["serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"],
      "role": "roles/storage.objectViewer"
    }
  ]
}
EOF
gsutil iam set bucket-policy.json gs://secure-bucket

# Enable object versioning
gsutil versioning set on gs://secure-bucket

# Set object retention policy
gsutil retention set 2y gs://secure-bucket

# Enable access logging
gsutil logging set on -b gs://log-bucket gs://secure-bucket`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Infrastructure as Code Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Infrastructure as Code (IaC) allows you to define and deploy cloud infrastructure using code. Securing
                    IaC is essential for maintaining a secure cloud environment.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Secure IaC Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use version control for all IaC templates</li>
                      <li>Implement code review processes</li>
                      <li>Scan IaC templates for security issues</li>
                      <li>Use parameterized templates with secure defaults</li>
                      <li>Implement least privilege in deployed resources</li>
                      <li>Use modules or blueprints for consistent security</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">IaC Security Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Checkov:</strong> Static code analysis for IaC
                      </li>
                      <li>
                        <strong>tfsec:</strong> Terraform security scanner
                      </li>
                      <li>
                        <strong>cfn-nag:</strong> CloudFormation security analyzer
                      </li>
                      <li>
                        <strong>Terrascan:</strong> Detect compliance and security violations
                      </li>
                      <li>
                        <strong>Snyk IaC:</strong> Find and fix vulnerabilities in IaC
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Terraform Security Configuration</h3>
                    <CodeBlock
                      language="hcl"
                      code={`# Secure S3 bucket configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-bucket"
  acl    = "private"

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

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }

  lifecycle_rule {
    enabled = true
    expiration {
      days = 90
    }
  }
}

# Bucket policy to enforce HTTPS
resource "aws_s3_bucket_policy" "secure_bucket_policy" {
  bucket = aws_s3_bucket.secure_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "$aws_s3_bucket.secure_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}
`}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Cloud Security Posture Management (CSPM)</AlertTitle>
              <AlertDescription>
                <p>
                  CSPM tools help identify and remediate cloud infrastructure misconfigurations and compliance issues.
                  These tools continuously monitor your cloud environment for security risks and provide remediation
                  guidance.
                </p>
                <p className="mt-2">Popular CSPM solutions include:</p>
                <ul className="list-disc pl-5 mt-1">
                  <li>AWS Security Hub</li>
                  <li>Microsoft Defender for Cloud</li>
                  <li>Google Security Command Center</li>
                  <li>Wiz</li>
                  <li>Prisma Cloud</li>
                  <li>Lacework</li>
                </ul>
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="data" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">Cloud Data Protection</h2>
            <p>
              Protecting data in the cloud requires a comprehensive approach to encryption, classification, access
              controls, and data lifecycle management.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Data Classification and Discovery</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Understanding what data you have and its sensitivity level is the foundation of effective data
                    protection in the cloud.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Data Classification Framework</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Public:</strong> Data that can be freely shared
                      </li>
                      <li>
                        <strong>Internal:</strong> Data for internal use only
                      </li>
                      <li>
                        <strong>Confidential:</strong> Sensitive data with restricted access
                      </li>
                      <li>
                        <strong>Restricted:</strong> Highly sensitive data with strict controls
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Data Discovery Approaches</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Automated data discovery and classification tools</li>
                      <li>Regular data inventory processes</li>
                      <li>Data flow mapping</li>
                      <li>Sensitive data scanning</li>
                      <li>Metadata tagging and labeling</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Data Discovery Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>AWS Macie:</strong> Discovers and protects sensitive data
                      </li>
                      <li>
                        <strong>Azure Purview:</strong> Data governance and discovery
                      </li>
                      <li>
                        <strong>Google Cloud Data Catalog:</strong> Metadata management
                      </li>
                      <li>
                        <strong>Cloud DLP services:</strong> Identify and protect sensitive data
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example AWS Macie Configuration</h3>
                    <CodeBlock
                      language="bash"
                      code={`# Enable Macie for your account
aws macie2 enable-macie

# Create a custom data identifier
aws macie2 create-custom-data-identifier \
  --name "Employee ID" \
  --regex "EMP-[0-9]{6}" \
  --description "Identifies employee ID numbers"

# Create a classification job
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"123456789012","buckets":["sensitive-data-bucket"]}]}' \
  --name "Sensitive Data Scan" \
  --description "Scan for sensitive data in S3 bucket"`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Encryption and Key Management</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Encryption is a critical control for protecting data in the cloud. Proper key management is
                    essential for effective encryption.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Encryption Types</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Encryption at rest:</strong> Data stored in databases, file systems, or storage services
                      </li>
                      <li>
                        <strong>Encryption in transit:</strong> Data moving across networks
                      </li>
                      <li>
                        <strong>Client-side encryption:</strong> Data encrypted before sending to the cloud
                      </li>
                      <li>
                        <strong>Field-level encryption:</strong> Specific data fields encrypted within applications
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Key Management Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use cloud key management services</li>
                      <li>Implement key rotation policies</li>
                      <li>Separate key management duties</li>
                      <li>Backup encryption keys securely</li>
                      <li>Use hardware security modules (HSMs) for critical keys</li>
                      <li>Implement envelope encryption for sensitive data</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Key Management Services</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>AWS Key Management Service (KMS):</strong> Managed encryption key service
                      </li>
                      <li>
                        <strong>Azure Key Vault:</strong> Secrets and key management
                      </li>
                      <li>
                        <strong>Google Cloud KMS:</strong> Cryptographic key management
                      </li>
                      <li>
                        <strong>HashiCorp Vault:</strong> Secrets management and encryption
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Azure Key Vault Configuration</h3>
                    <CodeBlock
                      language="powershell"
                      code={`# Create a Key Vault
New-AzKeyVault `+
`-Name "secure-keyvault" `+
`-ResourceGroupName "secure-rg" `+
`-Location "eastus" `+
`-EnabledForDiskEncryption `+
`-EnabledForDeployment `+
`-EnabledForTemplateDeployment `+
`-EnablePurgeProtection `+
`-EnableSoftDelete

# Create a key
$key = Add-AzKeyVaultKey `+
`-VaultName "secure-keyvault" `+
`-Name "data-encryption-key" `+
`-Destination "HSM" `+
`-KeyOps @("encrypt", "decrypt", "wrapKey", "unwrapKey")

# Set key rotation policy
Set-AzKeyVaultKeyRotationPolicy `+
`-VaultName "secure-keyvault" `+
`-KeyName "data-encryption-key" `+
`-ExpiresIn P1Y `+
`-RotationPolicy @{
  "lifetimeActions" = @(
    @{
      "trigger" = @{ "timeBeforeExpiry" = "P30D" };
      "action" = @{ "type" = "Rotate" }
    }
  )
}`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Data Loss Prevention</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Data Loss Prevention (DLP) helps identify, monitor, and protect sensitive data in the cloud to
                    prevent unauthorized access or exfiltration.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">DLP Capabilities</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Content inspection and classification</li>
                      <li>Policy-based protection actions</li>
                      <li>Data monitoring and alerting</li>
                      <li>Incident management and reporting</li>
                      <li>Integration with cloud services</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">DLP Implementation Approaches</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>API-based DLP:</strong> Monitors data via cloud service APIs
                      </li>
                      <li>
                        <strong>Proxy-based DLP:</strong> Inspects data in transit
                      </li>
                      <li>
                        <strong>Agent-based DLP:</strong> Monitors data on endpoints
                      </li>
                      <li>
                        <strong>Native cloud DLP:</strong> Uses cloud provider&apos;s DLP services
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud DLP Services</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>AWS Macie:</strong> Discovers and protects sensitive data in S3
                      </li>
                      <li>
                        <strong>Microsoft Purview DLP:</strong> Protects sensitive data across Microsoft cloud services
                      </li>
                      <li>
                        <strong>Google Cloud DLP:</strong> Discovers, classifies, and protects sensitive data
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Google Cloud DLP Configuration</h3>
                    <CodeBlock
                      language="bash"
                      code={`# Create a DLP inspection template
cat > dlp-template.json << EOF
{
  "inspectConfig": {
    "infoTypes": [
      {"name": "CREDIT_CARD_NUMBER"},
      {"name": "US_SOCIAL_SECURITY_NUMBER"},
      {"name": "EMAIL_ADDRESS"}
    ],
    "minLikelihood": "POSSIBLE",
    "limits": {
      "maxFindingsPerRequest": 100
    }
  }
}
EOF

gcloud dlp templates create \
  --organization=123456789012 \
  --template-id=sensitive-data-template \
  --description="Template for scanning sensitive data" \
  --file=dlp-template.json

# Create a DLP job to scan a Cloud Storage bucket
gcloud dlp jobs create \
  --project=my-project \
  --type=inspect \
  --storage-config=cloudstorage_bucket=gs://my-bucket \
  --inspect-template=organizations/123456789012/inspectTemplates/sensitive-data-template \
  --actions=de-identify=true,save_findings=true`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Database Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Cloud databases store critical data and require specific security controls to protect against
                    unauthorized access and data breaches.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Database Security Controls</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Authentication and access controls</li>
                      <li>Network security and isolation</li>
                      <li>Encryption at rest and in transit</li>
                      <li>Auditing and monitoring</li>
                      <li>Vulnerability management</li>
                      <li>Backup and recovery</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Database Security Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use private connectivity for database access</li>
                      <li>Implement strong authentication mechanisms</li>
                      <li>Apply the principle of least privilege</li>
                      <li>Enable encryption for sensitive data</li>
                      <li>Regularly patch and update database software</li>
                      <li>Implement database activity monitoring</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Database Security Features</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>AWS RDS:</strong> Encryption, IAM authentication, network isolation
                      </li>
                      <li>
                        <strong>Azure SQL:</strong> Advanced Threat Protection, Dynamic Data Masking
                      </li>
                      <li>
                        <strong>Google Cloud SQL:</strong> Private IP, IAM integration, data encryption
                      </li>
                      <li>
                        <strong>Managed NoSQL services:</strong> VPC endpoints, encryption, access controls
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example AWS RDS Security Configuration</h3>
                    <CodeBlock
                      language="bash"
                      code={`# Create a secure RDS instance
aws rds create-db-instance \
  --db-instance-identifier secure-db \
  --db-instance-class db.t3.small \
  --engine mysql \
  --master-username admin \
  --master-user-password "SecurePassword123!" \
  --allocated-storage 20 \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456 \
  --vpc-security-group-ids sg-12345678 \
  --db-subnet-group-name private-subnet-group \
  --backup-retention-period 7 \
  --enable-iam-database-authentication \
  --no-publicly-accessible

# Enable enhanced monitoring
aws rds modify-db-instance \
  --db-instance-identifier secure-db \
  --monitoring-interval 30 \
  --monitoring-role-arn arn:aws:iam::123456789012:role/rds-monitoring-role

# Enable performance insights
aws rds modify-db-instance \
  --db-instance-identifier secure-db \
  --enable-performance-insights \
  --performance-insights-kms-key-id arn:aws:kms:us-east-1:123456789012:key/abcd1234-ab12-cd34-ef56-abcdef123456 \
  --performance-insights-retention-period 7`}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle>Data Residency and Sovereignty</AlertTitle>
              <AlertDescription>
                <p>
                  Data residency and sovereignty requirements are increasingly important considerations for cloud data
                  protection. Many countries have regulations that require certain types of data to be stored within
                  their borders.
                </p>
                <ul className="list-disc pl-5 mt-2">
                  <li>Use region-specific cloud deployments to control data location</li>
                  <li>Implement data classification to identify regulated data</li>
                  <li>Understand the regulatory requirements for each jurisdiction</li>
                  <li>Consider using sovereign cloud offerings for highly regulated data</li>
                  <li>Implement technical controls to enforce data residency requirements</li>
                </ul>
              </AlertDescription>
            </Alert>
          </section>
        </TabsContent>

        <TabsContent value="devsecops" className="space-y-6">
          <section className="space-y-4">
            <h2 className="text-2xl font-bold mt-6">DevSecOps in the Cloud</h2>
            <p>
              DevSecOps integrates security into the DevOps process, ensuring that security is built into cloud
              applications and infrastructure from the beginning rather than added as an afterthought.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Secure CI/CD Pipelines</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Continuous Integration and Continuous Deployment (CI/CD) pipelines are central to modern cloud
                    development. Securing these pipelines is essential for cloud security.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Pipeline Security Controls</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Secure access to CI/CD systems</li>
                      <li>Code repository security</li>
                      <li>Secret management in pipelines</li>
                      <li>Artifact integrity verification</li>
                      <li>Infrastructure as Code (IaC) security scanning</li>
                      <li>Container image scanning</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Security Gates in CI/CD</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>Pre-commit hooks:</strong> Run security checks before code is committed
                      </li>
                      <li>
                        <strong>Static Application Security Testing (SAST):</strong> Analyze source code for
                        vulnerabilities
                      </li>
                      <li>
                        <strong>Software Composition Analysis (SCA):</strong> Check dependencies for vulnerabilities
                      </li>
                      <li>
                        <strong>Dynamic Application Security Testing (DAST):</strong> Test running applications
                      </li>
                      <li>
                        <strong>Infrastructure as Code scanning:</strong> Check for misconfigurations
                      </li>
                      <li>
                        <strong>Container security scanning:</strong> Check container images for vulnerabilities
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example GitHub Actions Security Workflow</h3>
                    <CodeBlock
                      language="yaml"
                      code={`name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'

      - name: Install dependencies
        run: npm ci

      - name: Run SAST scan
        uses: github/codeql-action/analyze@v1
        with:
          languages: javascript

      - name: Run dependency scan
        uses: snyk/actions/node@master
        env:\
          SNYK_TOKEN: $secrets.SNYK_TOKEN }}

      - name: Scan IaC files
        uses: bridgecrewio/checkov-action@master
        with:h:
          directory: infrastructure/
          framework: terraform

      - name: Build and scan container image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-app:$ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload scan results
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: trivy-results.sarif`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Container and Kubernetes Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Containers and Kubernetes are widely used in cloud environments. Securing these technologies
                    requires specific approaches and tools.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Container Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Use minimal base images</li>
                      <li>Scan images for vulnerabilities</li>
                      <li>Implement image signing and verification</li>
                      <li>Use non-root users in containers</li>
                      <li>Implement read-only file systems where possible</li>
                      <li>Apply resource limits</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Kubernetes Security</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Secure the Kubernetes API server</li>
                      <li>Implement RBAC for access control</li>
                      <li>Use network policies for pod-to-pod communication</li>
                      <li>Implement pod security policies or admission controllers</li>
                      <li>Secure etcd with encryption</li>
                      <li>Use namespaces for isolation</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example Kubernetes Security Configuration</h3>
                    <CodeBlock
                      language="yaml"
                      code={`# Network Policy to restrict pod communication
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Pod Security Context
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: my-app:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      limits:
        cpu: "1"
        memory: "512Mi"
      requests:
        cpu: "0.5"
        memory: "256Mi"

---
# RBAC Configuration
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: production
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Serverless Security</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Serverless computing shifts many security responsibilities to the cloud provider but introduces new
                    security considerations for developers.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Serverless Security Challenges</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Function permission management</li>
                      <li>Dependency vulnerabilities</li>
                      <li>Event-data validation</li>
                      <li>Secrets management</li>
                      <li>Function timeout and resource limits</li>
                      <li>Cold start security implications</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Serverless Security Best Practices</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Apply the principle of least privilege to function roles</li>
                      <li>Validate and sanitize all input data</li>
                      <li>Scan dependencies for vulnerabilities</li>
                      <li>Use secure coding practices</li>
                      <li>Implement proper error handling</li>
                      <li>Monitor function behavior and performance</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example AWS Lambda Security Configuration</h3>
                    <CodeBlock
                      language="yaml"
                      code={`# Serverless Framework configuration with security best practices
service: secure-serverless-app

provider:
  name: aws
  runtime: nodejs14.x
  stage: \${opt:stage, 'dev'}
  region: us-east-1
  tracing:
    lambda: true  # Enable X-Ray tracing
  logs:
    restApi: true  # Enable API Gateway logs
  environment:
    NODE_ENV: \${self:provider.stage}
  iamRoleStatements:
    - Effect: Allow
      Action:
        - dynamodb:GetItem
        - dynamodb:PutItem
      Resource: !GetAtt UsersTable.Arn

functions:
  getUser:
    handler: src/handlers/getUser.handler
    events:
      - http:
          path: users/{id}
          method: get
          cors: true
          authorizer:
            type: COGNITO_USER_POOLS
            authorizerId: !Ref ApiGatewayAuthorizer
    environment:
      TABLE_NAME: !Ref UsersTable
    timeout: 10  # Seconds
    memorySize: 256  # MB
    reservedConcurrency: 10  # Limit concurrent executions

resources:
  Resources:
    UsersTable:
      Type: AWS::DynamoDB::Table
      Properties:
        BillingMode: PAY_PER_REQUEST
        AttributeDefinitions:
          - AttributeName: id
            AttributeType: S
        KeySchema:
          - AttributeName: id
            KeyType: HASH
        SSESpecification:
          SSEEnabled: true  # Enable server-side encryption

    ApiGatewayAuthorizer:
      Type: AWS::ApiGateway::Authorizer
      Properties:
        Name: cognito-authorizer
        Type: COGNITO_USER_POOLS
        IdentitySource: method.request.header.Authorization
        RestApiId: !Ref ApiGatewayRestApi
        ProviderARNs:
          - !GetAtt UserPool.Arn

    UserPool:
      Type: AWS::Cognito::UserPool
      Properties:
        UserPoolName: \${self:service}-\${self:provider.stage}-user-pool
        AutoVerifiedAttributes:
          - email
        MfaConfiguration: 'ON'
        AccountRecoverySetting:
          RecoveryMechanisms:
            - Name: verified_email
              Priority: 1`}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Security Monitoring and Incident Response</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p>
                    Effective security monitoring and incident response are essential for detecting and responding to
                    security incidents in cloud environments.
                  </p>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Security Monitoring</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Enable cloud provider logging services</li>
                      <li>Implement centralized log management</li>
                      <li>Set up alerts for suspicious activities</li>
                      <li>Monitor for configuration changes</li>
                      <li>Implement continuous compliance monitoring</li>
                      <li>Use cloud-native security monitoring tools</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Incident Response</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>Develop cloud-specific incident response plans</li>
                      <li>Implement automated response capabilities</li>
                      <li>Use cloud-native forensics tools</li>
                      <li>Practice incident response scenarios</li>
                      <li>Establish communication channels</li>
                      <li>Document lessons learned from incidents</li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Cloud Security Monitoring Tools</h3>
                    <ul className="space-y-1 list-disc pl-5">
                      <li>
                        <strong>AWS CloudTrail:</strong> API activity logging
                      </li>
                      <li>
                        <strong>AWS GuardDuty:</strong> Threat detection service
                      </li>
                      <li>
                        <strong>Azure Security Center:</strong> Unified security management
                      </li>
                      <li>
                        <strong>Azure Sentinel:</strong> Cloud-native SIEM
                      </li>
                      <li>
                        <strong>Google Security Command Center:</strong> Security and risk management
                      </li>
                      <li>
                        <strong>Cloud-native SIEMs:</strong> Specialized for cloud environments
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h3 className="font-semibold mb-2">Example AWS CloudWatch Alarm</h3>
                    <CodeBlock
                      language="yaml"
                      code={`# CloudFormation template for security monitoring
Resources:
  RootUserLoginAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: RootUserLoginAlarm
      AlarmDescription: Alarm if root user logs in
      MetricName: RootUserLoginCount
      Namespace: CloudTrailMetrics
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref SecurityNotificationTopic

  SecurityNotificationTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Security Notifications
      TopicName: security-notifications

  SecurityMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
      MetricTransformations:
        - MetricNamespace: CloudTrailMetrics
          MetricName: RootUserLoginCount
          MetricValue: '1'

  CloudTrailLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: CloudTrail/DefaultLogGroup
      RetentionInDays: 90`}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Alert>
              <InfoIcon className="h-4 w-4" />
              <AlertTitle>Shift Left Security</AlertTitle>
              <AlertDescription>
                <p>
                  &quot;Shifting left&quot; means moving security earlier in the development lifecycle. This approach helps
                  identify and fix security issues before they reach production, reducing cost and risk.
                </p>
                <ul className="list-disc pl-5 mt-2">
                  <li>Integrate security tools into developer workflows</li>
                  <li>Provide security training for developers</li>
                  <li>Implement pre-commit hooks for security checks</li>
                  <li>Use infrastructure as code security scanning</li>
                  <li>Automate security testing in CI/CD pipelines</li>
                  <li>Create security champions within development teams</li>
                </ul>
              </AlertDescription>
            </Alert>
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
                    href="https://www.oreilly.com/library/view/cloud-security/9781492087489/"
                    className="text-primary hover:underline flex items-center"
                  >
                    Cloud Security: A Comprehensive Guide
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.packtpub.com/product/hands-on-security-in-devops/9781788995504"
                    className="text-primary hover:underline flex items-center"
                  >
                    Hands-On Security in DevOps
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.wiley.com/en-us/AWS+Certified+Security+Study+Guide%3A+Specialty+%28SCS+C01%29+Exam-p-9781119658825"
                    className="text-primary hover:underline flex items-center"
                  >
                    AWS Certified Security Study Guide
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
                    href="https://www.coursera.org/learn/cloud-security-basics"
                    className="text-primary hover:underline flex items-center"
                  >
                    Cloud Security Basics (Coursera)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.pluralsight.com/paths/aws-security"
                    className="text-primary hover:underline flex items-center"
                  >
                    AWS Security (Pluralsight)
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.sans.org/cyber-security-courses/securing-cloud-a-comprehensive-approach/"
                    className="text-primary hover:underline flex items-center"
                  >
                    SANS SEC488: Cloud Security Essentials
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
              </ul>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security Frameworks</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <Link
                    href="https://cloudsecurityalliance.org/research/cloud-controls-matrix/"
                    className="text-primary hover:underline flex items-center"
                  >
                    CSA Cloud Controls Matrix
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.cisecurity.org/benchmark/amazon_web_services/"
                    className="text-primary hover:underline flex items-center"
                  >
                    CIS Benchmarks for Cloud Providers
                    <ExternalLink className="h-3 w-3 ml-1" />
                  </Link>
                </li>
                <li>
                  <Link
                    href="https://www.nist.gov/publications/security-reference-architecture-cloud-computing"
                    className="text-primary hover:underline flex items-center"
                  >
                    NIST Cloud Computing Security
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
