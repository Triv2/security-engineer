import { Award, BookOpen, Briefcase, GraduationCap, LineChart, Shield, Target, Users } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { CodeBlock } from "@/components/code-block"

export default function CertificationsPage() {
  return (
    <div className="container mx-auto py-8 px-4">
      <div className="mb-8 text-center">
        <h1 className="text-4xl font-bold mb-4">🏆 Security Certifications</h1>
        <p className="text-xl text-muted-foreground">
          A comprehensive guide to security certifications for different career paths and skill levels
        </p>
      </div>

      <Tabs defaultValue="foundational">
        <TabsList className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 mb-8">
          <TabsTrigger value="foundational">
            <BookOpen className="mr-2 h-4 w-4" />
            Foundational
          </TabsTrigger>
          <TabsTrigger value="advanced">
            <Shield className="mr-2 h-4 w-4" />
            Advanced
          </TabsTrigger>
          <TabsTrigger value="specialized">
            <Target className="mr-2 h-4 w-4" />
            Specialized
          </TabsTrigger>
          <TabsTrigger value="vendor">
            <Briefcase className="mr-2 h-4 w-4" />
            Vendor-Specific
          </TabsTrigger>
          <TabsTrigger value="preparation">
            <GraduationCap className="mr-2 h-4 w-4" />
            Preparation
          </TabsTrigger>
          <TabsTrigger value="career">
            <LineChart className="mr-2 h-4 w-4" />
            Career Paths
          </TabsTrigger>
        </TabsList>

        {/* Foundational Certifications */}
        <TabsContent value="foundational" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Foundational Security Certifications</h2>
          <p className="text-lg mb-6">
            These entry-level certifications establish a solid foundation in cybersecurity principles and are ideal
            starting points for those new to the field.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">CompTIA Security+</h3>
              </div>
              <p className="mb-4">
                The most popular entry-level security certification that validates the baseline skills necessary to
                perform core security functions.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Exam Code:</strong> SY0-601
                </li>
                <li>
                  <strong>Prerequisites:</strong> None, but Network+ and 2 years of experience recommended
                </li>
                <li>
                  <strong>Cost:</strong> $381 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 90 questions, 90 minutes, performance-based and multiple choice
                </li>
                <li>
                  <strong>Passing Score:</strong> 750 (on a scale of 100-900)
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Threats/vulnerabilities, technologies/tools, architecture/design,
                identity/access management, risk management, cryptography
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">GIAC Security Essentials (GSEC)</h3>
              </div>
              <p className="mb-4">
                Demonstrates understanding of information security beyond simple terminology and concepts.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Exam Code:</strong> GSEC
                </li>
                <li>
                  <strong>Prerequisites:</strong> None
                </li>
                <li>
                  <strong>Cost:</strong> $2,499 USD (with training) or $949 (exam only)
                </li>
                <li>
                  <strong>Validity:</strong> 4 years
                </li>
                <li>
                  <strong>Format:</strong> 106-125 questions, 3 hours, open book
                </li>
                <li>
                  <strong>Passing Score:</strong> 73%
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Active defense, network security, access controls, encryption, incident
                handling, Linux/Windows security
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">
                  Certified Information Systems Security Professional (CISSP) Associate
                </h3>
              </div>
              <p className="mb-4">
                For those who have passed the CISSP exam but don't yet have the required experience.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> Pass CISSP exam, less than 5 years experience
                </li>
                <li>
                  <strong>Cost:</strong> $749 USD
                </li>
                <li>
                  <strong>Validity:</strong> 6 years (to gain required experience)
                </li>
                <li>
                  <strong>Format:</strong> Same as CISSP exam
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Same as CISSP domains
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">eLearnSecurity Junior Penetration Tester (eJPT)</h3>
              </div>
              <p className="mb-4">Entry-level penetration testing certification with a practical approach.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> None
                </li>
                <li>
                  <strong>Cost:</strong> $200 USD
                </li>
                <li>
                  <strong>Validity:</strong> Lifetime
                </li>
                <li>
                  <strong>Format:</strong> 3-day practical exam, 20 multiple-choice questions
                </li>
                <li>
                  <strong>Passing Score:</strong> 75%
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Information gathering, web attacks, network attacks, basic exploitation,
                reporting
              </p>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              For those new to cybersecurity, start with CompTIA Security+ to build a solid foundation before pursuing
              more specialized certifications.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Foundational Certification Comparison</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">Certification</th>
                  <th className="border p-2 text-left">Focus Area</th>
                  <th className="border p-2 text-left">Difficulty</th>
                  <th className="border p-2 text-left">Hands-on Component</th>
                  <th className="border p-2 text-left">Best For</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="border p-2">CompTIA Security+</td>
                  <td className="border p-2">Broad security concepts</td>
                  <td className="border p-2">Moderate</td>
                  <td className="border p-2">Some performance-based questions</td>
                  <td className="border p-2">IT professionals transitioning to security</td>
                </tr>
                <tr>
                  <td className="border p-2">GIAC GSEC</td>
                  <td className="border p-2">Practical security skills</td>
                  <td className="border p-2">Moderate to High</td>
                  <td className="border p-2">No, but very practical knowledge</td>
                  <td className="border p-2">Security practitioners seeking depth</td>
                </tr>
                <tr>
                  <td className="border p-2">CISSP Associate</td>
                  <td className="border p-2">Security management</td>
                  <td className="border p-2">High</td>
                  <td className="border p-2">No</td>
                  <td className="border p-2">Early career professionals aiming for management</td>
                </tr>
                <tr>
                  <td className="border p-2">eJPT</td>
                  <td className="border p-2">Basic penetration testing</td>
                  <td className="border p-2">Moderate</td>
                  <td className="border p-2">Yes, fully practical exam</td>
                  <td className="border p-2">Aspiring penetration testers</td>
                </tr>
              </tbody>
            </table>
          </div>
        </TabsContent>

        {/* Advanced Certifications */}
        <TabsContent value="advanced" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Advanced Security Certifications</h2>
          <p className="text-lg mb-6">
            These certifications are designed for experienced security professionals and demonstrate advanced knowledge
            and skills in security management and operations.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Certified Information Systems Security Professional (CISSP)</h3>
              </div>
              <p className="mb-4">
                The gold standard for security professionals, focusing on security management and architecture.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 5 years of experience in 2+ domains (4 years with college degree)
                </li>
                <li>
                  <strong>Cost:</strong> $749 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 100-150 questions, 3 hours, adaptive testing
                </li>
                <li>
                  <strong>Passing Score:</strong> Scaled scoring (700 out of 1000)
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Security and risk management, asset security, security architecture,
                communication security, identity management, security assessment, security operations, software
                development security
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Offensive Security Certified Professional (OSCP)</h3>
              </div>
              <p className="mb-4">The industry-leading hands-on penetration testing certification.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> Solid understanding of networking, Linux, and basic scripting
                </li>
                <li>
                  <strong>Cost:</strong> $999-$1,499 USD (includes lab time)
                </li>
                <li>
                  <strong>Validity:</strong> Lifetime
                </li>
                <li>
                  <strong>Format:</strong> 24-hour practical exam + report
                </li>
                <li>
                  <strong>Passing Score:</strong> 70 points (out of 100)
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Information gathering, vulnerability scanning, exploitation, privilege
                escalation, post-exploitation, reporting
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">GIAC Certified Incident Handler (GCIH)</h3>
              </div>
              <p className="mb-4">Focuses on detecting, responding, and resolving computer security incidents.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> None, but experience recommended
                </li>
                <li>
                  <strong>Cost:</strong> $2,499 USD (with training) or $949 (exam only)
                </li>
                <li>
                  <strong>Validity:</strong> 4 years
                </li>
                <li>
                  <strong>Format:</strong> 106-125 questions, 3 hours, open book
                </li>
                <li>
                  <strong>Passing Score:</strong> 73%
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Incident handling process, network/system attacks, common attack
                techniques, containment, eradication, recovery
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Certified Ethical Hacker (CEH)</h3>
              </div>
              <p className="mb-4">Demonstrates knowledge of attack vectors, tools, and techniques used by hackers.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 2 years experience or official training
                </li>
                <li>
                  <strong>Cost:</strong> $950-$1,199 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 125 questions, 4 hours
                </li>
                <li>
                  <strong>Passing Score:</strong> 70%
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Ethical hacking methodology, scanning, enumeration, system hacking,
                malware, sniffing, social engineering, denial of service, session hijacking, web servers/applications,
                SQL injection, wireless networks, mobile platforms, IoT, cloud computing
              </p>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              Advanced certifications often require significant experience and study time. Plan for 3-6 months of
              preparation for certifications like CISSP, and even longer for hands-on certifications like OSCP.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Advanced Certification Comparison</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">Certification</th>
                  <th className="border p-2 text-left">Focus Area</th>
                  <th className="border p-2 text-left">Difficulty</th>
                  <th className="border p-2 text-left">Hands-on Component</th>
                  <th className="border p-2 text-left">Career Impact</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="border p-2">CISSP</td>
                  <td className="border p-2">Security management</td>
                  <td className="border p-2">Very High</td>
                  <td className="border p-2">No</td>
                  <td className="border p-2">Often required for senior positions and management roles</td>
                </tr>
                <tr>
                  <td className="border p-2">OSCP</td>
                  <td className="border p-2">Penetration testing</td>
                  <td className="border p-2">Extremely High</td>
                  <td className="border p-2">Yes, fully practical</td>
                  <td className="border p-2">Highly respected for offensive security roles</td>
                </tr>
                <tr>
                  <td className="border p-2">GCIH</td>
                  <td className="border p-2">Incident handling</td>
                  <td className="border p-2">High</td>
                  <td className="border p-2">No, but practical knowledge</td>
                  <td className="border p-2">Valuable for SOC analysts and incident responders</td>
                </tr>
                <tr>
                  <td className="border p-2">CEH</td>
                  <td className="border p-2">Ethical hacking</td>
                  <td className="border p-2">Moderate to High</td>
                  <td className="border p-2">Optional practical (CEH Practical)</td>
                  <td className="border p-2">Widely recognized, good for government positions</td>
                </tr>
              </tbody>
            </table>
          </div>
        </TabsContent>

        {/* Specialized Certifications */}
        <TabsContent value="specialized" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Specialized Security Certifications</h2>
          <p className="text-lg mb-6">
            These certifications focus on specific security domains and demonstrate expertise in specialized areas of
            cybersecurity.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Certified Cloud Security Professional (CCSP)</h3>
              </div>
              <p className="mb-4">
                Demonstrates expertise in cloud security architecture, design, operations, and service orchestration.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 5 years of IT experience, 3 years in security, 1 year in cloud
                  security
                </li>
                <li>
                  <strong>Cost:</strong> $599 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 125 questions, 3 hours
                </li>
                <li>
                  <strong>Passing Score:</strong> 700 out of 1000
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Cloud concepts, architecture, design, data security, platform &
                infrastructure security, application security, operations, legal & compliance
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">GIAC Certified Forensic Analyst (GCFA)</h3>
              </div>
              <p className="mb-4">
                Validates the ability to conduct formal incident investigations and handle advanced incident handling
                scenarios.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> None, but experience recommended
                </li>
                <li>
                  <strong>Cost:</strong> $2,499 USD (with training) or $949 (exam only)
                </li>
                <li>
                  <strong>Validity:</strong> 4 years
                </li>
                <li>
                  <strong>Format:</strong> 115 questions, 3 hours, open book
                </li>
                <li>
                  <strong>Passing Score:</strong> 73%
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Advanced incident response, timeline analysis, memory forensics, malware
                analysis, enterprise forensics
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Certified Information Security Manager (CISM)</h3>
              </div>
              <p className="mb-4">
                Focuses on information security governance and management from an enterprise perspective.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 5 years of experience in information security management
                </li>
                <li>
                  <strong>Cost:</strong> $575-$760 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 150 questions, 4 hours
                </li>
                <li>
                  <strong>Passing Score:</strong> 450 out of 800
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Information security governance, risk management, program
                development/management, incident management
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Certified Secure Software Lifecycle Professional (CSSLP)</h3>
              </div>
              <p className="mb-4">
                Validates secure software development practices and expertise in application security.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 4 years of experience in the SDLC
                </li>
                <li>
                  <strong>Cost:</strong> $599 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 125 questions, 3 hours
                </li>
                <li>
                  <strong>Passing Score:</strong> 700 out of 1000
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Secure software concepts, requirements, design, implementation, testing,
                deployment, operations, supply chain
              </p>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              Specialized certifications are most valuable when aligned with your career goals. Choose certifications
              that complement your current role or help you transition to your desired specialization.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Other Specialized Security Certifications</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Security Architecture</h4>
              <ul className="list-disc pl-5 space-y-1">
                <li>SABSA Chartered Security Architect</li>
                <li>Certified Security Architecture Professional (CSAP)</li>
                <li>TOGAF Certification with Security Focus</li>
              </ul>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Governance, Risk & Compliance</h4>
              <ul className="list-disc pl-5 space-y-1">
                <li>Certified in Risk and Information Systems Control (CRISC)</li>
                <li>Certified in the Governance of Enterprise IT (CGEIT)</li>
                <li>GIAC Critical Controls Certification (GCCC)</li>
              </ul>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Security Operations</h4>
              <ul className="list-disc pl-5 space-y-1">
                <li>CompTIA CySA+ (Cybersecurity Analyst)</li>
                <li>GIAC Continuous Monitoring Certification (GMON)</li>
                <li>Certified SOC Analyst (CSA)</li>
              </ul>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Offensive Security</h4>
              <ul className="list-disc pl-5 space-y-1">
                <li>Offensive Security Certified Expert (OSCE)</li>
                <li>GIAC Exploit Researcher and Advanced Penetration Tester (GXPN)</li>
                <li>eLearnSecurity Certified Professional Penetration Tester (eCPPT)</li>
              </ul>
            </div>
          </div>
        </TabsContent>

        {/* Vendor-Specific Certifications */}
        <TabsContent value="vendor" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Vendor-Specific Security Certifications</h2>
          <p className="text-lg mb-6">
            These certifications validate expertise with specific security products, platforms, and technologies from
            major vendors.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">AWS Certified Security - Specialty</h3>
              </div>
              <p className="mb-4">Validates expertise in AWS security services, tools, and best practices.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> AWS Certified Cloud Practitioner or Associate-level certification
                  recommended
                </li>
                <li>
                  <strong>Cost:</strong> $300 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 65 questions, 170 minutes
                </li>
                <li>
                  <strong>Passing Score:</strong> 750 out of 1000
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Data protection, infrastructure security, IAM, logging/monitoring, incident
                response, security automation
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">
                  Microsoft Certified: Security, Compliance, and Identity Fundamentals
                </h3>
              </div>
              <p className="mb-4">
                Entry-level certification for Microsoft security, compliance, and identity solutions.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> None
                </li>
                <li>
                  <strong>Cost:</strong> $99 USD
                </li>
                <li>
                  <strong>Validity:</strong> Does not expire
                </li>
                <li>
                  <strong>Format:</strong> 40-60 questions, 60 minutes
                </li>
                <li>
                  <strong>Passing Score:</strong> 700 out of 1000
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Microsoft security/compliance/identity concepts, Azure AD capabilities,
                Microsoft security solutions, Microsoft compliance solutions
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Cisco Certified CyberOps Associate</h3>
              </div>
              <p className="mb-4">
                Validates the skills required for associate-level security operations center (SOC) roles.
              </p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> None
                </li>
                <li>
                  <strong>Cost:</strong> $300 USD
                </li>
                <li>
                  <strong>Validity:</strong> 3 years
                </li>
                <li>
                  <strong>Format:</strong> 95-105 questions, 120 minutes
                </li>
                <li>
                  <strong>Passing Score:</strong> 825 out of 1000
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Security concepts, security monitoring, host-based analysis, network
                intrusion analysis, security policies and procedures
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Award className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Google Professional Cloud Security Engineer</h3>
              </div>
              <p className="mb-4">Validates the ability to design and implement secure Google Cloud infrastructure.</p>
              <ul className="space-y-2 mb-4">
                <li>
                  <strong>Prerequisites:</strong> 3+ years of industry experience including 1+ years on Google Cloud
                </li>
                <li>
                  <strong>Cost:</strong> $200 USD
                </li>
                <li>
                  <strong>Validity:</strong> 2 years
                </li>
                <li>
                  <strong>Format:</strong> Multiple choice and multiple select, 2 hours
                </li>
                <li>
                  <strong>Passing Score:</strong> Not disclosed
                </li>
              </ul>
              <p>
                <strong>Key Topics:</strong> Configuring access, network security, data protection, logging/monitoring,
                incident response, compliance
              </p>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              Vendor-specific certifications are most valuable when they align with the technologies your organization
              uses. They demonstrate practical expertise with specific platforms and can be particularly valuable when
              applying for roles that require experience with those technologies.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Major Vendor Security Certification Paths</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Microsoft Security Certification Path</h4>
              <ol className="list-decimal pl-5 space-y-1">
                <li>Security, Compliance, and Identity Fundamentals (SC-900)</li>
                <li>Microsoft Certified: Security Operations Analyst Associate (SC-200)</li>
                <li>Microsoft Certified: Identity and Access Administrator Associate (SC-300)</li>
                <li>Microsoft Certified: Information Protection Administrator Associate (SC-400)</li>
                <li>Microsoft Certified: Cybersecurity Architect Expert (SC-100)</li>
              </ol>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">AWS Security Certification Path</h4>
              <ol className="list-decimal pl-5 space-y-1">
                <li>AWS Certified Cloud Practitioner</li>
                <li>AWS Certified Solutions Architect - Associate</li>
                <li>AWS Certified Security - Specialty</li>
                <li>AWS Certified Advanced Networking - Specialty</li>
              </ol>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Cisco Security Certification Path</h4>
              <ol className="list-decimal pl-5 space-y-1">
                <li>Cisco Certified CyberOps Associate</li>
                <li>CCNP Security</li>
                <li>Cisco Certified CyberOps Professional</li>
                <li>CCIE Security</li>
              </ol>
            </div>
            <div className="border p-4 rounded-lg">
              <h4 className="font-bold">Google Cloud Security Certification Path</h4>
              <ol className="list-decimal pl-5 space-y-1">
                <li>Google Cloud Digital Leader</li>
                <li>Google Associate Cloud Engineer</li>
                <li>Google Professional Cloud Security Engineer</li>
                <li>Google Professional Cloud Architect</li>
              </ol>
            </div>
          </div>
        </TabsContent>

        {/* Certification Preparation */}
        <TabsContent value="preparation" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Certification Preparation Strategies</h2>
          <p className="text-lg mb-6">
            Effective preparation is key to certification success. These strategies will help you prepare efficiently
            and pass your exams.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <GraduationCap className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Study Resources</h3>
              </div>
              <ul className="space-y-2">
                <li>
                  <strong>Official Study Guides:</strong> Always start with the official materials from the
                  certification body
                </li>
                <li>
                  <strong>Video Courses:</strong> Platforms like Pluralsight, LinkedIn Learning, Udemy, and INE
                </li>
                <li>
                  <strong>Practice Labs:</strong> TryHackMe, HackTheBox, and vendor-specific labs
                </li>
                <li>
                  <strong>Study Groups:</strong> Reddit communities, Discord servers, local meetups
                </li>
                <li>
                  <strong>Practice Exams:</strong> Boson, Kaplan, official practice tests
                </li>
                <li>
                  <strong>Flashcards:</strong> Anki or physical flashcards for key concepts
                </li>
              </ul>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Target className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Study Planning</h3>
              </div>
              <ul className="space-y-2">
                <li>
                  <strong>Exam Blueprint:</strong> Review the exam objectives and create a study plan
                </li>
                <li>
                  <strong>Time Allocation:</strong> Dedicate more time to unfamiliar or challenging topics
                </li>
                <li>
                  <strong>Study Schedule:</strong> Create a realistic schedule with specific goals
                </li>
                <li>
                  <strong>Progress Tracking:</strong> Monitor your progress with practice tests
                </li>
                <li>
                  <strong>Spaced Repetition:</strong> Review material at increasing intervals
                </li>
                <li>
                  <strong>Accountability:</strong> Find a study partner or join a study group
                </li>
              </ul>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Users className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Practical Experience</h3>
              </div>
              <ul className="space-y-2">
                <li>
                  <strong>Home Labs:</strong> Set up virtual environments to practice concepts
                </li>
                <li>
                  <strong>CTF Competitions:</strong> Participate in Capture The Flag events
                </li>
                <li>
                  <strong>Open Source Projects:</strong> Contribute to security tools or projects
                </li>
                <li>
                  <strong>Bug Bounties:</strong> Practice on platforms like HackerOne or Bugcrowd
                </li>
                <li>
                  <strong>Volunteer Work:</strong> Offer security services to non-profits
                </li>
                <li>
                  <strong>Shadowing:</strong> Learn from experienced professionals
                </li>
              </ul>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <Shield className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Exam Day Strategies</h3>
              </div>
              <ul className="space-y-2">
                <li>
                  <strong>Pre-Exam Routine:</strong> Get good sleep, eat well, arrive early
                </li>
                <li>
                  <strong>Time Management:</strong> Allocate time per question based on exam length
                </li>
                <li>
                  <strong>Question Approach:</strong> Read carefully, eliminate wrong answers
                </li>
                <li>
                  <strong>Flagging System:</strong> Skip difficult questions and return later
                </li>
                <li>
                  <strong>Review Period:</strong> Save time to review flagged questions
                </li>
                <li>
                  <strong>Stress Management:</strong> Use breathing techniques to stay calm
                </li>
              </ul>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              For hands-on certifications like OSCP, practical experience is more important than memorization. Spend at
              least 70% of your preparation time on labs and practical exercises.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Sample Study Plan Template</h3>
          <CodeBlock
            language="markdown"
            code={`# 12-Week CISSP Study Plan

## Week 1-2: Domain 1 & 2
- Read official study guide chapters
- Watch video course sections
- Complete practice questions
- Create flashcards for key concepts

## Week 3-4: Domain 3 & 4
- Read official study guide chapters
- Watch video course sections
- Complete practice questions
- Review Week 1-2 material

## Week 5-6: Domain 5 & 6
- Read official study guide chapters
- Watch video course sections
- Complete practice questions
- Review Week 3-4 material

## Week 7-8: Domain 7 & 8
- Read official study guide chapters
- Watch video course sections
- Complete practice questions
- Review Week 5-6 material

## Week 9-10: Comprehensive Review
- Take full practice exam
- Focus on weak areas
- Review all flashcards
- Join study group discussions

## Week 11-12: Final Preparation
- Take multiple practice exams
- Final review of weak areas
- Rest and prepare mentally
- Schedule exam for end of Week 12`}
          />
        </TabsContent>

        {/* Career Paths */}
        <TabsContent value="career" className="space-y-6">
          <h2 className="text-3xl font-bold mb-4">Certification Career Paths</h2>
          <p className="text-lg mb-6">
            Strategic certification planning can accelerate your cybersecurity career. These roadmaps outline
            certification paths for different security career trajectories.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <LineChart className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Security Operations Path</h3>
              </div>
              <p className="mb-4">
                For those interested in monitoring, detecting, and responding to security incidents.
              </p>
              <ol className="space-y-2 list-decimal pl-5">
                <li>
                  <strong>Entry Level:</strong> CompTIA Security+, CySA+
                </li>
                <li>
                  <strong>Mid Level:</strong> GIAC GCIH, GCIA, Cisco CyberOps Associate
                </li>
                <li>
                  <strong>Advanced:</strong> GIAC GCED, SANS FOR508, CISSP
                </li>
                <li>
                  <strong>Specialization:</strong> GIAC GREM (Malware), GIAC GCFA (Forensics)
                </li>
              </ol>
              <p className="mt-4">
                <strong>Career Progression:</strong> SOC Analyst → Incident Responder → Threat Hunter → SOC Manager
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <LineChart className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Penetration Testing Path</h3>
              </div>
              <p className="mb-4">For those interested in offensive security and identifying vulnerabilities.</p>
              <ol className="space-y-2 list-decimal pl-5">
                <li>
                  <strong>Entry Level:</strong> CompTIA Security+, eJPT
                </li>
                <li>
                  <strong>Mid Level:</strong> CEH, eCPPT, PenTest+
                </li>
                <li>
                  <strong>Advanced:</strong> OSCP, GIAC GPEN
                </li>
                <li>
                  <strong>Specialization:</strong> OSWE (Web), OSCE (Exploit Dev), GXPN (Advanced Exploitation)
                </li>
              </ol>
              <p className="mt-4">
                <strong>Career Progression:</strong> Security Analyst → Penetration Tester → Red Team Operator → Red
                Team Lead
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <LineChart className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Security Architecture Path</h3>
              </div>
              <p className="mb-4">For those interested in designing secure systems and infrastructure.</p>
              <ol className="space-y-2 list-decimal pl-5">
                <li>
                  <strong>Entry Level:</strong> CompTIA Security+, Cloud certifications (AWS/Azure fundamentals)
                </li>
                <li>
                  <strong>Mid Level:</strong> CISSP Associate, AWS/Azure Security certifications
                </li>
                <li>
                  <strong>Advanced:</strong> CISSP, CCSP
                </li>
                <li>
                  <strong>Specialization:</strong> SABSA Chartered Security Architect, TOGAF with security focus
                </li>
              </ol>
              <p className="mt-4">
                <strong>Career Progression:</strong> Security Engineer → Security Architect → Enterprise Security
                Architect → CISO
              </p>
            </div>

            <div className="border rounded-lg p-6 shadow-sm">
              <div className="flex items-center mb-4">
                <LineChart className="h-6 w-6 mr-2 text-primary" />
                <h3 className="text-xl font-bold">Security Management Path</h3>
              </div>
              <p className="mb-4">For those interested in security governance, risk management, and compliance.</p>
              <ol className="space-y-2 list-decimal pl-5">
                <li>
                  <strong>Entry Level:</strong> CompTIA Security+, ITIL Foundation
                </li>
                <li>
                  <strong>Mid Level:</strong> CISM, CRISC
                </li>
                <li>
                  <strong>Advanced:</strong> CISSP, CGEIT
                </li>
                <li>
                  <strong>Specialization:</strong> CCISO, ISO 27001 Lead Implementer/Auditor
                </li>
              </ol>
              <p className="mt-4">
                <strong>Career Progression:</strong> Security Analyst → Security Manager → Director of Security → CISO
              </p>
            </div>
          </div>

          <Alert>
            <Shield className="h-4 w-4" />
            <AlertTitle>Certification Tip</AlertTitle>
            <AlertDescription>
              Don't chase certifications just for the sake of collecting them. Focus on certifications that align with
              your career goals and provide real value for your target roles.
            </AlertDescription>
          </Alert>

          <h3 className="text-2xl font-bold mt-8 mb-4">Certification ROI Considerations</h3>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse">
              <thead>
                <tr className="bg-muted">
                  <th className="border p-2 text-left">Consideration</th>
                  <th className="border p-2 text-left">Questions to Ask</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="border p-2">Time Investment</td>
                  <td className="border p-2">
                    <ul className="list-disc pl-5">
                      <li>How many hours of study are required?</li>
                      <li>Does the certification require ongoing CPEs?</li>
                      <li>What is the renewal period and requirements?</li>
                    </ul>
                  </td>
                </tr>
                <tr>
                  <td className="border p-2">Financial Cost</td>
                  <td className="border p-2">
                    <ul className="list-disc pl-5">
                      <li>What is the exam cost?</li>
                      <li>What are the study material costs?</li>
                      <li>Are there renewal fees?</li>
                      <li>Does your employer offer reimbursement?</li>
                    </ul>
                  </td>
                </tr>
                <tr>
                  <td className="border p-2">Career Impact</td>
                  <td className="border p-2">
                    <ul className="list-disc pl-5">
                      <li>Is this certification in demand in job postings?</li>
                      <li>Will it help you qualify for a promotion or raise?</li>
                      <li>Does it open doors to new career opportunities?</li>
                      <li>How does it compare to equivalent experience?</li>
                    </ul>
                  </td>
                </tr>
                <tr>
                  <td className="border p-2">Knowledge Value</td>
                  <td className="border p-2">
                    <ul className="list-disc pl-5">
                      <li>Will you learn practical skills you can apply immediately?</li>
                      <li>Does it fill gaps in your knowledge?</li>
                      <li>Is the knowledge likely to remain relevant long-term?</li>
                    </ul>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
