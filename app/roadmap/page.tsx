import { Milestone, type MilestoneProps } from "@/components/milestone"

export default function RoadmapPage() {
  const milestones: MilestoneProps[] = [
    {
      number: 1,
      title: "Introduction to Security Engineering",
      description: "Understand the fundamentals of security engineering, its importance, and various career paths.",
      timeframe: "2-4 weeks",
      skillLevel: "Beginner",
      keyTopics: [
        "Security engineering principles and goals",
        "CIA Triad (Confidentiality, Integrity, Availability)",
        "Defense in depth strategy",
        "Career paths: SOC Analyst, AppSec Engineer, Red/Blue Team",
        "Security mindset development",
        "Threat landscape overview",
        "Basic security terminology",
        "Security engineering vs. other security roles",
      ],
      resources: [
        {
          name: "OWASP Foundation",
          url: "https://owasp.org/",
          type: "Resource",
        },
        {
          name: "Cybrary - Introduction to IT & Cybersecurity",
          url: "https://www.cybrary.it/course/introduction-to-it-and-cybersecurity/",
          type: "Course",
        },
        {
          name: "Security Engineering by Ross Anderson (Free Online)",
          url: "https://www.cl.cam.ac.uk/~rja14/book.html",
          type: "Book",
        },
        {
          name: "Day in the Life of a Security Engineer",
          url: "https://www.youtube.com/watch?v=Wvj5YZLMRB0",
          type: "Video",
        },
      ],
      projects: [
        {
          title: "Security Mindmap Creation",
          description: "Create a mindmap of security domains, threats, and defenses to visualize the field.",
        },
        {
          title: "Security News Analysis",
          description:
            "Follow security news for two weeks and analyze three major incidents to understand real-world implications.",
        },
      ],
    },
    {
      number: 2,
      title: "Technical Foundations",
      description:
        "Build the core technical skills needed for security engineering across networking, operating systems, and programming.",
      timeframe: "4-8 weeks",
      skillLevel: "Beginner",
      keyTopics: [
        "Networking fundamentals (OSI model, TCP/IP)",
        "Common protocols (HTTP, DNS, DHCP, ARP)",
        "IP addressing, subnetting, and routing",
        "Linux command line essentials",
        "Windows command line and PowerShell",
        "Basic scripting with Python",
        "Bash scripting for automation",
        "Version control with Git",
      ],
      resources: [
        {
          name: "Practical Networking",
          url: "https://www.practicalnetworking.net/",
          type: "Article",
        },
        {
          name: "Linux Journey",
          url: "https://linuxjourney.com/",
          type: "Course",
        },
        {
          name: "Learn Python the Hard Way",
          url: "https://learnpythonthehardway.org/",
          type: "Book",
        },
        {
          name: "PowerShell in a Month of Lunches",
          url: "https://www.manning.com/books/learn-powershell-in-a-month-of-lunches",
          type: "Book",
        },
      ],
      projects: [
        {
          title: "Network Traffic Analysis",
          description:
            "Capture and analyze network traffic using Wireshark to identify protocols and understand network behavior.",
        },
        {
          title: "Automation Script Development",
          description:
            "Write Python or Bash scripts to automate security tasks like log parsing or system information gathering.",
        },
        {
          title: "Linux Server Setup",
          description: "Install and configure a Linux server with basic security controls and remote access.",
        },
      ],
    },
    {
      number: 3,
      title: "Security Concepts",
      description: "Develop a deeper understanding of core security concepts, threat modeling, and risk management.",
      timeframe: "3-6 weeks",
      skillLevel: "Beginner",
      keyTopics: [
        "Threat modeling methodologies (STRIDE, DREAD)",
        "Risk assessment frameworks",
        "Common vulnerabilities and exposures (CVE)",
        "OWASP Top 10 web vulnerabilities",
        "Authentication and authorization concepts",
        "Cryptography fundamentals",
        "Security policies and compliance",
        "Social engineering techniques",
      ],
      resources: [
        {
          name: "Threat Modeling: Designing for Security",
          url: "https://www.wiley.com/en-us/Threat+Modeling%3A+Designing+for+Security-p-9781118809990",
          type: "Book",
        },
        {
          name: "OWASP Top Ten",
          url: "https://owasp.org/www-project-top-ten/",
          type: "Article",
        },
        {
          name: "Cryptography I by Stanford University (Coursera)",
          url: "https://www.coursera.org/learn/crypto",
          type: "Course",
        },
        {
          name: "Social Engineering: The Science of Human Hacking",
          url: "https://www.wiley.com/en-us/Social+Engineering%3A+The+Science+of+Human+Hacking%2C+2nd+Edition-p-9781119433385",
          type: "Book",
        },
      ],
      projects: [
        {
          title: "Threat Model Creation",
          description: "Create a threat model for a simple web application using STRIDE methodology.",
        },
        {
          title: "Vulnerability Research",
          description:
            "Research and document a recent CVE, including its impact, exploitation methods, and mitigations.",
        },
        {
          title: "Security Policy Development",
          description:
            "Draft a basic security policy for a small organization covering password management, access control, and incident response.",
        },
      ],
    },
    {
      number: 4,
      title: "Tools of the Trade",
      description: "Master essential security tools used by professionals for scanning, monitoring, and analysis.",
      timeframe: "4-8 weeks",
      skillLevel: "Intermediate",
      keyTopics: [
        "Network scanning with Nmap",
        "Packet analysis with Wireshark",
        "Web application testing with Burp Suite",
        "Vulnerability scanning tools",
        "Password cracking tools (John the Ripper, Hashcat)",
        "SIEM concepts and tools",
        "Intrusion Detection/Prevention Systems",
        "Log analysis techniques",
      ],
      resources: [
        {
          name: "Nmap Network Scanning",
          url: "https://nmap.org/book/",
          type: "Book",
        },
        {
          name: "SANS SEC503: Intrusion Detection In-Depth",
          url: "https://www.sans.org/cyber-security-courses/intrusion-detection-in-depth/",
          type: "Course",
        },
        {
          name: "Burp Suite Academy",
          url: "https://portswigger.net/web-security",
          type: "Practice",
        },
        {
          name: "The Practice of Network Security Monitoring",
          url: "https://nostarch.com/nsm",
          type: "Book",
        },
      ],
      projects: [
        {
          title: "Network Reconnaissance Lab",
          description: "Set up a lab environment and practice network scanning and enumeration techniques with Nmap.",
        },
        {
          title: "Web Application Security Testing",
          description: "Use Burp Suite to identify and exploit common web vulnerabilities in a practice environment.",
        },
        {
          title: "SIEM Implementation",
          description:
            "Install and configure a basic SIEM solution (like Wazuh) to collect and analyze logs from multiple sources.",
        },
      ],
    },
    {
      number: 5,
      title: "Defensive Skills",
      description: "Learn to implement and manage security controls to protect systems and detect threats.",
      timeframe: "6-10 weeks",
      skillLevel: "Intermediate",
      keyTopics: [
        "System hardening techniques",
        "Network security architecture",
        "Firewall configuration and management",
        "Endpoint protection strategies",
        "Security monitoring and alerting",
        "Incident detection and triage",
        "Log analysis for threat hunting",
        "Security baseline development",
      ],
      resources: [
        {
          name: "CIS Benchmarks",
          url: "https://www.cisecurity.org/cis-benchmarks/",
          type: "Article",
        },
        {
          name: "Blue Team Field Manual",
          url: "https://www.amazon.com/Blue-Team-Field-Manual-BTFM/dp/1733338667",
          type: "Book",
        },
        {
          name: "Defensive Security Handbook",
          url: "https://www.oreilly.com/library/view/defensive-security-handbook/9781491960370/",
          type: "Book",
        },
        {
          name: "SANS SEC555: SIEM with Tactical Analytics",
          url: "https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/",
          type: "Course",
        },
      ],
      projects: [
        {
          title: "System Hardening Exercise",
          description: "Harden a Windows and Linux system according to CIS benchmarks and document the process.",
        },
        {
          title: "Network Defense Implementation",
          description:
            "Design and implement a defense-in-depth strategy for a small network, including firewalls, IDS/IPS, and segmentation.",
        },
        {
          title: "Threat Hunting Exercise",
          description: "Develop and execute a threat hunting plan using log analysis and security monitoring tools.",
        },
      ],
    },
    {
      number: 6,
      title: "Certifications & Paths",
      description: "Prepare for and obtain industry-recognized certifications to validate your skills and knowledge.",
      timeframe: "3-12 months",
      skillLevel: "Intermediate",
      keyTopics: [
        "CompTIA Security+ certification",
        "CompTIA CySA+ certification",
        "SANS GIAC certifications",
        "Certified Ethical Hacker (CEH)",
        "Offensive Security certifications (OSCP)",
        "Cloud security certifications",
        "Certification study strategies",
        "Hands-on learning platforms",
      ],
      resources: [
        {
          name: "CompTIA Security+ Certification Guide",
          url: "https://www.comptia.org/certifications/security",
          type: "Course",
        },
        {
          name: "TryHackMe",
          url: "https://tryhackme.com/",
          type: "Practice",
        },
        {
          name: "HackTheBox",
          url: "https://www.hackthebox.eu/",
          type: "Practice",
        },
        {
          name: "SANS Certification Roadmap",
          url: "https://www.sans.org/cyber-security-skills-roadmap/",
          type: "Article",
        },
      ],
      projects: [
        {
          title: "Certification Study Plan",
          description:
            "Create a detailed study plan for your chosen certification, including resources, practice tests, and a timeline.",
        },
        {
          title: "Hands-on Lab Challenges",
          description:
            "Complete a series of security challenges on platforms like TryHackMe or HackTheBox to prepare for practical exams.",
        },
        {
          title: "Mock Exam Preparation",
          description: "Take and review mock exams for your target certification to identify knowledge gaps.",
        },
      ],
    },
    {
      number: 7,
      title: "Home Lab Setup",
      description: "Build a comprehensive home lab environment to practice security techniques and scenarios.",
      timeframe: "4-8 weeks",
      skillLevel: "Intermediate",
      keyTopics: [
        "Virtualization platforms (VirtualBox, VMware)",
        "Containerization with Docker",
        "Network simulation and configuration",
        "Vulnerable machine deployment",
        "Security tool integration",
        "Monitoring and logging setup",
        "Attack and defense simulation",
        "Infrastructure as Code concepts",
      ],
      resources: [
        {
          name: "Building Virtual Machine Labs",
          url: "https://leanpub.com/avatar",
          type: "Book",
        },
        {
          name: "Practical Malware Analysis & Triage",
          url: "https://academy.tcm-sec.com/p/practical-malware-analysis-triage",
          type: "Course",
        },
        {
          name: "Vulnerable By Design ~ VulnHub",
          url: "https://www.vulnhub.com/",
          type: "Practice",
        },
        {
          name: "Docker for Pentesters",
          url: "https://blog.ropnop.com/docker-for-pentesters/",
          type: "Article",
        },
      ],
      projects: [
        {
          title: "Complete Home Lab Setup",
          description:
            "Build a comprehensive home lab with multiple VMs, network segments, and security monitoring tools.",
        },
        {
          title: "Automated Lab Deployment",
          description:
            "Create scripts or use Infrastructure as Code tools to automate the deployment of your lab environment.",
        },
        {
          title: "Attack Simulation Exercise",
          description:
            "Conduct a full attack and defense exercise in your lab, documenting the attack path and defensive measures.",
        },
      ],
    },
    {
      number: 8,
      title: "Breaking Into the Field",
      description:
        "Prepare for and launch your career in security engineering with job hunting strategies and portfolio development.",
      timeframe: "2-6 months",
      skillLevel: "Advanced",
      keyTopics: [
        "Resume and cover letter optimization",
        "LinkedIn profile development",
        "GitHub portfolio creation",
        "Technical interview preparation",
        "Security blog or content creation",
        "Networking strategies",
        "Job search techniques",
        "Continuous learning plan",
      ],
      resources: [
        {
          name: "The Complete Cyber Security Job Search Guide",
          url: "https://danielmiessler.com/blog/build-successful-infosec-career/",
          type: "Article",
        },
        {
          name: "Cracking the Coding Interview",
          url: "https://www.crackingthecodinginterview.com/",
          type: "Book",
        },
        {
          name: "Cybersecurity Career Guide",
          url: "https://www.springboard.com/blog/cybersecurity/cybersecurity-career-paths/",
          type: "Article",
        },
        {
          name: "Security Engineering Job Interviews",
          url: "https://www.youtube.com/watch?v=MY-2xKHHhxA",
          type: "Video",
        },
      ],
      projects: [
        {
          title: "Security Portfolio Development",
          description: "Create a GitHub portfolio showcasing your security projects, tools, and documentation.",
        },
        {
          title: "Technical Blog Creation",
          description:
            "Start a security blog or contribute to existing platforms with technical articles on security topics.",
        },
        {
          title: "Mock Interview Practice",
          description:
            "Prepare for and participate in mock interviews covering both technical and behavioral questions.",
        },
      ],
    },
  ]

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-4xl font-bold mb-4">🚀 Security Engineering Roadmap</h1>
      <p className="text-xl text-muted-foreground mb-12">
        A comprehensive step-by-step journey to build your foundation and launch your career in cybersecurity.
      </p>

      <div className="space-y-12">
        {milestones.map((milestone) => (
          <Milestone key={milestone.number} {...milestone} />
        ))}
      </div>
    </div>
  )
}
