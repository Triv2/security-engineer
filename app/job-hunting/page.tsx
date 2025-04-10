import { Briefcase } from "lucide-react"
import { ReferenceGuide } from "@/components/reference-guide"

export default function JobHuntingPage() {
  return (
    <ReferenceGuide
      title="💼 Security Job Hunting"
      icon={<Briefcase className="h-8 w-8 text-primary" />}
      concepts={[
        "Security job roles and responsibilities",
        "Entry-level security positions",
        "Resume and cover letter best practices",
        "Technical interview preparation",
        "Security portfolios and GitHub profiles",
        "Networking in the security community",
        "Salary expectations and negotiation",
        "Career progression in security",
      ]}
      tools={[
        "LinkedIn - Professional networking",
        "GitHub - Project portfolio",
        "Security BSides/conferences - Networking events",
        "InfoSec job boards (e.g., CyberSecJobs)",
        "Resume templates and ATS optimization tools",
        "Mock interview platforms",
        "Technical challenge preparation resources",
        "Salary comparison tools (Glassdoor, PayScale)",
      ]}
      practiceTips={[
        "Create a security-focused resume highlighting relevant skills",
        "Build a GitHub portfolio with security projects and tools",
        "Write blog posts or create videos about security topics",
        "Prepare answers for common security interview questions",
        "Practice explaining complex security concepts simply",
        "Attend local security meetups and conferences",
        "Contribute to open-source security projects",
        "Prepare a 30-second elevator pitch about yourself",
      ]}
    />
  )
}
