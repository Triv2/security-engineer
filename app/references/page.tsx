import Link from "next/link"
import { Card, CardContent } from "@/components/ui/card"
import { Server, Terminal, Cloud, PenToolIcon as Tool, Award, FlaskRoundIcon as Flask, Briefcase } from "lucide-react"
import { WindowsIcon } from "@/components/windows-icon"

export default function ReferencesPage() {
  const references = [
    {
      title: "Networking Basics",
      path: "/networking",
      icon: Server,
      description: "Learn about OSI model, TCP/IP, common ports, and network security fundamentals.",
    },
    {
      title: "Linux Security",
      path: "/linux",
      icon: Terminal,
      description: "Explore Linux security concepts, permissions, hardening, and security tools.",
    },
    {
      title: "Windows Security",
      path: "/windows",
      icon: WindowsIcon,
      description: "Understand Windows security mechanisms, Active Directory, and Windows-specific security tools.",
    },
    {
      title: "Cloud Security",
      path: "/cloud",
      icon: Cloud,
      description: "Learn about securing cloud environments, shared responsibility models, and cloud security tools.",
    },
    {
      title: "Security Tools",
      path: "/tools",
      icon: Tool,
      description: "Discover essential security tools for vulnerability scanning, network analysis, and more.",
    },
    {
      title: "Certifications",
      path: "/certifications",
      icon: Award,
      description: "Find the right security certifications for your career path and how to prepare for them.",
    },
    {
      title: "Labs & Projects",
      path: "/labs",
      icon: Flask,
      description: "Set up your own security lab environment and practice with hands-on projects.",
    },
    {
      title: "Job Hunting",
      path: "/job-hunting",
      icon: Briefcase,
      description: "Prepare for security job interviews, build your portfolio, and advance your career.",
    },
  ]

  return (
    <div className="max-w-5xl mx-auto">
      <h1 className="text-4xl font-bold mb-4">📚 Reference Guides</h1>
      <p className="text-xl text-muted-foreground mb-8">
        Comprehensive resources to help you master different aspects of security engineering.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {references.map((reference) => (
          <Link key={reference.path} href={reference.path} className="no-underline">
            <Card className="h-full hover:shadow-md transition-shadow">
              <CardContent className="p-6">
                <div className="flex items-start gap-4">
                  {typeof reference.icon === "function" ? (
                    <reference.icon className="h-8 w-8 text-primary mt-1" />
                  ) : (
                    <reference.icon className="h-8 w-8 text-primary mt-1" />
                  )}
                  <div>
                    <h2 className="text-xl font-semibold mb-2">{reference.title}</h2>
                    <p className="text-muted-foreground">{reference.description}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
