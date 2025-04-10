import Link from "next/link"
import { Button } from "@/components/ui/button"
import {
  Shield,
  BookOpen,
  Server,
  Terminal,
  Cloud,
  PenToolIcon as Tool,
  Award,
  FlaskRoundIcon as Flask,
  Briefcase,
} from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"

export default function HomePage() {
  const guides = [
    { title: "Networking Basics", path: "/networking", icon: Server },
    { title: "Linux Security", path: "/linux", icon: Terminal },
    { title: "Windows Security", path: "/windows", icon: Terminal },
    { title: "Cloud Security", path: "/cloud", icon: Cloud },
    { title: "Security Tools", path: "/tools", icon: Tool },
    { title: "Certifications", path: "/certifications", icon: Award },
    { title: "Labs & Projects", path: "/labs", icon: Flask },
    { title: "Job Hunting", path: "/job-hunting", icon: Briefcase },
  ]

  return (
    <div className="max-w-5xl mx-auto space-y-12">
      <section className="text-center space-y-6 py-12">
        <div className="inline-block p-3 bg-primary/10 rounded-full mb-4">
          <Shield className="h-12 w-12 text-primary" />
        </div>
        <h1 className="text-4xl md:text-5xl font-bold tracking-tight">🛡️ How to Become a Security Engineer</h1>
        <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
          Welcome! This guide will help you build the skills, mindset, and hands-on experience needed to become a
          Security Engineer.
        </p>
        <div className="flex justify-center gap-4">
          <Button asChild size="lg">
            <Link href="/roadmap">Start the Roadmap →</Link>
          </Button>
        </div>
      </section>

      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t"></div>
        </div>
        <div className="relative flex justify-center">
          <span className="bg-background px-4 text-muted-foreground">Reference Guides</span>
        </div>
      </div>

      <section>
        <h2 className="text-3xl font-bold text-center mb-8">
          <BookOpen className="h-8 w-8 inline-block mr-2 text-primary" />
          Reference Guides
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {guides.map((guide) => (
            <Link key={guide.path} href={guide.path}>
              <Card className="h-full hover:shadow-md transition-shadow">
                <CardContent className="p-6 flex flex-col items-center text-center">
                  <guide.icon className="h-10 w-10 text-primary mb-4" />
                  <h3 className="text-lg font-semibold">{guide.title}</h3>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </section>
    </div>
  )
}
