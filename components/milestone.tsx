import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import Link from "next/link"
import { ExternalLink } from "lucide-react"

interface Resource {
  name: string
  url: string
  type: "Course" | "Book" | "Tool" | "Video" | "Article" | "Practice" | "Resource"
}

interface Project {
  title: string
  description: string
}

export interface MilestoneProps {
  number: number
  title: string
  description: string
  timeframe: string
  skillLevel: "Beginner" | "Intermediate" | "Advanced"
  keyTopics: string[]
  resources: Resource[]
  projects: Project[]
}

export function Milestone({
  number,
  title,
  description,
  timeframe,
  skillLevel,
  keyTopics,
  resources,
  projects,
}: MilestoneProps) {
  const skillLevelColor = {
    Beginner: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
    Intermediate: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
    Advanced: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300",
  }

  const resourceTypeColor = {
    Course: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
    Book: "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-300",
    Tool: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
    Video: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
    Article: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300",
    Practice: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-300",
    Resource: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300",
  }

  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center">
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-primary text-primary-foreground font-bold text-xl">
          {number}
        </div>
        {number < 8 && <div className="w-0.5 h-full bg-border mt-2"></div>}
      </div>
      <Card className="flex-1">
        <CardHeader className="pb-2">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <h2 className="text-2xl font-bold">{title}</h2>
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline" className="font-normal">
                {timeframe}
              </Badge>
              <Badge className={skillLevelColor[skillLevel]}>{skillLevel}</Badge>
            </div>
          </div>
          <p className="text-muted-foreground">{description}</p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Key Topics</h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1">
              {keyTopics.map((topic, index) => (
                <li key={index} className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>{topic}</span>
                </li>
              ))}
            </ul>
          </div>

          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="resources">
              <AccordionTrigger>Learning Resources</AccordionTrigger>
              <AccordionContent>
                <ul className="space-y-3">
                  {resources.map((resource, index) => (
                    <li key={index} className="flex items-start">
                      <Badge className={`mr-2 ${resourceTypeColor[resource.type]}`}>{resource.type}</Badge>
                      <Link
                        href={resource.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center hover:underline text-primary"
                      >
                        {resource.name}
                        <ExternalLink className="ml-1 h-3 w-3" />
                      </Link>
                    </li>
                  ))}
                </ul>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="projects">
              <AccordionTrigger>Practical Projects</AccordionTrigger>
              <AccordionContent>
                <ul className="space-y-3">
                  {projects.map((project, index) => (
                    <li key={index} className="space-y-1">
                      <h4 className="font-medium">{project.title}</h4>
                      <p className="text-sm text-muted-foreground">{project.description}</p>
                    </li>
                  ))}
                </ul>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    </div>
  )
}
