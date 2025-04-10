import type React from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface ReferenceGuideProps {
  title: string
  icon: React.ReactNode
  concepts: string[]
  tools: string[]
  practiceTips: string[]
}

export function ReferenceGuide({ title, icon, concepts, tools, practiceTips }: ReferenceGuideProps) {
  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center gap-3 mb-8">
        {icon}
        <h1 className="text-4xl font-bold">{title}</h1>
      </div>

      <div className="space-y-8">
        <Card>
          <CardHeader>
            <CardTitle>Key Concepts</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {concepts.map((concept, index) => (
                <li key={index} className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>{concept}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Tools</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {tools.map((tool, index) => (
                <li key={index} className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>{tool}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Practice Tips</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              {practiceTips.map((tip, index) => (
                <li key={index} className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>{tip}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
