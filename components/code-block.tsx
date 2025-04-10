interface CodeBlockProps {
  code: string
  language?: string
}

export function CodeBlock({ code, language = "bash" }: CodeBlockProps) {
  return (
    <div className="bg-muted p-2 rounded-md overflow-x-auto">
      <pre className="text-xs">
        <code className={`language-${language}`}>{code}</code>
      </pre>
    </div>
  )
}
