import { cn } from "@/lib/utils"

interface WindowsIconProps {
  className?: string
}

export function WindowsIcon({ className }: WindowsIconProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn("lucide lucide-windows", className)}
    >
      <path d="M3 12h18M12 3v18M4.2 5.4l15.6 13.2M18.2 7.2 7.8 18.6" />
      <path d="m7.8 5.4 10.4 13.2" />
    </svg>
  )
}
