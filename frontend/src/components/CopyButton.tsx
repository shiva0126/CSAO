import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard API unavailable (e.g. insecure context) -- silently no-op
    }
  }

  return (
    <Button variant="outline" size="sm" onClick={onCopy}>
      {copied ? <Check className="size-4 text-green-600" /> : <Copy className="size-4" />}
      {copied ? 'Copied' : label}
    </Button>
  )
}
