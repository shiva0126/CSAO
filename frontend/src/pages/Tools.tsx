import { useState } from 'react'
import { TerminalSquare } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ToolTerminal } from '@/components/ToolTerminal'
import { useTrustCenter } from '@/lib/queries'

export function ToolsPage() {
  const trustCenter = useTrustCenter()
  const tools = trustCenter.data?.tool_validation ?? []
  const [openTool, setOpenTool] = useState<{ key: string; name: string } | null>(null)

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">Tools</h1>
        <p className="text-sm text-muted-foreground">
          Every collector tool CSAO installs automatically in the assessment worker. Status is reported by the
          worker itself
          {trustCenter.data?.tool_status_checked_at && (
            <> as of {new Date(trustCenter.data.tool_status_checked_at).toLocaleString()}</>
          )}
          . Open a tool's terminal for manual testing — it drops you straight into a shell inside the worker
          container with that tool's own help/usage guide shown first, so there's nothing to memorize or type from
          scratch.
        </p>
      </div>

      {trustCenter.isLoading && <p className="text-muted-foreground">Loading…</p>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {tools.map((tool) => (
          <Card key={tool.key}>
            <CardHeader className="flex flex-row items-start justify-between gap-2">
              <div>
                <CardTitle className="text-base">{tool.name}</CardTitle>
                {tool.purpose && <p className="text-sm text-muted-foreground mt-1">{tool.purpose}</p>}
              </div>
              <Badge variant={tool.installed ? 'secondary' : 'destructive'} className="shrink-0">
                {tool.installed ? 'Installed' : 'Not installed'}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {tool.version && <span>Version: {tool.version}</span>}
                <span>Mode: {tool.read_only_mode}</span>
                <span>{tool.required ? 'Required' : 'Optional'}</span>
              </div>
              <Button size="sm" variant="outline" onClick={() => setOpenTool({ key: tool.key, name: tool.name })}>
                <TerminalSquare className="size-4" />
                Open terminal
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>

      {openTool && (
        <ToolTerminal
          toolKey={openTool.key}
          toolName={openTool.name}
          open={!!openTool}
          onOpenChange={(next) => {
            if (!next) setOpenTool(null)
          }}
        />
      )}
    </div>
  )
}
