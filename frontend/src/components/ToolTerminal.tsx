import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { Button } from '@/components/ui/button'

function wsUrl(toolKey: string): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.host}/api/v1/tools/${toolKey}/terminal`
}

export function ToolTerminal({
  toolKey,
  toolName,
  open,
  onOpenChange,
}: {
  toolKey: string
  toolName: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const socketRef = useRef<WebSocket | null>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onOpenChange(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onOpenChange])

  useEffect(() => {
    setError(null)
    if (!open || !containerRef.current) return

    // Hoisted only so the cleanup function below can dispose whatever was
    // actually created before an error, if any -- kept separate from the
    // `const`s inside try{} so those stay concretely typed (non-optional)
    // for every closure defined in this scope.
    let cleanupTerm: Terminal | undefined
    let cleanupSocket: WebSocket | undefined
    let cleanupObserver: ResizeObserver | undefined
    let cleanupDataDisposable: { dispose: () => void } | undefined
    let cleanupResizeDisposable: { dispose: () => void } | undefined

    try {
      const term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontSize: 13,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        theme: { background: '#0b0f19' },
      })
      cleanupTerm = term
      terminalRef.current = term
      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(containerRef.current)
      fit.fit()

      const socket = new WebSocket(wsUrl(toolKey))
      cleanupSocket = socket
      socketRef.current = socket
      socket.binaryType = 'arraybuffer'

      const sendResize = () => {
        if (socket.readyState !== WebSocket.OPEN) return
        socket.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols }))
      }

      socket.onopen = () => {
        fit.fit()
        sendResize()
        term.focus()
      }
      socket.onmessage = (event) => {
        if (event.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(event.data))
        }
      }
      socket.onerror = () => {
        term.write('\r\n\x1b[91m--- connection error -- see browser console for details ---\x1b[0m\r\n')
        console.error('ToolTerminal: WebSocket error', { toolKey, url: wsUrl(toolKey) })
      }
      socket.onclose = () => {
        term.write('\r\n\x1b[90m--- session closed ---\x1b[0m\r\n')
      }

      cleanupDataDisposable = term.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(new TextEncoder().encode(data))
        }
      })
      cleanupResizeDisposable = term.onResize(sendResize)

      cleanupObserver = new ResizeObserver(() => fit.fit())
      cleanupObserver.observe(containerRef.current)
    } catch (err) {
      console.error('ToolTerminal: failed to initialize', err)
      setError(err instanceof Error ? err.message : String(err))
    }

    return () => {
      cleanupObserver?.disconnect()
      cleanupDataDisposable?.dispose()
      cleanupResizeDisposable?.dispose()
      cleanupSocket?.close()
      cleanupTerm?.dispose()
      socketRef.current = null
      terminalRef.current = null
    }
  }, [open, toolKey])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={() => onOpenChange(false)}>
      <div
        className="w-full max-w-3xl rounded-xl bg-popover p-4 text-popover-foreground shadow-xl ring-1 ring-foreground/10"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-medium text-base">{toolName} terminal</h2>
          <Button variant="ghost" size="icon-sm" onClick={() => onOpenChange(false)}>
            <X className="size-4" />
          </Button>
        </div>
        {error && <p className="text-sm text-destructive mb-3">Failed to start terminal: {error}</p>}
        <div ref={containerRef} className="h-[60vh] rounded-md overflow-hidden bg-[#0b0f19] p-2" />
      </div>
    </div>
  )
}
