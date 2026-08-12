import { useEffect, useRef } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'

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

  useEffect(() => {
    if (!open || !containerRef.current) return

    const term = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      theme: { background: '#0b0f19' },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()
    terminalRef.current = term

    const socket = new WebSocket(wsUrl(toolKey))
    socket.binaryType = 'arraybuffer'
    socketRef.current = socket

    function sendResize() {
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
    socket.onclose = () => {
      term.write('\r\n\x1b[90m--- session closed ---\x1b[0m\r\n')
    }

    const dataDisposable = term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(new TextEncoder().encode(data))
      }
    })
    const resizeDisposable = term.onResize(sendResize)

    const observer = new ResizeObserver(() => fit.fit())
    observer.observe(containerRef.current)

    return () => {
      observer.disconnect()
      dataDisposable.dispose()
      resizeDisposable.dispose()
      socket.close()
      term.dispose()
      socketRef.current = null
      terminalRef.current = null
    }
  }, [open, toolKey])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl" showCloseButton>
        <DialogHeader>
          <DialogTitle>{toolName} terminal</DialogTitle>
        </DialogHeader>
        <div ref={containerRef} className="h-[60vh] rounded-md overflow-hidden bg-[#0b0f19] p-2" />
      </DialogContent>
    </Dialog>
  )
}
