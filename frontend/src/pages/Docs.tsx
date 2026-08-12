import { useMemo, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Network, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useAttackPathCatalog, useDoc, useDocsList, useMitreReference } from '@/lib/queries'

const CATEGORY_ORDER = ['Guides', 'Security & Permissions', 'Audit Reports', 'Engineering Log']

type Selection = { kind: 'doc'; id: string } | { kind: 'mitre' } | { kind: 'attack-paths' }

function MarkdownView({ id }: { id: string }) {
  const doc = useDoc(id)
  if (doc.isLoading) return <p className="text-muted-foreground">Loading…</p>
  if (!doc.data) return <p className="text-destructive">Failed to load this document.</p>
  return (
    <article className="max-w-3xl space-y-4">
      <h1 className="text-2xl font-semibold">{doc.data.title}</h1>
      <div className="markdown-body text-sm leading-relaxed">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            h1: (p) => <h2 className="text-xl font-semibold mt-6 mb-2" {...p} />,
            h2: (p) => <h3 className="text-lg font-semibold mt-5 mb-2" {...p} />,
            h3: (p) => <h4 className="text-base font-semibold mt-4 mb-1.5" {...p} />,
            p: (p) => <p className="text-muted-foreground mb-3" {...p} />,
            ul: (p) => <ul className="list-disc list-inside space-y-1 mb-3 text-muted-foreground" {...p} />,
            ol: (p) => <ol className="list-decimal list-inside space-y-1 mb-3 text-muted-foreground" {...p} />,
            li: (p) => <li {...p} />,
            code: (p) => <code className="bg-muted px-1 py-0.5 rounded text-xs font-mono" {...p} />,
            pre: (p) => <pre className="bg-muted p-3 rounded-md overflow-x-auto text-xs font-mono mb-3" {...p} />,
            a: (p) => <a className="text-primary underline underline-offset-2" {...p} />,
            table: (p) => <div className="overflow-x-auto mb-3"><table className="w-full text-xs border border-border" {...p} /></div>,
            th: (p) => <th className="border border-border bg-muted px-2 py-1 text-left font-medium" {...p} />,
            td: (p) => <td className="border border-border px-2 py-1" {...p} />,
            hr: () => <hr className="border-border my-4" />,
          }}
        >
          {doc.data.content}
        </ReactMarkdown>
      </div>
    </article>
  )
}

function MitreReferenceView() {
  const mitre = useMitreReference()
  const [search, setSearch] = useState('')
  const rows = useMemo(() => {
    const all = mitre.data?.rows ?? []
    if (!search) return all
    const q = search.toLowerCase()
    return all.filter((r) => `${r.tool} ${r.check_id} ${r.tactic} ${r.technique} ${r.technique_id}`.toLowerCase().includes(q))
  }, [mitre.data, search])

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold mb-1">MITRE ATT&CK Reference</h1>
        <p className="text-sm text-muted-foreground">
          Every collector check that maps to a MITRE ATT&CK technique, sourced from{' '}
          <code className="bg-muted px-1 rounded text-xs">data/mitre_mappings.yaml</code>.
        </p>
      </div>
      <input
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Filter by tool, check, tactic, or technique…"
        className="w-full max-w-sm h-8 rounded-md border border-border bg-background px-3 text-sm"
      />
      <Card>
        <CardContent className="max-h-[65vh] overflow-y-auto p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tool</TableHead>
                <TableHead>Check</TableHead>
                <TableHead>Tactic</TableHead>
                <TableHead>Technique</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((r, i) => (
                <TableRow key={i}>
                  <TableCell className="capitalize">{r.tool}</TableCell>
                  <TableCell className="font-mono text-xs">{r.check_id}</TableCell>
                  <TableCell>{r.tactic}</TableCell>
                  <TableCell>
                    {r.technique_id} — {r.technique}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

function AttackPathCatalogView() {
  const catalog = useAttackPathCatalog()
  const rows = catalog.data?.rows ?? []
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold mb-1">Attack Path Catalog</h1>
        <p className="text-sm text-muted-foreground">
          The {rows.length} named multi-step attack paths CSAO correlates findings against, sourced from{' '}
          <code className="bg-muted px-1 rounded text-xs">data/attack_path_catalog.yaml</code>.
        </p>
      </div>
      <div className="space-y-3">
        {rows.map((r) => (
          <Card key={r.ap_code}>
            <CardContent className="py-4 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-muted-foreground">{r.ap_code}</span>
                <span className="font-medium">{r.name}</span>
                <Badge variant={r.severity === 'Critical' ? 'destructive' : 'outline'}>{r.severity}</Badge>
              </div>
              <p className="text-sm text-muted-foreground">{r.kill_chain_summary}</p>
              <p className="text-xs text-muted-foreground">
                Domains: {r.domains_spanned} · STRIDE: {r.stride_categories}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}

export function DocsPage() {
  const docs = useDocsList()
  const [selection, setSelection] = useState<Selection | null>(null)

  const grouped = useMemo(() => {
    const rows = docs.data?.rows ?? []
    const byCategory: Record<string, typeof rows> = {}
    for (const row of rows) {
      byCategory[row.category] = byCategory[row.category] ?? []
      byCategory[row.category].push(row)
    }
    return byCategory
  }, [docs.data])

  const active: Selection = selection ?? (docs.data?.rows[0] ? { kind: 'doc', id: docs.data.rows[0].id } : { kind: 'mitre' })

  return (
    <div className="flex gap-6">
      <nav className="w-64 shrink-0 space-y-4">
        {CATEGORY_ORDER.filter((c) => grouped[c]?.length).map((category) => (
          <div key={category}>
            <div className="text-xs font-semibold uppercase text-muted-foreground mb-1.5 px-1">{category}</div>
            <div className="space-y-0.5">
              {grouped[category].map((doc) => (
                <button
                  key={doc.id}
                  onClick={() => setSelection({ kind: 'doc', id: doc.id })}
                  className={`w-full text-left rounded-md px-2 py-1.5 text-sm transition-colors ${
                    active.kind === 'doc' && active.id === doc.id
                      ? 'bg-primary text-primary-foreground'
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  }`}
                  title={doc.description}
                >
                  {doc.title}
                </button>
              ))}
            </div>
          </div>
        ))}
        <div>
          <div className="text-xs font-semibold uppercase text-muted-foreground mb-1.5 px-1">Reference / Theory</div>
          <div className="space-y-0.5">
            <button
              onClick={() => setSelection({ kind: 'mitre' })}
              className={`w-full flex items-center gap-2 text-left rounded-md px-2 py-1.5 text-sm transition-colors ${
                active.kind === 'mitre' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              }`}
            >
              <ShieldCheck className="size-3.5" /> MITRE ATT&CK Mappings
            </button>
            <button
              onClick={() => setSelection({ kind: 'attack-paths' })}
              className={`w-full flex items-center gap-2 text-left rounded-md px-2 py-1.5 text-sm transition-colors ${
                active.kind === 'attack-paths' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
              }`}
            >
              <Network className="size-3.5" /> Attack Path Catalog
            </button>
          </div>
        </div>
      </nav>
      <div className="flex-1 min-w-0">
        {active.kind === 'doc' && <MarkdownView id={active.id} />}
        {active.kind === 'mitre' && <MitreReferenceView />}
        {active.kind === 'attack-paths' && <AttackPathCatalogView />}
      </div>
    </div>
  )
}
