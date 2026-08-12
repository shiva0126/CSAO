import { useState } from 'react'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useFindings, type FindingFilters } from '@/lib/queries'
import { FindingDrawer } from '@/components/FindingDrawer'
import type { FindingRow } from '@/lib/types'

const FILTER_TOGGLES: { key: keyof FindingFilters; label: string }[] = [
  { key: 'high_risk', label: 'High risk' },
  { key: 'needs_review', label: 'Needs review' },
  { key: 'manual_validation', label: 'Manual validation' },
  { key: 'crown_jewel', label: 'Crown jewel' },
  { key: 'internet_facing', label: 'Internet-facing' },
]

function severityVariant(severity: string): 'destructive' | 'secondary' | 'outline' {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'destructive'
  if (severity === 'MEDIUM') return 'secondary'
  return 'outline'
}

export function FindingsPage() {
  const [filters, setFilters] = useState<FindingFilters>({})
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<FindingRow | null>(null)

  const { data, isLoading, error } = useFindings({ ...filters, search })

  function toggle(key: keyof FindingFilters) {
    setFilters((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <span className="text-sm text-muted-foreground">{data?.rows.length ?? 0} finding(s)</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search resource, title, service…"
          value={search}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        {FILTER_TOGGLES.map(({ key, label }) => (
          <Button
            key={key}
            size="sm"
            variant={filters[key] ? 'default' : 'outline'}
            onClick={() => toggle(key)}
          >
            {label}
          </Button>
        ))}
      </div>

      {isLoading && <p className="text-muted-foreground">Loading findings…</p>}
      {error && <p className="text-destructive">Failed to load findings.</p>}

      {data && data.rows.length === 0 && (
        <p className="text-muted-foreground text-sm">
          No findings yet — run an assessment from the Assessments page to populate this view.
        </p>
      )}

      {data && data.rows.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Resource</TableHead>
              <TableHead>Service</TableHead>
              <TableHead>Risk</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Flags</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.rows.map((row) => (
              <TableRow
                key={row.register_id}
                className="cursor-pointer"
                onClick={() => setSelected(row)}
              >
                <TableCell>
                  <Badge variant={severityVariant(row.severity)}>{row.severity}</Badge>
                </TableCell>
                <TableCell className="font-medium">{row.title || row.resource}</TableCell>
                <TableCell>{row.cloud_service}</TableCell>
                <TableCell>{row.risk}</TableCell>
                <TableCell>{row.status}</TableCell>
                <TableCell className="space-x-1">
                  {row.crown_jewel && <Badge variant="outline">Crown Jewel</Badge>}
                  {row.internet_facing && <Badge variant="outline">Internet-facing</Badge>}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
