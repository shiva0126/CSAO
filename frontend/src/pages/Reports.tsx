import { ExternalLink, Archive } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useReports } from '@/lib/queries'
import { api } from '@/lib/api'

export function ReportsPage() {
  const { data, isLoading, error, refetch } = useReports()

  async function archive(name: string) {
    await api.post(`/reports/${name}/archive`)
    refetch()
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Reports</h1>

      {isLoading && <p className="text-muted-foreground">Loading reports…</p>}
      {error && <p className="text-destructive">Failed to load reports.</p>}

      {data && data.rows.length === 0 && (
        <p className="text-muted-foreground text-sm">
          No reports generated yet — completed assessments produce a report here.
        </p>
      )}

      {data && data.rows.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Report</TableHead>
              <TableHead>Generated</TableHead>
              <TableHead>Re-runs</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.rows.map((row) => (
              <TableRow key={row.name}>
                <TableCell className="font-medium">{row.title || row.name}</TableCell>
                <TableCell>{row.generated_at}</TableCell>
                <TableCell>
                  {row.version_count > 0 ? <Badge variant="outline">{row.version_count} version(s)</Badge> : '—'}
                </TableCell>
                <TableCell className="text-right space-x-2">
                  <Button asChild size="sm" variant="outline">
                    <a href={row.download_href ?? `/reports/${row.name}`} target="_blank" rel="noreferrer">
                      <ExternalLink className="size-3.5 mr-1" /> View
                    </a>
                  </Button>
                  {row.previewable !== false && (
                    <Button size="sm" variant="ghost" onClick={() => archive(row.name)}>
                      <Archive className="size-3.5 mr-1" /> Archive
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
