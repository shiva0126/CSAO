import { useState, type FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  useActiveMonitor,
  useAssessmentHistory,
  useCancelAssessment,
  useStartAssessment,
  useWizardDefaults,
} from '@/lib/queries'
import { ApiError } from '@/lib/api'
import type { AssessmentHistoryItem } from '@/lib/types'

export function AssessmentsPage() {
  const wizard = useWizardDefaults()
  const history = useAssessmentHistory()
  const startAssessment = useStartAssessment()
  const cancelAssessment = useCancelAssessment()

  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [description, setDescription] = useState('')
  const [accountId, setAccountId] = useState('')
  const [regions, setRegions] = useState('')
  const [collectors, setCollectors] = useState<string[]>([])
  const [error, setError] = useState('')

  const monitor = useActiveMonitor(true)
  const isRunning = monitor.data?.status === 'RUNNING'

  function toggleCollector(key: string) {
    setCollectors((prev) => (prev.includes(key) ? prev.filter((c) => c !== key) : [...prev, key]))
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await startAssessment.mutateAsync({
        name,
        client,
        description,
        assessment_type: 'full',
        cloud_account_id: accountId,
        regions: regions.split(',').map((r) => r.trim()).filter(Boolean),
        collectors,
        services: [],
        output_location: 'output',
        risk_profile: 'balanced',
        report_types: ['html'],
      })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to start assessment')
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Assessments</h1>

      {isRunning && monitor.data && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Assessment in progress — {monitor.data.assessment?.name}</span>
              <Button variant="destructive" size="sm" onClick={() => cancelAssessment.mutate()}>
                Cancel
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
              <div
                className="bg-primary h-full transition-all"
                style={{ width: `${monitor.data.progress ?? 0}%` }}
              />
            </div>
            <div className="text-sm text-muted-foreground">
              {monitor.data.status_message} — stage: {monitor.data.current_stage} ({monitor.data.progress ?? 0}%)
            </div>
          </CardContent>
        </Card>
      )}

      {!isRunning && (
        <Card>
          <CardHeader>
            <CardTitle>Launch New Assessment</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Assessment name</Label>
                  <Input id="name" value={name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setName(e.target.value)} required />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="client">Client</Label>
                  <Input id="client" value={client} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setClient(e.target.value)} />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea id="description" value={description} onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setDescription(e.target.value)} />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Cloud account</Label>
                  <Select value={accountId} onValueChange={setAccountId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a validated account" />
                    </SelectTrigger>
                    <SelectContent>
                      {(wizard.data?.accounts ?? []).map((a) => (
                        <SelectItem key={a.id} value={a.id}>
                          {a.name} {a.read_only_validated ? '' : '(not validated)'}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="regions">Regions (comma-separated)</Label>
                  <Input id="regions" placeholder="us-east-1, us-west-2" value={regions} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setRegions(e.target.value)} />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Collectors</Label>
                <p className="text-xs text-muted-foreground">
                  What each tool checks, the AWS permissions it needs, and whether it's currently
                  installed on this machine — see the Trust Center tab in Admin for install status.
                </p>
                <div className="grid gap-2">
                  {(wizard.data?.collectors ?? []).map((c) => (
                    <button
                      key={c.key}
                      type="button"
                      onClick={() => toggleCollector(c.key)}
                      className={`text-left border rounded-md p-3 transition-colors ${
                        collectors.includes(c.key)
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:bg-accent'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-sm">{c.label}</span>
                        <Badge variant="outline" className="text-xs">{c.runtime} runtime</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{c.description}</p>
                      {c.services?.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-1">
                          Services: {c.services.join(', ')}
                        </p>
                      )}
                    </button>
                  ))}
                </div>
              </div>

              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" disabled={startAssessment.isPending || !accountId}>
                {startAssessment.isPending ? 'Starting…' : 'Launch Assessment'}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>History</CardTitle>
        </CardHeader>
        <CardContent>
          {(history.data?.history as AssessmentHistoryItem[] | undefined)?.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Account</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(history.data!.history as AssessmentHistoryItem[]).map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="font-medium">{item.name}</TableCell>
                    <TableCell>{item.account_name}</TableCell>
                    <TableCell>
                      <Badge variant={item.status === 'FAILED' ? 'destructive' : 'secondary'}>{item.status}</Badge>
                    </TableCell>
                    <TableCell>{item.started}</TableCell>
                    <TableCell>{item.finding_count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-muted-foreground text-sm">No assessments run yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
