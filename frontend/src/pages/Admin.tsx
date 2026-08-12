import { useState, type FormEvent } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  useAccounts,
  useRemoveAccount,
  useSaveAccount,
  useSettings,
  useTestAccount,
  useTrustCenter,
  useUsers,
} from '@/lib/queries'
import { api, ApiError } from '@/lib/api'

function AccountsTab() {
  const accounts = useAccounts()
  const saveAccount = useSaveAccount()
  const removeAccount = useRemoveAccount()
  const testAccount = useTestAccount()
  const [form, setForm] = useState({ name: '', auth_type: 'profile', profile: '', regions: '' })
  const [error, setError] = useState('')

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await saveAccount.mutateAsync(form)
      setForm({ name: '', auth_type: 'profile', profile: '', regions: '' })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save account')
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Add Cloud Account</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={form.name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, name: e.target.value }))} required />
            </div>
            <div className="space-y-2">
              <Label>AWS profile</Label>
              <Input value={form.profile} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, profile: e.target.value }))} placeholder="default" />
            </div>
            <div className="space-y-2 col-span-2">
              <Label>Regions (comma-separated)</Label>
              <Input value={form.regions} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, regions: e.target.value }))} placeholder="us-east-1" />
            </div>
            {error && <p className="text-sm text-destructive col-span-2">{error}</p>}
            <Button type="submit" className="col-span-2 w-fit" disabled={saveAccount.isPending}>
              Save Account
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Cloud Accounts</CardTitle>
        </CardHeader>
        <CardContent>
          {accounts.data?.accounts.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Auth Type</TableHead>
                  <TableHead>Validation</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.data.accounts.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="font-medium">{a.name}</TableCell>
                    <TableCell>{a.auth_type}</TableCell>
                    <TableCell>
                      <Badge variant={a.last_validation_status === 'VALIDATED' ? 'secondary' : 'outline'}>
                        {a.last_validation_status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button size="sm" variant="outline" onClick={() => testAccount.mutate(a.id)}>
                        Test
                      </Button>
                      <Button size="sm" variant="destructive" onClick={() => removeAccount.mutate(a.id)}>
                        Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-muted-foreground text-sm">No cloud accounts configured yet.</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function SettingsTab() {
  const settings = useSettings()
  if (settings.isLoading) return <p className="text-muted-foreground">Loading settings…</p>
  return (
    <Card>
      <CardHeader>
        <CardTitle>Runtime Configuration</CardTitle>
      </CardHeader>
      <CardContent>
        <pre className="text-xs bg-muted p-3 rounded-md overflow-x-auto max-h-96">
          {JSON.stringify(settings.data?.config, null, 2)}
        </pre>
      </CardContent>
    </Card>
  )
}

function UsersTab() {
  const users = useUsers()
  const [form, setForm] = useState({ username: '', display_name: '', role: 'READ_ONLY', password: '' })
  const [error, setError] = useState('')

  async function createUser(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      await api.post('/users', form)
      setForm({ username: '', display_name: '', role: 'READ_ONLY', password: '' })
      users.refetch()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create user')
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Add User</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={createUser} className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Username</Label>
              <Input value={form.username} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, username: e.target.value }))} required />
            </div>
            <div className="space-y-2">
              <Label>Display name</Label>
              <Input value={form.display_name} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, display_name: e.target.value }))} />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <Input value={form.role} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, role: e.target.value }))} placeholder="READ_ONLY / ANALYST / ADMINISTRATOR" />
            </div>
            <div className="space-y-2">
              <Label>Password (min 12 chars)</Label>
              <Input type="password" value={form.password} onChange={(e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, password: e.target.value }))} required />
            </div>
            {error && <p className="text-sm text-destructive col-span-2">{error}</p>}
            <Button type="submit" className="col-span-2 w-fit">Add User</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Active</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users.data?.users ?? []).map((u) => (
                <TableRow key={String(u.id)}>
                  <TableCell className="font-medium">{String(u.username)}</TableCell>
                  <TableCell>{String(u.role)}</TableCell>
                  <TableCell>{u.is_active ? 'Yes' : 'No'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

function TrustCenterTab() {
  const trustCenter = useTrustCenter()
  const data = trustCenter.data

  if (trustCenter.isLoading) return <p className="text-muted-foreground">Loading…</p>
  if (!data) return <p className="text-destructive">Failed to load Trust Center data.</p>

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Collector Tool Status</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground mb-1">
            Whether each external scanning tool is actually installed in the worker that runs
            assessments — a tool can be "enabled" in configuration while still being unavailable to run.
          </p>
          {data.tool_status_checked_at && (
            <p className="text-xs text-muted-foreground mb-3">
              Reported by the assessment worker at {data.tool_status_checked_at} (checked once per
              worker startup/restart).
            </p>
          )}
          {data.tool_validation.length === 0 && (
            <p className="text-sm text-muted-foreground mb-3">
              No status reported yet — the assessment worker reports this once at startup. If this
              stays empty, check that the worker container is running.
            </p>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tool</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Read-only mode</TableHead>
                <TableHead>Required</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.tool_validation.map((t) => (
                <TableRow key={t.name}>
                  <TableCell className="font-medium">{t.name}</TableCell>
                  <TableCell>
                    <Badge variant={t.installed ? 'secondary' : 'destructive'}>
                      {t.installed ? 'Installed' : 'Not installed'}
                    </Badge>
                  </TableCell>
                  <TableCell>{t.version || '—'}</TableCell>
                  <TableCell>{t.read_only_mode}</TableCell>
                  <TableCell>{t.required ? 'Yes' : 'Optional'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Read-Only Guarantee</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="list-disc list-inside text-sm space-y-1">
            {data.read_only_guarantee.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
          <div className="mt-3">
            <Badge variant={data.safety_validation.status === 'PASSED' ? 'secondary' : 'destructive'}>
              Safety validation: {data.safety_validation.status}
            </Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Permission Matrix ({data.permission_matrix.length} entries)</CardTitle>
        </CardHeader>
        <CardContent className="max-h-96 overflow-y-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service</TableHead>
                <TableHead>Collector</TableHead>
                <TableHead>Purpose</TableHead>
                <TableHead>IAM Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.permission_matrix.map((row, i) => (
                <TableRow key={i}>
                  <TableCell className="font-medium">{row.aws_service}</TableCell>
                  <TableCell>{row.collector}</TableCell>
                  <TableCell className="text-sm">{row.purpose}</TableCell>
                  <TableCell className="text-xs font-mono">{row.iam_actions.join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>FAQ</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {data.faq.map((item, i) => (
            <div key={i}>
              <div className="font-medium text-sm">{item.q}</div>
              <div className="text-sm text-muted-foreground">{item.a}</div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

export function AdminPage() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Admin</h1>
      <Tabs defaultValue="accounts">
        <TabsList>
          <TabsTrigger value="accounts">Accounts</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="trust-center">Trust Center</TabsTrigger>
        </TabsList>
        <TabsContent value="accounts"><AccountsTab /></TabsContent>
        <TabsContent value="settings"><SettingsTab /></TabsContent>
        <TabsContent value="users"><UsersTab /></TabsContent>
        <TabsContent value="trust-center"><TrustCenterTab /></TabsContent>
      </Tabs>
    </div>
  )
}
