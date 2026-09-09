import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createColumnHelper, tableFeatures, type ReactTable, useTable } from '@tanstack/react-table'
import { useState, type ChangeEvent } from 'react'
import { Link, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom'

type Status = { status: string; uptimeSeconds: number; metrics: Record<string, number> }
type Profile = { ownerId: string; fileId: string; filename: string; size: number }
type ProfileDetail = Profile & { sha256: string; data: string }
type Leaderboard = { boardId: number; entityId: number; rating: number; rank: number; name: string; columns: number[] }
type Playlist = { filename: string; size: number; sha256: string; content: string }
type TableData = Profile | Leaderboard

const features = tableFeatures({})
const profileHelper = createColumnHelper<typeof features, Profile>()
const boardHelper = createColumnHelper<typeof features, Leaderboard>()
const emptyProfiles: Profile[] = []
const emptyLeaderboard: Leaderboard[] = []
const playlistMaxSize = 0x20000
const profileSize = 8192

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/admin/api/v1${path}`, init)
  if (!response.ok) throw new Error((await response.text()).trim())
  return response.json()
}

function Overview() {
  const status = useQuery({ queryKey: ['status'], queryFn: () => api<Status>('/status'), refetchInterval: 5000 })
  const playlist = useQuery({ queryKey: ['playlist'], queryFn: () => api<Playlist>('/playlist') })
  const metrics = status.data?.metrics ?? {}
  return <div className="stack">
    <div className="cards">
      <Metric label="Service" value={status.data?.status ?? 'loading'} tone="green" />
      <Metric label="LSG connections" value={metrics.lsg_connections ?? 0} />
      <Metric label="LSG frames" value={metrics.lsg_frames ?? 0} />
      <Metric label="NAT packets" value={metrics.nat_packets ?? 0} />
    </div>
    <section className="panel"><h2>Runtime</h2><dl>
      <div><dt>Uptime</dt><dd>{Math.floor((status.data?.uptimeSeconds ?? 0) / 60)} minutes</dd></div>
      <div><dt>Auth requests</dt><dd>{metrics.auth_requests ?? 0}</dd></div>
      <div><dt>Lobby requests</dt><dd>{metrics.lobby_requests ?? 0}</dd></div>
    </dl></section>
    <section className="panel"><h2>Active playlist</h2><dl>
      <div><dt>File</dt><dd>{playlist.data?.filename ?? 'loading'}</dd></div>
      <div><dt>Size</dt><dd>{playlist.data?.size.toLocaleString() ?? 0} bytes</dd></div>
      <div><dt>SHA-256</dt><dd className="hash">{playlist.data?.sha256 ?? 'loading'}</dd></div>
    </dl></section>
  </div>
}

function Metric({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return <div className="metric"><span>{label}</span><strong className={tone}>{value}</strong></div>
}

function Profiles() {
  const [offset, setOffset] = useState(0)
  const limit = 50
  const query = useQuery({ queryKey: ['profiles', offset], queryFn: () => api<{ profiles: Profile[] }>(`/profiles?limit=${limit}&offset=${offset}`) })
  const table = useTable({ features, data: query.data?.profiles ?? emptyProfiles, columns: profileHelper.columns([
    profileHelper.accessor('ownerId', { header: 'Owner ID' }),
    profileHelper.accessor('fileId', { header: 'File ID', cell: info => <Link to={`/profiles/${info.getValue()}`}>{info.getValue()}</Link> }),
    profileHelper.accessor('filename', { header: 'Filename' }),
    profileHelper.accessor('size', { header: 'Bytes' }),
  ]) })
  return <div className="stack"><DataTable title="Profiles" table={table} empty={query.isLoading ? 'Loading profiles' : query.isError ? query.error.message : 'No stored profiles'} /><div className="pager"><button className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</button><span>Showing {offset + 1}–{offset + (query.data?.profiles.length ?? 0)}</span><button className="secondary" disabled={(query.data?.profiles.length ?? 0) < limit} onClick={() => setOffset(offset + limit)}>Next</button></div></div>
}

function ProfileEditor() {
  const { fileId = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['profile', fileId], queryFn: () => api<ProfileDetail>(`/profiles/${fileId}`) })
  const [draft, setDraft] = useState<string>()
  const [message, setMessage] = useState('')
  const sourceHex = query.data ? bytesToHex(base64ToBytes(query.data.data)) : ''
  const content = draft ?? sourceHex
  const parsed = parseHex(content)
  const dirty = query.data !== undefined && content !== sourceHex
  const mutation = useMutation({
    mutationFn: (data: Uint8Array) => api<ProfileDetail>(`/profiles/${fileId}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer }),
    onSuccess: data => {
      queryClient.setQueryData(['profile', fileId], data)
      void queryClient.invalidateQueries({ queryKey: ['profiles'] })
      setDraft(undefined)
      setMessage('Profile saved. New game reads will use it immediately.')
    },
    onError: error => setMessage(error instanceof Error ? error.message : 'Save failed'),
  })
  const remove = useMutation({
    mutationFn: async () => {
      const response = await fetch(`/admin/api/v1/profiles/${fileId}`, { method: 'DELETE' })
      if (!response.ok) throw new Error((await response.text()).trim())
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['profiles'] })
      navigate('/profiles')
    },
    onError: error => setMessage(error instanceof Error ? error.message : 'Delete failed'),
  })
  const upload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    const data = new Uint8Array(await file.arrayBuffer())
    if (data.length !== profileSize) {
      setMessage(`Profile must be exactly ${profileSize} bytes; selected file is ${data.length} bytes.`)
      return
    }
    setDraft(bytesToHex(data))
    setMessage('')
  }
  if (query.isLoading) return <section className="panel"><div className="empty">Loading profile</div></section>
  if (query.isError || !query.data) return <section className="panel"><div className="empty error-text">{query.error?.message ?? 'Profile not found'}</div></section>
  return <section className="panel editor-panel">
    <div className="editor-heading"><div><Link className="back-link" to="/profiles">← Profiles</Link><h2>Profile {fileId}</h2><p>Owner {query.data.ownerId} · exact 8192-byte iw4-mpdata blob</p></div><div className="editor-actions"><a className="button-link secondary" href={`/admin/api/v1/profiles/${fileId}/download`}>Download</a><label className="button-link secondary">Upload<input type="file" hidden onChange={upload} /></label><button type="button" className="danger" onClick={() => { if (window.confirm(`Delete profile ${fileId}?`)) remove.mutate() }} disabled={remove.isPending}>Delete</button><button type="button" className="secondary" onClick={() => { setDraft(undefined); setMessage('') }} disabled={!dirty || mutation.isPending}>Discard</button><button type="button" onClick={() => { if (parsed.data) mutation.mutate(parsed.data) }} disabled={!dirty || parsed.data === undefined || mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save profile'}</button></div></div>
    {message && <p className={`notice ${mutation.isError || remove.isError || parsed.error ? 'error' : 'success'}`}>{message}</p>}
    <textarea className="hex-editor" aria-label="Profile hex data" spellCheck={false} value={content} onChange={event => { setDraft(event.target.value); setMessage('') }} />
    <div className="editor-meta"><span className={dirty ? 'dirty' : ''}>{dirty ? 'Unsaved changes' : 'Saved'}</span><span className={parsed.error ? 'error-text' : ''}>{parsed.error ?? `${parsed.data?.length ?? 0} / ${profileSize} bytes`}</span><span className="hash">{query.data.sha256}</span></div>
  </section>
}

function base64ToBytes(value: string) {
  const binary = atob(value)
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}

function bytesToHex(data: Uint8Array) {
  const lines: string[] = []
  for (let offset = 0; offset < data.length; offset += 16) {
    lines.push(Array.from(data.slice(offset, offset + 16), value => value.toString(16).padStart(2, '0')).join(' '))
  }
  return lines.join('\n')
}

function parseHex(value: string): { data?: Uint8Array; error?: string } {
  const compact = value.replace(/\s/g, '')
  if (/[^0-9a-f]/i.test(compact)) return { error: 'Hex contains invalid characters' }
  if (compact.length % 2 !== 0) return { error: 'Hex contains an incomplete byte' }
  const data = new Uint8Array(compact.length / 2)
  for (let index = 0; index < compact.length; index += 2) data[index / 2] = Number.parseInt(compact.slice(index, index + 2), 16)
  if (data.length !== profileSize) return { error: `${data.length} / ${profileSize} bytes` }
  return { data }
}

function Leaderboards() {
  const query = useQuery({ queryKey: ['leaderboards'], queryFn: () => api<{ rows: Leaderboard[] }>('/leaderboards?boardId=1') })
  const table = useTable({ features, data: query.data?.rows ?? emptyLeaderboard, columns: boardHelper.columns([
    boardHelper.accessor('rank', { header: 'Rank' }), boardHelper.accessor('name', { header: 'Player' }),
    boardHelper.accessor('entityId', { header: 'Entity ID' }), boardHelper.accessor('rating', { header: 'Rating' }),
  ]) })
  return <DataTable title="Leaderboard · Board 1" table={table} empty="No leaderboard rows" />
}

function PlaylistEditor() {
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['playlist'], queryFn: () => api<Playlist>('/playlist') })
  const [draft, setDraft] = useState<string>()
  const [message, setMessage] = useState('')
  const content = draft ?? query.data?.content ?? ''
  const mutation = useMutation({
    mutationFn: (value: string) => api<Playlist>('/playlist', { method: 'PUT', headers: { 'Content-Type': 'text/plain; charset=utf-8' }, body: value }),
    onSuccess: data => {
      queryClient.setQueryData(['playlist'], data)
      setDraft(undefined)
      setMessage('Playlist saved. New storage requests will use it immediately.')
    },
    onError: error => setMessage(error instanceof Error ? error.message : 'Save failed'),
  })
  const size = new TextEncoder().encode(content).length
  const dirty = query.data !== undefined && content !== query.data.content
  const reset = () => {
    if (dirty && !window.confirm('Discard unsaved playlist changes?')) return
    setDraft(undefined)
    setMessage('')
  }
  return <section className="panel editor-panel">
    <div className="editor-heading"><div><h2>Playlist editor</h2><p>Changes are validated, saved atomically, and served without restarting the container.</p></div><div className="editor-actions"><button type="button" className="secondary" onClick={reset} disabled={!dirty || mutation.isPending}>Discard</button><button type="button" onClick={() => mutation.mutate(content)} disabled={!dirty || size > playlistMaxSize || mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save playlist'}</button></div></div>
    {query.isError && <p className="notice error">{query.error.message}</p>}
    {message && <p className={`notice ${mutation.isError ? 'error' : 'success'}`}>{message}</p>}
    <textarea aria-label="Playlist content" spellCheck={false} value={content} onChange={event => { setDraft(event.target.value); setMessage('') }} disabled={query.isLoading} />
    <div className="editor-meta"><span className={dirty ? 'dirty' : ''}>{dirty ? 'Unsaved changes' : 'Saved'}</span><span className={size > playlistMaxSize ? 'error-text' : ''}>{size.toLocaleString()} / {playlistMaxSize.toLocaleString()} bytes</span><span className="hash">{query.data?.sha256 ?? 'loading'}</span></div>
  </section>
}

function DataTable<T extends TableData>({ title, table, empty }: { title: string; table: ReactTable<typeof features, T>; empty: string }) {
  return <section className="panel table-panel"><h2>{title}</h2><div className="table-wrap"><table><thead>{table.getHeaderGroups().map(group => <tr key={group.id}>{group.headers.map(header => <th key={header.id}>{header.isPlaceholder ? null : <table.FlexRender header={header} />}</th>)}</tr>)}</thead><tbody>{table.getRowModel().rows.map(row => <tr key={row.id}>{row.getAllCells().map(cell => <td key={cell.id}><table.FlexRender cell={cell} /></td>)}</tr>)}</tbody></table>{table.getRowModel().rows.length === 0 && <div className="empty">{empty}</div>}</div></section>
}

function App() {
  return <div className="shell"><aside><div className="brand"><span>IW4</span><div>MW2<br/><small>operations</small></div></div><nav>
    <NavLink to="/">Overview</NavLink><NavLink to="/playlist">Playlist</NavLink><NavLink to="/profiles">Profiles</NavLink><NavLink to="/leaderboards">Leaderboards</NavLink>
  </nav></aside><main><header><div><p>DEMONWARE EMULATOR</p><h1>Operations Console</h1></div><span className="live">LIVE</span></header><Routes><Route path="/" element={<Overview />} /><Route path="/playlist" element={<PlaylistEditor />} /><Route path="/profiles" element={<Profiles />} /><Route path="/profiles/:fileId" element={<ProfileEditor />} /><Route path="/leaderboards" element={<Leaderboards />} /></Routes></main></div>
}

export default App
