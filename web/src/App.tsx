import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createColumnHelper, tableFeatures, type ReactTable, useTable } from '@tanstack/react-table'
import { useRef, useState, type ChangeEvent } from 'react'
import { Link, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import playerdataSource from '../../files/game_assets/mp/playerdata.def?raw'
import { parseDefinition, parseProfile, updateProfile, type ProfileField } from './playerdata'

type Status = { status: string; uptimeSeconds: number; metrics: Record<string, number> }
type Profile = { ownerId: string; fileId: string; filename: string; size: number }
type ProfileDetail = Profile & { sha256: string; data: string }
type Leaderboard = { boardId: number; entityId: number; rating: number; rank: number; name: string; columns: number[] }
type Playlist = { filename: string; size: number; sha256: string; content: string }
type EZPatch = { filename: string; version: number; size: number; sha256: string; contentVersion: string; updatedAt: string }
type TableData = Profile | Leaderboard

const features = tableFeatures({})
const profileHelper = createColumnHelper<typeof features, Profile>()
const boardHelper = createColumnHelper<typeof features, Leaderboard>()
const emptyProfiles: Profile[] = []
const emptyLeaderboard: Leaderboard[] = []
const playlistMaxSize = 0x20000
const profileSize = 8192
const playerdataDefinition = parseDefinition(playerdataSource)

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/admin/api/v1${path}`, init)
  if (!response.ok) throw new Error((await response.text()).trim())
  return response.json()
}

async function uploadEZPatch(file: File, version?: string): Promise<EZPatch> {
  const suffix = version ? `?version=${encodeURIComponent(version)}` : ''
  return api<EZPatch>(`/ezpatch${suffix}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: file })
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
  const [draft, setDraft] = useState<Uint8Array>()
  const [filter, setFilter] = useState('')
  const [message, setMessage] = useState('')
  const source = query.data ? base64ToBytes(query.data.data) : undefined
  const content = draft ?? source
  const parsed = content ? parseProfile(content, playerdataDefinition) : undefined
  const fields = parsed?.fields.filter(field => field.path.toLowerCase().includes(filter.toLowerCase())) ?? []
  const dirty = draft !== undefined
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
    setDraft(data)
    setMessage('')
  }
  const changeField = (field: ProfileField, value: number | boolean | string) => {
    if (!content) return
    setDraft(updateProfile(content, field, value))
    setMessage('')
  }
  if (query.isLoading) return <section className="panel"><div className="empty">Loading profile</div></section>
  if (query.isError || !query.data || !content || !parsed) return <section className="panel"><div className="empty error-text">{query.error?.message ?? 'Profile not found'}</div></section>
  return <section className="panel editor-panel">
    <div className="editor-heading"><div><Link className="back-link" to="/profiles">← Profiles</Link><h2>Profile {fileId}</h2><p>Owner {query.data.ownerId} · fields decoded from playerdata.def</p></div><div className="editor-actions"><a className="button-link secondary" href={`/admin/api/v1/profiles/${fileId}/download`}>Download</a><label className="button-link secondary">Upload<input type="file" hidden onChange={upload} /></label><button type="button" className="danger" onClick={() => { if (window.confirm(`Delete profile ${fileId}?`)) remove.mutate() }} disabled={remove.isPending}>Delete</button><button type="button" className="secondary" onClick={() => { setDraft(undefined); setMessage('') }} disabled={!dirty || mutation.isPending}>Discard</button><button type="button" onClick={() => mutation.mutate(content)} disabled={!dirty || mutation.isPending}>{mutation.isPending ? 'Saving…' : 'Save profile'}</button></div></div>
    {message && <p className={`notice ${mutation.isError || remove.isError ? 'error' : 'success'}`}>{message}</p>}
    <div className="profile-summary"><span className={parsed.checksumValid ? 'success-text' : 'error-text'}>{parsed.checksumValid ? 'CRC32 valid' : 'CRC32 invalid'}</span><span>Definition: {parsed.definitionSize.toLocaleString()} bytes</span><span>{parsed.fields.length.toLocaleString()} editable values</span></div>
    <input className="field-filter" type="search" placeholder="Filter fields, e.g. prestige or customClasses" value={filter} onChange={event => setFilter(event.target.value)} />
    <div className="profile-fields">{fields.map(field => <ProfileFieldEditor key={field.path} field={field} onChange={value => changeField(field, value)} />)}</div>
    {!fields.length && <div className="empty">No fields match this filter</div>}
    <div className="editor-meta"><span className={dirty ? 'dirty' : ''}>{dirty ? 'Unsaved changes' : 'Saved'}</span><span>{content.length} / {profileSize} bytes</span><span className="hash">{query.data.sha256}</span></div>
  </section>
}

function ProfileFieldEditor({ field, onChange }: { field: ProfileField; onChange: (value: number | boolean | string) => void }) {
  const input = field.kind === 'bool'
    ? <input type="checkbox" checked={Boolean(field.value)} onChange={event => onChange(event.target.checked)} />
    : field.kind === 'enum'
      ? <select value={Number(field.value)} onChange={event => onChange(Number(event.target.value))}>{field.options?.map((option, index) => <option key={`${option}-${index}`} value={index}>{option || `(empty ${index})`}</option>)}</select>
      : field.kind === 'string'
        ? <input type="text" maxLength={Math.max(0, (field.length ?? 1) - 1)} value={String(field.value)} onChange={event => onChange(event.target.value)} />
        : <input type="number" value={Number(field.value)} min={field.kind === 'byte' ? 0 : undefined} max={field.kind === 'byte' ? 255 : field.kind === 'short' ? 65535 : undefined} onChange={event => onChange(Number(event.target.value))} />
  return <label className="profile-field"><span>{field.path}</span>{input}<small>{field.kind} · {field.offsetBits % 8 ? `bit ${field.offsetBits}` : `byte ${field.offsetBits / 8}`}</small></label>
}

function base64ToBytes(value: string) {
  const binary = atob(value)
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}

function Leaderboards() {
  const query = useQuery({ queryKey: ['leaderboards'], queryFn: () => api<{ rows: Leaderboard[] }>('/leaderboards?boardId=1') })
  const table = useTable({ features, data: query.data?.rows ?? emptyLeaderboard, columns: boardHelper.columns([
    boardHelper.accessor('rank', { header: 'Rank' }), boardHelper.accessor('name', { header: 'Player' }),
    boardHelper.accessor('entityId', { header: 'Entity ID' }), boardHelper.accessor('rating', { header: 'Rating' }),
  ]) })
  return <DataTable title="Leaderboard · Board 1" table={table} empty="No leaderboard rows" />
}

function EZPatchEditor() {
  const queryClient = useQueryClient()
  const input = useRef<HTMLInputElement>(null)
  const query = useQuery({ queryKey: ['ezpatch'], queryFn: () => api<EZPatch>('/ezpatch') })
  const [file, setFile] = useState<File>()
  const [version, setVersion] = useState('')
  const [message, setMessage] = useState('')
  const mutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error('Choose an ez_common_mp.ff file')
      return uploadEZPatch(file, version.trim() || undefined)
    },
    onSuccess: data => {
      queryClient.setQueryData(['ezpatch'], data)
      setFile(undefined)
      setVersion('')
      if (input.current) input.current.value = ''
      setMessage(`EZ Patch saved as version ${data.version}. New downloads will use it immediately.`)
    },
    onError: error => setMessage(error instanceof Error ? error.message : 'Upload failed'),
  })
  const info = query.data
  return <div className="stack"><section className="panel"><div className="editor-heading"><div><h2>EZ Patch</h2><p>Upload a PS3 MW2 format-269 ez_common_mp.ff. The CBO is generated automatically.</p></div><a className="button-link" href="/admin/api/v1/ezpatch/download">Download current FF</a></div><dl>
    <div><dt>Patch version</dt><dd>{info?.version ?? 'loading'}</dd></div><div><dt>Fastfile</dt><dd>{info?.filename ?? 'loading'}</dd></div>
    <div><dt>Size</dt><dd>{info?.size.toLocaleString() ?? 0} bytes</dd></div><div><dt>Content version</dt><dd>{info?.contentVersion ?? 'loading'}</dd></div>
    <div><dt>Updated</dt><dd>{info ? new Date(info.updatedAt).toLocaleString() : 'loading'}</dd></div><div><dt>SHA-256</dt><dd className="hash">{info?.sha256 ?? 'loading'}</dd></div>
  </dl></section><section className="panel"><h2>Replace fastfile</h2><div className="upload-grid"><label>Fastfile<input ref={input} type="file" accept=".ff,application/octet-stream" onChange={event => { setFile(event.target.files?.[0]); setMessage('') }} /></label><label>Version override<input type="number" min="1" max="4294967295" placeholder={`Auto: ${(info?.version ?? 0) + 1}`} value={version} onChange={event => setVersion(event.target.value)} /></label></div><p className="hint">Leave version blank to increment automatically. The upload becomes active atomically without restarting the server.</p><div className="editor-actions"><button disabled={!file || mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Uploading…' : 'Upload and activate'}</button></div>{file && <p className="message">Selected: {file.name} · {file.size.toLocaleString()} bytes</p>}{message && <p className="message">{message}</p>}</section></div>
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
    <NavLink to="/">Overview</NavLink><NavLink to="/playlist">Playlist</NavLink><NavLink to="/ezpatch">EZ Patch</NavLink><NavLink to="/profiles">Profiles</NavLink><NavLink to="/leaderboards">Leaderboards</NavLink>
  </nav></aside><main><header><div><p>DEMONWARE EMULATOR</p><h1>Operations Console</h1></div><span className="live">LIVE</span></header><Routes><Route path="/" element={<Overview />} /><Route path="/playlist" element={<PlaylistEditor />} /><Route path="/ezpatch" element={<EZPatchEditor />} /><Route path="/profiles" element={<Profiles />} /><Route path="/profiles/:fileId" element={<ProfileEditor />} /><Route path="/leaderboards" element={<Leaderboards />} /></Routes></main></div>
}

export default App
