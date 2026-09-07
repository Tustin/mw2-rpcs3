import { useQuery } from '@tanstack/react-query'
import { createColumnHelper, tableFeatures, type ReactTable, useTable } from '@tanstack/react-table'
import { NavLink, Route, Routes } from 'react-router-dom'

type Status = { status: string; uptimeSeconds: number; metrics: Record<string, number> }
type Profile = { ownerId: number; fileId: number; filename: string; size: number }
type Leaderboard = { boardId: number; entityId: number; rating: number; rank: number; name: string; columns: number[] }
type Playlist = { filename: string; size: number; sha256: string }
type TableData = Profile | Leaderboard

const features = tableFeatures({})
const profileHelper = createColumnHelper<typeof features, Profile>()
const boardHelper = createColumnHelper<typeof features, Leaderboard>()
const emptyProfiles: Profile[] = []
const emptyLeaderboard: Leaderboard[] = []

async function api<T>(path: string): Promise<T> {
  const response = await fetch(`/admin/api/v1${path}`)
  if (!response.ok) throw new Error(await response.text())
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
  const query = useQuery({ queryKey: ['profiles'], queryFn: () => api<{ profiles: Profile[] }>('/profiles') })
  const table = useTable({ features, data: query.data?.profiles ?? emptyProfiles, columns: profileHelper.columns([
    profileHelper.accessor('ownerId', { header: 'Owner ID' }),
    profileHelper.accessor('fileId', { header: 'File ID' }),
    profileHelper.accessor('filename', { header: 'Filename' }),
    profileHelper.accessor('size', { header: 'Bytes' }),
  ]) })
  return <DataTable title="Profiles" table={table} empty="No stored profiles" />
}

function Leaderboards() {
  const query = useQuery({ queryKey: ['leaderboards'], queryFn: () => api<{ rows: Leaderboard[] }>('/leaderboards?boardId=1') })
  const table = useTable({ features, data: query.data?.rows ?? emptyLeaderboard, columns: boardHelper.columns([
    boardHelper.accessor('rank', { header: 'Rank' }), boardHelper.accessor('name', { header: 'Player' }),
    boardHelper.accessor('entityId', { header: 'Entity ID' }), boardHelper.accessor('rating', { header: 'Rating' }),
  ]) })
  return <DataTable title="Leaderboard · Board 1" table={table} empty="No leaderboard rows" />
}

function DataTable<T extends TableData>({ title, table, empty }: { title: string; table: ReactTable<typeof features, T>; empty: string }) {
  return <section className="panel table-panel"><h2>{title}</h2><div className="table-wrap"><table><thead>{table.getHeaderGroups().map(group => <tr key={group.id}>{group.headers.map(header => <th key={header.id}>{header.isPlaceholder ? null : <table.FlexRender header={header} />}</th>)}</tr>)}</thead><tbody>{table.getRowModel().rows.map(row => <tr key={row.id}>{row.getAllCells().map(cell => <td key={cell.id}><table.FlexRender cell={cell} /></td>)}</tr>)}</tbody></table>{table.getRowModel().rows.length === 0 && <div className="empty">{empty}</div>}</div></section>
}

function App() {
  return <div className="shell"><aside><div className="brand"><span>IW4</span><div>MW2<br/><small>operations</small></div></div><nav>
    <NavLink to="/">Overview</NavLink><NavLink to="/profiles">Profiles</NavLink><NavLink to="/leaderboards">Leaderboards</NavLink>
  </nav><div className="access">Protected by<br/><strong>Cloudflare Access</strong></div></aside><main><header><div><p>DEMONWARE EMULATOR</p><h1>Operations Console</h1></div><span className="live">LIVE</span></header><Routes><Route path="/" element={<Overview />} /><Route path="/profiles" element={<Profiles />} /><Route path="/leaderboards" element={<Leaderboards />} /></Routes></main></div>
}

export default App
