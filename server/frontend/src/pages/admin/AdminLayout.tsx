import { Router, Route } from 'preact-router'
import { useState } from 'preact/hooks'
import { Sidebar } from '../../components/Sidebar'
import { Dashboard } from './Dashboard'

function Placeholder(name: string) {
  return function Page() {
    return (
      <div class="p-7">
        <div class="font-mono text-[10px] tracking-[2px] text-text-tertiary mb-1">{name.toUpperCase()}</div>
        <h1 class="text-xl font-bold text-text-primary">{name}</h1>
        <p class="text-text-tertiary mt-2 text-sm">Coming soon...</p>
      </div>
    )
  }
}

const StreamsPage = Placeholder('Streams')
const AutoDJPage = Placeholder('AutoDJ')
const GoLivePage = Placeholder('Go Live')
const RelaysPage = Placeholder('Relays')
const TranscodersPage = Placeholder('Transcoders')
const StudioPage = Placeholder('Studio')
const UsersPage = Placeholder('Users')
const SecurityPage = Placeholder('Security')
const SettingsPage = Placeholder('Settings')

export function AdminLayout() {
  const [path, setPath] = useState(window.location.pathname)

  return (
    <div class="flex h-screen overflow-hidden">
      <Sidebar activePath={path} />
      <main class="flex-1 overflow-y-auto ml-16">
        <Router onChange={(e) => setPath(e.url)}>
          <Route path="/admin" component={Dashboard} />
          <Route path="/admin/streams" component={StreamsPage} />
          <Route path="/admin/autodj" component={AutoDJPage} />
          <Route path="/admin/golive" component={GoLivePage} />
          <Route path="/admin/relays" component={RelaysPage} />
          <Route path="/admin/transcoders" component={TranscodersPage} />
          <Route path="/admin/studio" component={StudioPage} />
          <Route path="/admin/users" component={UsersPage} />
          <Route path="/admin/security" component={SecurityPage} />
          <Route path="/admin/settings" component={SettingsPage} />
        </Router>
      </main>
    </div>
  )
}
