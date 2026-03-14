import { Router, Route } from 'preact-router'
import { useState } from 'preact/hooks'
import { Sidebar } from '../../components/Sidebar'
import { Dashboard } from './Dashboard'
import { Streams } from './Streams'
import { Relays } from './Relays'
import { Transcoders } from './Transcoders'
import { Users } from './Users'
import { Security } from './Security'
import { Settings } from './Settings'
import { AutoDJ } from './AutoDJ'
import { Studio } from './Studio'

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

const GoLivePage = Placeholder('Go Live')

export function AdminLayout() {
  const [path, setPath] = useState(window.location.pathname)

  return (
    <div class="flex h-screen overflow-hidden">
      <Sidebar activePath={path} />
      <main class="flex-1 overflow-y-auto ml-16">
        <Router onChange={(e) => setPath(e.url)}>
          <Route path="/admin" component={Dashboard} />
          <Route path="/admin/streams" component={Streams} />
          <Route path="/admin/autodj" component={AutoDJ} />
          <Route path="/admin/golive" component={GoLivePage} />
          <Route path="/admin/relays" component={Relays} />
          <Route path="/admin/transcoders" component={Transcoders} />
          <Route path="/admin/studio" component={Studio} />
          <Route path="/admin/users" component={Users} />
          <Route path="/admin/security" component={Security} />
          <Route path="/admin/settings" component={Settings} />
        </Router>
      </main>
    </div>
  )
}
