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
import { GoLive } from './GoLive'

export function AdminLayout() {
  const [path, setPath] = useState(window.location.pathname)

  return (
    <div class="flex h-screen overflow-hidden">
      <Sidebar activePath={path} />
      <main class="flex-1 overflow-y-auto ml-[72px]">
        <Router onChange={(e) => setPath(e.url)}>
          <Route path="/admin" component={Dashboard} />
          <Route path="/admin/streams" component={Streams} />
          <Route path="/admin/autodj" component={AutoDJ} />
          <Route path="/admin/golive" component={GoLive} />
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
