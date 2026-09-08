import { Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import DashboardOverview from './pages/DashboardOverview'
import LiveSimulator from './pages/LiveSimulator'
import DurableSpoolView from './pages/DurableSpoolView'
import ParserRegistry from './pages/ParserRegistry'
import OcsfEventsView from './pages/OcsfEventsView'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardOverview />} />
        <Route path="/ingest" element={<LiveSimulator />} />
        <Route path="/spool" element={<DurableSpoolView />} />
        <Route path="/registry" element={<ParserRegistry />} />
        <Route path="/events" element={<OcsfEventsView />} />
      </Routes>
    </Layout>
  )
}
