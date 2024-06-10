import { Layout } from 'components/layout'
import { ExplorerPage } from 'pages/explorer'
import { FundAddressPage } from 'pages/fund'
import { ManagePage } from 'pages/manage'
import {
  createBrowserRouter,
  createRoutesFromElements,
  Route,
} from 'react-router-dom'

const routes = createRoutesFromElements(
  <Route path="/" element={<Layout />}>
    {/* Step 1 */}
    <Route path="fund" element={<FundAddressPage />} />
    {/* Step 2 */}
    <Route path="manage" element={<ManagePage />} />
    {/* Step 3 */}
    <Route path="explorer" element={<ExplorerPage />} />
  </Route>,
)

export const router = createBrowserRouter(routes)
