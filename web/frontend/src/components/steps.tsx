import { useLocation } from 'react-router-dom'

export const Steps = function () {
  const { pathname } = useLocation()
  if (pathname.endsWith('manage')) {
    return <span className="text-center">Manage private key</span>
  }
  if (pathname.endsWith('fund')) {
    return <span className="text-center">Fund address</span>
  }
  return null
}
