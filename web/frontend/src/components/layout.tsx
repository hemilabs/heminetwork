import { Outlet, useLocation, useNavigate } from 'react-router-dom'

import { Footer } from './footer'
import { Header } from './header'
import { useEffect } from 'react'

export const Layout = function () {
  const { pathname } = useLocation()
  const navigate = useNavigate()

  useEffect(
    function redirectToFirstStep() {
      if (pathname === '/') {
        navigate('/manage')
      }
    },
    [navigate, pathname],
  )

  return (
    <div className="flex h-screen w-full flex-col justify-between px-16 py-8 2xl:mx-auto 2xl:max-w-screen-2xl">
      <Header />
      <Outlet />
      <Footer />
    </div>
  )
}
