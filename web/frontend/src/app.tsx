import { RouterProvider } from 'react-router-dom'

import './styles/index.css'
import { router } from './router'

export const App = () => <RouterProvider router={router} />
