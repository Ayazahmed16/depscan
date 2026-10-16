import { lazy, StrictMode, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import './index.css'

// Each route is its own chunk, so the landing page's Archivo font and styles
// never load inside the console, and the console's chart code never loads on the landing page.
const Landing = lazy(() => import('./landing/Landing'))
const ConsoleApp = lazy(() => import('./console/ConsoleApp'))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/app" element={<ConsoleApp />} />
          <Route path="*" element={<Landing />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  </StrictMode>,
)
