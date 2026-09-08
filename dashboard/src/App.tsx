import { useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Preloader from './components/Preloader';
import Landing from './pages/Landing';
import Console from './pages/Console';

export default function App() {
  const [ready, setReady] = useState(false);
  const handleDone = useCallback(() => setReady(true), []);

  return (
    <>
      {/* 2-second preloader */}
      {!ready && <Preloader onDone={handleDone} />}

      {/* Main app — rendered underneath (avoids flash on preloader exit) */}
      <div style={{ visibility: ready ? 'visible' : 'hidden' }}>
        <BrowserRouter>
          <Navbar />
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/console" element={<Console />} />
          </Routes>
        </BrowserRouter>
      </div>
    </>
  );
}
