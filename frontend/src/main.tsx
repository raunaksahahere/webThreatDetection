import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/archivo/standard.css';
import '@fontsource/atkinson-hyperlegible-next/400.css';
import '@fontsource/atkinson-hyperlegible-next/700.css';
import '@fontsource-variable/jetbrains-mono/index.css';
import './styles/global.css';
import './styles/report.css';
import { App } from './App';
import { applyStoredTheme } from './components/Header';

applyStoredTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
