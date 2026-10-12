import { createRoot } from 'react-dom/client';
import { App } from './App';
import { captureInvite } from './lib/invite';
import './explorer.css';

// An invitation link is taken out of the address bar before anything else
// runs, so signing in (which may take a QR scan) does not lose it.
captureInvite();

createRoot(document.getElementById('root')!).render(<App />);
