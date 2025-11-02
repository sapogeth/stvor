'use client';

import { useState } from 'react';
import { getRelayUrl } from '@/lib/relay-url';

export default function TestRelayPage() {
  const [result, setResult] = useState<string>('');
  const [relayUrl, setRelayUrl] = useState<string>('');

  const testConnection = async () => {
    try {
      const url = getRelayUrl();
      setRelayUrl(url);
      setResult(`Testing connection to: ${url}`);

      const response = await fetch(`${url}/directory/test`);
      const data = await response.json();

      setResult(`Success! Status: ${response.status}, Data: ${JSON.stringify(data)}`);
    } catch (error) {
      setResult(`Error: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'monospace' }}>
      <h1>Test Relay Connection</h1>
      <button
        onClick={testConnection}
        style={{
          padding: '10px 20px',
          fontSize: '16px',
          cursor: 'pointer',
          marginBottom: '20px',
        }}
      >
        Test Connection
      </button>

      <div>
        <h2>Relay URL:</h2>
        <pre>{relayUrl || 'Not tested yet'}</pre>
      </div>

      <div>
        <h2>Result:</h2>
        <pre style={{ whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>
          {result || 'Click button to test'}
        </pre>
      </div>

      <div style={{ marginTop: '20px', padding: '10px', background: '#f0f0f0' }}>
        <h3>Instructions:</h3>
        <ol>
          <li>Make sure relay server is running on port 3001</li>
          <li>Click "Test Connection" button</li>
          <li>Check browser console for any errors</li>
          <li>Check browser DevTools → Network tab for request details</li>
        </ol>
      </div>
    </div>
  );
}
