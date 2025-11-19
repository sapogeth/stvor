'use client';

import { useState } from 'react';
import { DefenseInDepthExample } from '@/components/DefenseInDepthExample';

export default function SecurityPage() {
  const [activeTab, setActiveTab] = useState<'overview' | 'e2e' | 'defense' | 'test' | 'docs'>('overview');
  const [username, setUsername] = useState('demo-user');
  const [recipient, setRecipient] = useState('alice');

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '20px', fontFamily: 'system-ui' }}>
      <header style={{ textAlign: 'center', marginBottom: '40px', borderBottom: '2px solid #007bff', paddingBottom: '20px' }}>
        <h1 style={{ fontSize: '2.5em', margin: '10px 0' }}>🔐 Security Center</h1>
        <p style={{ fontSize: '1.1em', color: '#666' }}>Stvor Messenger - Complete Security Architecture</p>
        <p style={{ fontSize: '0.95em', color: '#999' }}>End-to-End Encryption + Defense-in-Depth</p>
      </header>

      <nav style={{ display: 'flex', gap: '10px', marginBottom: '30px', borderBottom: '1px solid #ddd', flexWrap: 'wrap' }}>
        {['overview', 'e2e', 'defense', 'test', 'docs'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            style={{
              padding: '12px 24px',
              border: 'none',
              background: activeTab === tab ? '#007bff' : '#f0f0f0',
              color: activeTab === tab ? 'white' : '#000',
              cursor: 'pointer',
              fontSize: '0.95em',
              borderRadius: '4px 4px 0 0',
              fontWeight: activeTab === tab ? 'bold' : 'normal',
            }}
          >
            {tab === 'e2e' ? 'E2E' : tab === 'defense' ? 'Defense' : tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </nav>

      <main>
        {/* OVERVIEW TAB */}
        {activeTab === 'overview' && (
          <section>
            <h2>Complete Security Architecture</h2>
            <p style={{ fontSize: '1.05em', lineHeight: '1.6', color: '#444', marginBottom: '30px' }}>
              Stvor implements a <strong>two-layer security model</strong>: industry-standard E2E encryption + 
              advanced Defense-in-Depth mechanisms from peer-reviewed KAIST research.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '40px' }}>
              {/* E2E Layer */}
              <div style={{ border: '3px solid #28a745', borderRadius: '8px', padding: '20px', background: '#f0fff4' }}>
                <h3 style={{ fontSize: '1.3em', color: '#28a745', marginBottom: '10px' }}>🔒 Layer 1: End-to-End Encryption</h3>
                <p style={{ fontWeight: 'bold', color: '#333', marginBottom: '10px' }}>Industry Standard</p>
                <ul style={{ paddingLeft: '20px', fontSize: '0.95em', lineHeight: '1.8' }}>
                  <li>✅ <strong>Double Ratchet Protocol</strong> - Forward & Backward Secrecy</li>
                  <li>✅ <strong>Post-Quantum Hybrid</strong> - ML-KEM-768 + X25519</li>
                  <li>✅ <strong>AES-256-GCM</strong> - 256-bit symmetric encryption</li>
                  <li>✅ <strong>Ed25519 + ML-DSA-65</strong> - Digital signatures</li>
                  <li>✅ <strong>HKDF-SHA-384</strong> - Key derivation</li>
                  <li>✅ <strong>Session Management</strong> - IndexedDB persistence</li>
                </ul>
                <p style={{ fontSize: '0.85em', color: '#666', marginTop: '10px' }}>
                  <strong>Protects:</strong> Message content encryption, Forward secrecy, Post-quantum attacks
                </p>
              </div>

              {/* Defense-in-Depth Layer */}
              <div style={{ border: '3px solid #007bff', borderRadius: '8px', padding: '20px', background: '#f0f7ff' }}>
                <h3 style={{ fontSize: '1.3em', color: '#007bff', marginBottom: '10px' }}>🛡️ Layer 2: Defense-in-Depth</h3>
                <p style={{ fontWeight: 'bold', color: '#333', marginBottom: '10px' }}>Research-Based (KAIST)</p>
                <ul style={{ paddingLeft: '20px', fontSize: '0.95em', lineHeight: '1.8' }}>
                  <li>✅ <strong>Network Integrity</strong> - EREBUS relay pinning</li>
                  <li>✅ <strong>Metadata Obfuscation</strong> - Message padding</li>
                  <li>✅ <strong>Behavior Privacy</strong> - Typing/read receipt protection</li>
                  <li>✅ <strong>Traffic Analysis</strong> - Jitter & batching</li>
                  <li>✅ <strong>Side-Channel</strong> - Opt-in controls</li>
                  <li>✅ <strong>User Consent</strong> - Privacy enforcement</li>
                </ul>
                <p style={{ fontSize: '0.85em', color: '#666', marginTop: '10px' }}>
                  <strong>Protects:</strong> Network attacks, Traffic patterns, Behavior inference
                </p>
              </div>
            </div>

            <div style={{ background: '#fff3cd', border: '1px solid #ffc107', borderRadius: '8px', padding: '20px', marginBottom: '30px' }}>
              <p style={{ margin: '0', fontSize: '0.95em', lineHeight: '1.6' }}>
                <strong>🎯 Why Two Layers?</strong> E2E encryption protects message <em>content</em>. 
                Defense-in-Depth protects <em>metadata</em> (size, timing, behavior patterns) that attackers can observe 
                even with perfect encryption. Together they provide comprehensive protection against:
              </p>
              <ul style={{ paddingLeft: '20px', marginTop: '10px', fontSize: '0.95em' }}>
                <li>Network-level attackers (ASes, ISPs, relay operators)</li>
                <li>Traffic analysis attacks (packet size classification)</li>
                <li>User behavior inference (keystroke timing, presence)</li>
                <li>Cryptographic protocol attacks (EREBUS partitioning)</li>
              </ul>
            </div>
          </section>
        )}

        {/* E2E TAB */}
        {activeTab === 'e2e' && (
          <section>
            <h2>🔒 End-to-End Encryption (Layer 1)</h2>
            
            <h3 style={{ marginTop: '30px' }}>Double Ratchet Protocol</h3>
            <p>Implements Signal/WhatsApp encryption standard with forward & backward secrecy:</p>
            <ul style={{ paddingLeft: '20px' }}>
              <li><strong>Send Ratchet:</strong> Advances on every message send</li>
              <li><strong>Receive Ratchet:</strong> Advances on every message receive</li>
              <li><strong>DH Ratchet:</strong> Periodic key exchange for perfect forward secrecy</li>
              <li><strong>Symmetric Ratchet:</strong> AES-256-GCM for message encryption</li>
            </ul>

            <h3 style={{ marginTop: '30px' }}>Post-Quantum Hybrid Cryptography</h3>
            <p>Prepared for quantum computers while maintaining backward compatibility:</p>
            <div style={{ background: '#f9f9f9', padding: '15px', borderRadius: '4px', marginTop: '10px' }}>
              <p style={{ margin: '0 0 10px 0' }}><strong>Key Exchange:</strong></p>
              <ul style={{ margin: '0 0 15px 0', paddingLeft: '20px' }}>
                <li>Classical: X25519 (Elliptic Curve)</li>
                <li>Post-Quantum: ML-KEM-768 (NIST Standard)</li>
              </ul>
              <p style={{ margin: '0 0 10px 0' }}><strong>Digital Signatures:</strong></p>
              <ul style={{ margin: '0', paddingLeft: '20px' }}>
                <li>Classical: Ed25519 (Twisted Edwards Curve)</li>
                <li>Post-Quantum: ML-DSA-65 (NIST Standard)</li>
              </ul>
            </div>

            <h3 style={{ marginTop: '30px' }}>Message Encryption</h3>
            <ul style={{ paddingLeft: '20px' }}>
              <li><strong>Algorithm:</strong> AES-256-GCM (Advanced Encryption Standard)</li>
              <li><strong>Key Size:</strong> 256 bits</li>
              <li><strong>Mode:</strong> Galois/Counter Mode (authenticated encryption)</li>
              <li><strong>Authentication:</strong> Built-in message authentication (GMAC)</li>
              <li><strong>AAD:</strong> Session ID included in authentication data</li>
            </ul>

            <h3 style={{ marginTop: '30px' }}>Key Derivation</h3>
            <ul style={{ paddingLeft: '20px' }}>
              <li><strong>Function:</strong> HKDF-SHA-384 (HMAC-based Key Derivation Function)</li>
              <li><strong>Hash:</strong> SHA-384 (384-bit output)</li>
              <li><strong>Extract-then-Expand:</strong> Two-stage design for security</li>
            </ul>

            <h3 style={{ marginTop: '30px' }}>Session Management</h3>
            <ul style={{ paddingLeft: '20px' }}>
              <li>✅ IndexedDB persistence (client-side only)</li>
              <li>✅ Session health monitoring (age, message counts)</li>
              <li>✅ Automatic key rotation</li>
              <li>✅ Replay protection with nonce deduplication</li>
              <li>✅ Session refresh on integrity mismatches</li>
            </ul>
          </section>
        )}

        {/* DEFENSE-IN-DEPTH TAB */}
        {activeTab === 'defense' && (
          <section>
            <h2>🛡️ Defense-in-Depth Security (Layer 2)</h2>
            <p style={{ fontSize: '1.05em', lineHeight: '1.6', color: '#444', marginBottom: '30px' }}>
              Three orthogonal security mechanisms from KAIST NetS&P Lab research papers
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '20px', marginBottom: '40px' }}>
              {/* Mechanism 1 */}
              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3 style={{ fontSize: '1.3em', color: '#007bff', marginBottom: '10px' }}>🌐 Network Layer</h3>
                <h4>RelayPinner - Network Integrity Verification</h4>
                <p style={{ color: '#d9534f', fontWeight: 'bold' }}>Problem:</p>
                <p>Autonomous Systems (ASes) can perform network-level attacks to hijack relay server connections without routing manipulation.</p>
                <p style={{ color: '#5cb85c', fontWeight: 'bold', marginTop: '10px' }}>Solution:</p>
                <p>Ed25519-signed relay identity verification using challenge-response protocol.</p>
                <div style={{ background: '#fff', padding: '10px', borderRadius: '4px', marginBottom: '10px', fontSize: '0.9em' }}>
                  <ul style={{ margin: '0', paddingLeft: '20px' }}>
                    <li>✅ Proves relay authenticity</li>
                    <li>✅ Nonce-based challenge-response</li>
                    <li>✅ Backup relay failover</li>
                    <li>✅ 60-second verification cache</li>
                  </ul>
                </div>
                <p style={{ fontSize: '0.85em', color: '#666', marginTop: '10px' }}>
                  <strong>Research:</strong> EREBUS (Tran et al., 2020 IEEE S&P)
                </p>
              </div>

              {/* Mechanism 2 */}
              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3 style={{ fontSize: '1.3em', color: '#5cb85c', marginBottom: '10px' }}>📦 Transport Layer</h3>
                <h4>Message Padding - Traffic Analysis Resistance</h4>
                <p style={{ color: '#d9534f', fontWeight: 'bold' }}>Problem:</p>
                <p>Message size distribution reveals content information even when encrypted.</p>
                <p style={{ color: '#5cb85c', fontWeight: 'bold', marginTop: '10px' }}>Solution:</p>
                <p>Adaptive message padding to fixed block sizes (256, 512, or 1024 bytes).</p>
                <div style={{ background: '#fff', padding: '10px', borderRadius: '4px', marginBottom: '10px', fontSize: '0.9em' }}>
                  <ul style={{ margin: '0', paddingLeft: '20px' }}>
                    <li>✅ Hides message length</li>
                    <li>✅ 256/512/1024 byte blocks</li>
                    <li>✅ Random padding bytes</li>
                    <li>✅ Configurable jitter (±10%)</li>
                  </ul>
                </div>
                <p style={{ fontSize: '0.85em', color: '#666', marginTop: '10px' }}>
                  <strong>Research:</strong> DNS-over-HTTPS Privacy (Csikor et al., 2021 IEEE EuroS&P)
                </p>
              </div>

              {/* Mechanism 3 */}
              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3 style={{ fontSize: '1.3em', color: '#f0ad4e', marginBottom: '10px' }}>👤 Application Layer</h3>
                <h4>PrivacyConfigManager - Side-Channel Privacy</h4>
                <p style={{ color: '#d9534f', fontWeight: 'bold' }}>Problem:</p>
                <p>Automatic presence indicators (typing, read receipts, online status) leak user behavior patterns.</p>
                <p style={{ color: '#5cb85c', fontWeight: 'bold', marginTop: '10px' }}>Solution:</p>
                <p>Opt-in features disabled by default with timing obfuscation and event batching.</p>
                <div style={{ background: '#fff', padding: '10px', borderRadius: '4px', marginBottom: '10px', fontSize: '0.9em' }}>
                  <ul style={{ margin: '0', paddingLeft: '20px' }}>
                    <li>✅ Typing indicators (disabled by default)</li>
                    <li>✅ Read receipts (disabled by default)</li>
                    <li>✅ Online status (disabled by default)</li>
                    <li>✅ Event batching (5 per 2 sec max)</li>
                  </ul>
                </div>
                <p style={{ fontSize: '0.85em', color: '#666', marginTop: '10px' }}>
                  <strong>Research:</strong> I Know You Pin Me (Woo et al., 2024 IEEE EuroS&PW)
                </p>
              </div>
            </div>

            <div style={{ background: '#f0f0f0', padding: '20px', borderRadius: '8px' }}>
              <h3>Implementation Statistics</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '15px', marginTop: '15px' }}>
                {[
                  { label: 'Type Safety', value: '100% TypeScript' },
                  { label: 'Code Lines', value: '1,986 lines' },
                  { label: 'Dependencies', value: '0 external' },
                  { label: 'Documentation', value: '100% JSDoc' },
                  { label: 'Research Papers', value: '3 IEEE' },
                  { label: 'Test Cases', value: '35+ designed' },
                ].map((stat) => (
                  <div key={stat.label} style={{ textAlign: 'center', padding: '15px', background: 'white', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.9em', color: '#666', marginBottom: '5px' }}>{stat.label}</div>
                    <div style={{ fontSize: '1.2em', fontWeight: 'bold', color: '#007bff' }}>{stat.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* TEST TAB */}
        {activeTab === 'test' && (
          <section>
            <h2>🧪 Test Defense-in-Depth Features</h2>
            <p style={{ fontSize: '1.05em', marginBottom: '30px', color: '#666' }}>
              Interactive testing of all three security mechanisms.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '30px', padding: '20px', background: '#f9f9f9', borderRadius: '8px' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>Your Username:</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username"
                  style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px', boxSizing: 'border-box' }}
                />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>Recipient:</label>
                <input
                  type="text"
                  value={recipient}
                  onChange={(e) => setRecipient(e.target.value)}
                  placeholder="Enter recipient username"
                  style={{ width: '100%', padding: '8px', border: '1px solid #ddd', borderRadius: '4px', boxSizing: 'border-box' }}
                />
              </div>
            </div>

            <DefenseInDepthExample
              username={username}
              recipient={recipient}
              chatId={`${username}-${recipient}`.toLowerCase()}
            />
          </section>
        )}

        {/* DOCUMENTATION TAB */}
        {activeTab === 'docs' && (
          <section>
            <h2>📚 Documentation & Resources</h2>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>📖 Quick Start</h3>
                <p>New to our security architecture? Start by exploring the "Overview" and "E2E" tabs above.</p>
              </div>

              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>🔍 Complete API</h3>
                <p>Full API documentation for all security mechanisms:</p>
                <code style={{ background: '#fff', padding: '8px', display: 'block', borderRadius: '4px', overflow: 'auto', fontSize: '0.85em', marginTop: '8px' }}>
                  import {'{'}RelayPinner, padMessage{'}'} from '@ilyazh/crypto';
                </code>
              </div>

              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>📖 Integration Guide</h3>
                <p>Step-by-step integration guide for developers:</p>
                <ul style={{ paddingLeft: '20px', fontSize: '0.9em', marginTop: '8px' }}>
                  <li><code>DEFENSE_IN_DEPTH_INTEGRATION.md</code></li>
                  <li><code>apps/web/lib/defense-usage-in-chat.md</code></li>
                </ul>
              </div>

              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>📊 Research Papers</h3>
                <ul style={{ paddingLeft: '20px', fontSize: '0.9em' }}>
                  <li><strong>EREBUS</strong> - Tran et al., 2020 IEEE S&P</li>
                  <li><strong>DNS-over-HTTPS Privacy</strong> - Csikor et al., 2021 IEEE EuroS&P</li>
                  <li><strong>I Know You Pin Me</strong> - Woo et al., 2024 IEEE EuroS&PW</li>
                </ul>
              </div>

              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>⚙️ Configuration</h3>
                <code style={{ background: '#fff', padding: '12px', display: 'block', borderRadius: '4px', fontSize: '0.8em', overflow: 'auto' }}>
                  REACT_APP_RELAY_KEY_HASH=...
                  <br />REACT_APP_PADDING_ENABLED=true
                  <br />REACT_APP_PADDING_BLOCK_SIZE=256
                </code>
              </div>

              <div style={{ border: '1px solid #ddd', borderRadius: '8px', padding: '20px', background: '#f9f9f9' }}>
                <h3>📁 Source Code</h3>
                <ul style={{ paddingLeft: '20px', fontSize: '0.9em' }}>
                  <li><code>packages/crypto/src/defense-in-depth.ts</code> (824 lines)</li>
                  <li><code>apps/web/lib/defense-integration.ts</code> (523 lines)</li>
                  <li><code>apps/web/components/DefenseInDepthExample.tsx</code> (639 lines)</li>
                </ul>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer style={{ marginTop: '60px', paddingTop: '20px', borderTop: '2px solid #007bff', textAlign: 'center', color: '#666' }}>
        <p>
          🔐 Security Center - Complete Security Architecture
          <br />
          <strong>Layer 1:</strong> End-to-End Encryption (Industry Standard) 
          | <strong>Layer 2:</strong> Defense-in-Depth (KAIST Research)
          <br />
          <small>Version 1.0.0 | 2025-11-20</small>
        </p>
      </footer>
    </div>
  );
}
