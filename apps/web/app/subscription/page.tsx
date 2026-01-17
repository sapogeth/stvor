'use client';
import { useState, useEffect } from 'react';
import { useUser } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

type Tab = 'plan' | 'usage' | 'billing' | 'api';

export default function SubscriptionPage() {
  const { isSignedIn, isLoaded } = useUser();
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<Tab>('plan');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<any>(null);
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    if (isLoaded && !isSignedIn) router.push('/sign-in');
  }, [isLoaded, isSignedIn, router]);

  useEffect(() => {
    const load = async () => {
      if (!isSignedIn) return;
      setLoading(true);
      setError(null);
      try {
        const res = await fetch('/api/subscription/data');
        if (!res.ok) throw new Error('Failed to load');
        const json = await res.json();
        setData(json);
      } catch (e: any) {
        setError(e.message || 'Unknown error');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [isSignedIn]);

  const genKey = async () => {
    setGenerating(true);
    try {
      const res = await fetch('/api/subscription/generate-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'API Key ' + new Date().toLocaleDateString() })
      });
      if (!res.ok) throw new Error('Failed to generate');
      const key = await res.json();
      setApiKeys([...apiKeys, key]);
    } catch (e: any) {
      setError(e.message || 'Unknown error');
    } finally {
      setGenerating(false);
    }
  };

  if (!isLoaded) return <div className="min-h-screen flex items-center justify-center bg-black"><span className="text-white">Loading...</span></div>;
  if (!isSignedIn) return null;

  return (
    <main className="min-h-screen flex flex-col bg-black text-white">
      {/* Header */}
      <div className="bg-black border-b border-green-900 shadow-sm p-4 flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Link href="/chat" className="text-green-500 hover:text-green-400 text-sm font-medium">← Back to Chat</Link>
          <div>
            <div className="font-semibold">Subscription & API</div>
            <div className="text-xs text-green-500">Manage your plan, usage, billing, and API keys</div>
          </div>
        </div>
      </div>

      <div className="flex-1 p-8">
        <div className="max-w-4xl mx-auto">
          {error && (
            <div className="mb-6 p-4 bg-red-900/30 border border-red-700 text-red-400 rounded-lg">{error}</div>
          )}

          <div className="bg-black border-2 border-green-900 rounded-lg overflow-hidden mb-8">
            <div className="flex border-b border-green-900">
              <button onClick={() => setActiveTab('plan')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'plan' ? 'text-green-500 border-b-2 border-green-500 bg-green-900/10' : 'text-gray-400 hover:text-green-500 hover:bg-green-900/5')}>Plan</button>
              <button onClick={() => setActiveTab('usage')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'usage' ? 'text-green-500 border-b-2 border-green-500 bg-green-900/10' : 'text-gray-400 hover:text-green-500 hover:bg-green-900/5')}>Usage</button>
              <button onClick={() => setActiveTab('billing')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'billing' ? 'text-green-500 border-b-2 border-green-500 bg-green-900/10' : 'text-gray-400 hover:text-green-500 hover:bg-green-900/5')}>Billing</button>
              <button onClick={() => setActiveTab('api')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'api' ? 'text-green-500 border-b-2 border-green-500 bg-green-900/10' : 'text-gray-400 hover:text-green-500 hover:bg-green-900/5')}>API Keys</button>
            </div>

          <div className="p-8">
            {loading ? (
              <div className="text-center py-8">
                <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-green-500"></div>
                <p className="mt-4 text-gray-400">Loading subscription data...</p>
              </div>
            ) : (
              <>
                {activeTab === 'plan' && data && (
                  <div className="p-8">
                    <h2 className="text-2xl font-bold mb-6 text-white">Your Current Plan</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-black border-2 border-green-900 p-6 rounded-lg">
                        <h3 className="font-semibold text-green-500 mb-2 capitalize">{data.subscription.plan} Plan</h3>
                        <p className="text-sm text-gray-400">Status: {data.subscription.status}</p>
                        <p className="text-sm text-gray-400">Renews: {new Date(data.subscription.currentPeriodEnd).toLocaleDateString()}</p>
                        <p className="text-sm text-gray-400">Messages: {data.subscription.messagesUsed} / {data.subscription.messagesLimit}</p>
                        <p className="text-sm text-gray-400">Devices: {data.subscription.devicesUsed} / {data.subscription.devicesAllowed}</p>
                      </div>
                      <button className="bg-black border-2 border-green-500 hover:border-green-400 hover:bg-green-900/10 text-green-500 hover:text-green-400 font-semibold py-3 rounded-lg transition">Upgrade Plan</button>
                    </div>
                  </div>
                )}

                {activeTab === 'usage' && data && (
                  <div className="p-8">
                    <h2 className="text-2xl font-bold mb-6 text-white">Usage Statistics</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-black border-2 border-green-900 p-6 rounded-lg">
                        <h3 className="font-semibold text-gray-300 mb-3">Messages This Month</h3>
                        <div className="text-3xl font-bold text-green-500">{data.usage.messagesThisMonth}</div>
                      </div>
                      <div className="bg-black border-2 border-green-900 p-6 rounded-lg">
                        <h3 className="font-semibold text-gray-300 mb-3">Active Devices</h3>
                        <div className="text-3xl font-bold text-green-500">{data.usage.devicesActive}</div>
                      </div>
                      <div className="bg-black border-2 border-green-900 p-6 rounded-lg">
                        <h3 className="font-semibold text-gray-300 mb-3">Storage Usage</h3>
                        <div className="text-3xl font-bold text-green-500">{data.usage.storageUsedMB} MB / {data.usage.storageLimit} MB</div>
                      </div>
                      <div className="bg-black border-2 border-green-900 p-6 rounded-lg">
                        <h3 className="font-semibold text-gray-300 mb-2">Uptime</h3>
                        <p className="text-3xl font-bold text-green-500">{data.usage.uptime}</p>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'billing' && (
                  <div className="p-8">
                    <h2 className="text-2xl font-bold mb-6 text-white">Billing History</h2>
                    {data?.billing?.length ? (
                      <ul className="space-y-2">
                        {data.billing.map((b: any) => (
                          <li key={b.id} className="flex justify-between p-3 border border-green-900 rounded bg-black">
                            <span className="text-gray-300">{new Date(b.date).toLocaleDateString()}</span>
                            <span className="flex-1 mx-3 text-gray-400">{b.description}</span>
                            <span className="font-semibold text-white">${b.amount.toFixed(2)}</span>
                            <span className={"ml-3 text-xs px-3 py-1 rounded-full " + (b.status === 'paid' ? 'bg-green-900/30 text-green-400 border border-green-700' : b.status === 'pending' ? 'bg-yellow-900/30 text-yellow-400 border border-yellow-700' : 'bg-red-900/30 text-red-400 border border-red-700')}>{b.status}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-400">No billing records found.</p>
                    )}
                  </div>
                )}

                {activeTab === 'api' && (
                  <div className="p-8">
                    <div className="flex justify-between items-center mb-6">
                      <h2 className="text-2xl font-bold text-white">API Keys</h2>
                      <button onClick={genKey} disabled={generating} className="bg-black border-2 border-green-500 hover:border-green-400 hover:bg-green-900/10 disabled:border-gray-700 disabled:text-gray-600 text-green-500 hover:text-green-400 font-semibold py-2 px-4 rounded-lg transition">
                        {generating ? 'Generating...' : '+ Generate New Key'}
                      </button>
                    </div>
                    {apiKeys.length === 0 ? (
                      <div className="text-center py-8 bg-black border-2 border-green-900 rounded-lg">
                        <p className="text-gray-400 mb-4">No API keys generated yet.</p>
                        <p className="text-sm text-gray-500">Generate an API key to programmatically access the STVOR API.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {apiKeys.map((k) => (
                          <div key={k.id} className="border-2 border-green-900 rounded-lg p-4 bg-black">
                            <div className="flex justify-between items-start mb-3">
                              <div>
                                <h3 className="font-semibold text-white">{k.name}</h3>
                                <p className="text-sm text-gray-400">Created: {new Date(k.createdAt).toLocaleDateString()}</p>
                              </div>
                              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-green-900/30 text-green-400 border border-green-700">Active</span>
                            </div>
                            <div className="bg-black border border-green-900 p-3 rounded font-mono text-sm break-all mb-4 text-gray-300">{k.key}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
