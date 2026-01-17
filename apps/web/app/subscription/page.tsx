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

  if (!isLoaded) return <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800"><span className="text-gray-900 dark:text-white">Loading...</span></div>;
  if (!isSignedIn) return null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800">
      <div className="max-w-4xl mx-auto p-8">
        <div className="mb-8">
          <Link href="/chat" className="text-blue-500 hover:text-blue-600 dark:text-blue-400 dark:hover:text-blue-300 mb-4 inline-block">← Back to Chat</Link>
          <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">Subscription & API</h1>
          <p className="text-gray-600 dark:text-gray-400">Manage your plan, usage, billing, and API keys</p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-100 dark:bg-red-900/30 border border-red-400 dark:border-red-500 text-red-700 dark:text-red-300 rounded-lg">{error}</div>
        )}

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl overflow-hidden mb-8">
          <div className="flex border-b border-gray-200 dark:border-gray-700">
            <button onClick={() => setActiveTab('plan')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'plan' ? 'text-blue-500 border-b-2 border-blue-500 dark:text-blue-400 dark:border-blue-400' : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200')}>Plan</button>
            <button onClick={() => setActiveTab('usage')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'usage' ? 'text-blue-500 border-b-2 border-blue-500 dark:text-blue-400 dark:border-blue-400' : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200')}>Usage</button>
            <button onClick={() => setActiveTab('billing')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'billing' ? 'text-blue-500 border-b-2 border-blue-500 dark:text-blue-400 dark:border-blue-400' : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200')}>Billing</button>
            <button onClick={() => setActiveTab('api')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'api' ? 'text-blue-500 border-b-2 border-blue-500 dark:text-blue-400 dark:border-blue-400' : 'text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200')}>API Keys</button>
          </div>

          <div className="p-8">
            {loading ? (
              <div className="text-center py-8">
                <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                <p className="mt-4 text-gray-600 dark:text-gray-400">Loading subscription data...</p>
              </div>
            ) : (
              <>
                {activeTab === 'plan' && data && (
                  <div>
                    <h2 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white">Your Current Plan</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-blue-50 dark:bg-blue-900/20 p-6 rounded-lg border border-blue-100 dark:border-blue-800">
                        <h3 className="font-semibold text-blue-900 dark:text-blue-300 mb-2 capitalize">{data.subscription.plan} Plan</h3>
                        <p className="text-sm text-blue-800 dark:text-blue-400">Status: {data.subscription.status}</p>
                        <p className="text-sm text-blue-800 dark:text-blue-400">Renews: {new Date(data.subscription.currentPeriodEnd).toLocaleDateString()}</p>
                        <p className="text-sm text-blue-800 dark:text-blue-400">Messages: {data.subscription.messagesUsed} / {data.subscription.messagesLimit}</p>
                        <p className="text-sm text-blue-800 dark:text-blue-400">Devices: {data.subscription.devicesUsed} / {data.subscription.devicesAllowed}</p>
                      </div>
                      <button className="w-full bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 text-white font-semibold py-3 rounded-lg transition">Upgrade Plan</button>
                    </div>
                  </div>
                )}

                {activeTab === 'usage' && data && (
                  <div>
                    <h2 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white">Usage Statistics</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-50 dark:bg-gray-700/50 p-6 rounded-lg border border-gray-200 dark:border-gray-600">
                        <h3 className="font-semibold text-gray-900 dark:text-gray-200 mb-3">Messages This Month</h3>
                        <div className="text-3xl font-bold text-gray-900 dark:text-white">{data.usage.messagesThisMonth}</div>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-700/50 p-6 rounded-lg border border-gray-200 dark:border-gray-600">
                        <h3 className="font-semibold text-gray-900 dark:text-gray-200 mb-3">Active Devices</h3>
                        <div className="text-3xl font-bold text-gray-900 dark:text-white">{data.usage.devicesActive}</div>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-700/50 p-6 rounded-lg border border-gray-200 dark:border-gray-600">
                        <h3 className="font-semibold text-gray-900 dark:text-gray-200 mb-3">Storage Usage</h3>
                        <div className="text-3xl font-bold text-gray-900 dark:text-white">{data.usage.storageUsedMB} MB / {data.usage.storageLimit} MB</div>
                      </div>
                      <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg border border-green-200 dark:border-green-800">
                        <h3 className="font-semibold text-green-900 dark:text-green-300 mb-2">Uptime</h3>
                        <p className="text-3xl font-bold text-green-600 dark:text-green-400">{data.usage.uptime}</p>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'billing' && (
                  <div>
                    <h2 className="text-2xl font-bold mb-6 text-gray-900 dark:text-white">Billing History</h2>
                    {data?.billing?.length ? (
                      <ul className="space-y-2">
                        {data.billing.map((b: any) => (
                          <li key={b.id} className="flex justify-between p-3 border border-gray-200 dark:border-gray-700 rounded bg-gray-50 dark:bg-gray-700/30">
                            <span className="text-gray-900 dark:text-gray-200">{new Date(b.date).toLocaleDateString()}</span>
                            <span className="flex-1 mx-3 text-gray-700 dark:text-gray-300">{b.description}</span>
                            <span className="font-semibold text-gray-900 dark:text-white">${b.amount.toFixed(2)}</span>
                            <span className={"ml-3 text-xs px-3 py-1 rounded-full " + (b.status === 'paid' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : b.status === 'pending' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300' : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300')}>{b.status}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-gray-600 dark:text-gray-400">No billing records found.</p>
                    )}
                  </div>
                )}

                {activeTab === 'api' && (
                  <div>
                    <div className="flex justify-between items-center mb-6">
                      <h2 className="text-2xl font-bold text-gray-900 dark:text-white">API Keys</h2>
                      <button onClick={genKey} disabled={generating} className="bg-blue-500 hover:bg-blue-600 dark:bg-blue-600 dark:hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-600 text-white font-semibold py-2 px-4 rounded-lg transition">
                        {generating ? 'Generating...' : '+ Generate New Key'}
                      </button>
                    </div>
                    {apiKeys.length === 0 ? (
                      <div className="text-center py-8 bg-gray-50 dark:bg-gray-700/30 rounded-lg border border-gray-200 dark:border-gray-700">
                        <p className="text-gray-600 dark:text-gray-400 mb-4">No API keys generated yet.</p>
                        <p className="text-sm text-gray-500 dark:text-gray-500">Generate an API key to programmatically access the STVOR API.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {apiKeys.map((k) => (
                          <div key={k.id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-gray-50 dark:bg-gray-700/30">
                            <div className="flex justify-between items-start mb-3">
                              <div>
                                <h3 className="font-semibold text-gray-900 dark:text-white">{k.name}</h3>
                                <p className="text-sm text-gray-600 dark:text-gray-400">Created: {new Date(k.createdAt).toLocaleDateString()}</p>
                              </div>
                              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300">Active</span>
                            </div>
                            <div className="bg-gray-100 dark:bg-gray-800 p-3 rounded font-mono text-sm break-all mb-4 text-gray-900 dark:text-gray-200">{k.key}</div>
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
    </div>
  );
}
