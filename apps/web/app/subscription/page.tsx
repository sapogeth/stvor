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

	if (!isLoaded) return <div className="min-h-screen flex items-center justify-center">Loading...</div>;
	if (!isSignedIn) return null;

	return (
		<div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
			<div className="max-w-4xl mx-auto p-8">
				<div className="mb-8">
					<Link href="/chat" className="text-indigo-600 hover:text-indigo-700 mb-4 inline-block">← Back to Chat</Link>
					<h1 className="text-4xl font-bold text-gray-900 mb-2">Subscription & API</h1>
					<p className="text-gray-600">Manage your plan, usage, billing, and API keys</p>
				</div>

				{error && (
					<div className="mb-6 p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg">{error}</div>
				)}

				<div className="bg-white rounded-lg shadow-lg overflow-hidden mb-8">
					<div className="flex border-b border-gray-200">
						<button onClick={() => setActiveTab('plan')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'plan' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-600 hover:text-gray-900')}>Plan</button>
						<button onClick={() => setActiveTab('usage')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'usage' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-600 hover:text-gray-900')}>Usage</button>
						<button onClick={() => setActiveTab('billing')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'billing' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-600 hover:text-gray-900')}>Billing</button>
						<button onClick={() => setActiveTab('api')} className={'flex-1 px-6 py-4 font-semibold ' + (activeTab === 'api' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-600 hover:text-gray-900')}>API Keys</button>
					</div>

					<div className="p-8">
						{loading ? (
							<div className="text-center py-8">
								<div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
								<p className="mt-4 text-gray-600">Loading subscription data...</p>
							</div>
						) : (
							<>
								{activeTab === 'plan' && data && (
									<div>
										<h2 className="text-2xl font-bold mb-6">Your Current Plan</h2>
										<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
											<div className="bg-indigo-50 p-6 rounded-lg">
												<h3 className="font-semibold text-indigo-900 mb-2 capitalize">{data.subscription.plan} Plan</h3>
												<p className="text-sm text-indigo-800">Status: {data.subscription.status}</p>
												<p className="text-sm text-indigo-800">Renews: {new Date(data.subscription.currentPeriodEnd).toLocaleDateString()}</p>
												<p className="text-sm text-indigo-800">Messages: {data.subscription.messagesUsed} / {data.subscription.messagesLimit}</p>
												<p className="text-sm text-indigo-800">Devices: {data.subscription.devicesUsed} / {data.subscription.devicesAllowed}</p>
											</div>
											<button className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 rounded-lg transition">Upgrade Plan</button>
										</div>
									</div>
								)}

								{activeTab === 'usage' && data && (
									<div>
										<h2 className="text-2xl font-bold mb-6">Usage Statistics</h2>
										<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
											<div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
												<h3 className="font-semibold text-gray-900 mb-3">Messages This Month</h3>
												<div className="text-3xl font-bold text-gray-900">{data.usage.messagesThisMonth}</div>
											</div>
											<div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
												<h3 className="font-semibold text-gray-900 mb-3">Active Devices</h3>
												<div className="text-3xl font-bold text-gray-900">{data.usage.devicesActive}</div>
											</div>
											<div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
												<h3 className="font-semibold text-gray-900 mb-3">Storage Usage</h3>
												<div className="text-3xl font-bold text-gray-900">{data.usage.storageUsedMB} MB / {data.usage.storageLimit} MB</div>
											</div>
											<div className="bg-green-50 p-6 rounded-lg border border-green-200">
												<h3 className="font-semibold text-green-900 mb-2">Uptime</h3>
												<p className="text-3xl font-bold text-green-600">{data.usage.uptime}</p>
											</div>
										</div>
									</div>
								)}

								{activeTab === 'billing' && (
									<div>
										<h2 className="text-2xl font-bold mb-6">Billing History</h2>
										{data?.billing?.length ? (
											<ul className="space-y-2">
												{data.billing.map((b: any) => (
													<li key={b.id} className="flex justify-between p-3 border rounded">
														<span>{new Date(b.date).toLocaleDateString()}</span>
														<span className="flex-1 mx-3">{b.description}</span>
														<span className="font-semibold">${b.amount.toFixed(2)}</span>
														<span className={"ml-3 text-xs px-3 py-1 rounded-full " + (b.status === 'paid' ? 'bg-green-100 text-green-800' : b.status === 'pending' ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800')}>{b.status}</span>
													</li>
												))}
											</ul>
										) : (
											<p className="text-gray-600">No billing records found.</p>
										)}
									</div>
								)}

								{activeTab === 'api' && (
									<div>
										<div className="flex justify-between items-center mb-6">
											<h2 className="text-2xl font-bold">API Keys</h2>
											<button onClick={genKey} disabled={generating} className="bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white font-semibold py-2 px-4 rounded-lg transition">
												{generating ? 'Generating...' : '+ Generate New Key'}
											</button>
										</div>
										{apiKeys.length === 0 ? (
											<div className="text-center py-8 bg-gray-50 rounded-lg">
												<p className="text-gray-600 mb-4">No API keys generated yet.</p>
												<p className="text-sm text-gray-500">Generate an API key to programmatically access the STVOR API.</p>
											</div>
										) : (
											<div className="space-y-4">
												{apiKeys.map((k) => (
													<div key={k.id} className="border border-gray-200 rounded-lg p-4">
														<div className="flex justify-between items-start mb-3">
															<div>
																<h3 className="font-semibold text-gray-900">{k.name}</h3>
																<p className="text-sm text-gray-600">Created: {new Date(k.createdAt).toLocaleDateString()}</p>
															</div>
															<span className="px-3 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-800">Active</span>
														</div>
														<div className="bg-gray-100 p-3 rounded font-mono text-sm break-all mb-4">{k.key}</div>
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
