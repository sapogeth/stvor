import { currentUser } from '@clerk/nextjs/server';
import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const user = await currentUser();
    if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

    const payload = {
      subscription: {
        plan: 'premium',
        status: 'active',
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        messagesUsed: 1250,
        messagesLimit: 5000,
        devicesAllowed: 5,
        devicesUsed: 2,
      },
      usage: {
        messagesThisMonth: 1250,
        devicesActive: 2,
        storageUsedMB: 425,
        storageLimit: 1000,
        uptime: '99.98%',
      },
      billing: [
        {
          id: '1',
          date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
          description: 'Premium Plan Monthly',
          amount: 9.99,
          status: 'paid',
        },
      ],
      apiKeys: [],
    };

    return NextResponse.json(payload);
  } catch (e) {
    console.error('[subscription/data] Error:', e);
    return NextResponse.json({ error: 'Failed to load subscription data' }, { status: 500 });
  }
}
