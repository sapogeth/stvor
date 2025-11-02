// apps/web/app/api/relay/prekeys/[username]/route.ts
import { NextResponse } from 'next/server';

const RELAY_BASE =
  process.env.RELAY_BASE_URL ||
  'http://localhost:3001';

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  const resolvedParams = await params;
  const username = (resolvedParams.username || '').toLowerCase();

  const res = await fetch(`${RELAY_BASE}/prekey/${username}`, {
    method: 'GET',
    headers: {
      'content-type': 'application/json',
    },
  });

  if (!res.ok) {
    console.warn(`[Proxy] Prekey GET /${username} -> ${res.status}`);
    return NextResponse.json(
      {
        error: 'prekey_not_found',
        message: `No prekey bundle for ${username}`,
      },
      { status: res.status }
    );
  }

  const data = await res.json();

  console.log(`[Proxy] Prekey GET /${username} -> 200`);

  return NextResponse.json({
    username,
    identityPublicKey:
      data.identityPublicKey || data.identityEd25519 || data.ed25519,
    prekeyBundle: data.prekeyBundle || data.bundle || data,
    prekeySignature:
      data.prekeySignature ||
      data.signature ||
      data.prekeyBundle?.signature ||
      data.bundle?.signature ||
      null,
  });
}
