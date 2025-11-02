/**
 * Health check route - used to verify App Router is functioning
 *
 * Test with: curl http://localhost:3002/healthcheck
 */

export async function GET() {
  return new Response(JSON.stringify({
    status: 'ok',
    timestamp: new Date().toISOString(),
    message: 'Next.js App Router is working',
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
