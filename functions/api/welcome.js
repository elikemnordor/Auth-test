 import { verifyToken, createClerkClient } from '@clerk/backend';

 export async function onRequest(context) {
  const { request, env } = context;

  // Basic CORS headers (tune origin in production if needed)
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  };
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Try Clerk Worker SDK first using verifyToken() against the token in header/cookie.
  try {
    const authHeader = request.headers.get('Authorization');
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionCookie = cookieHeader
      .split(';')
      .map(p => p.trim())
      .find(p => p.startsWith('__session='))
      ?.split('=')[1];
    const sessionCookieDecoded = sessionCookie ? decodeURIComponent(sessionCookie) : undefined;
    const tokenFromHeader = !!(authHeader && authHeader.startsWith('Bearer '));
    const token = tokenFromHeader ? authHeader.split(' ')[1] : sessionCookieDecoded;

    if (token) {
      const payloadGuess = await decodeJwtPayload(token).catch(() => undefined);
      const issuer = payloadGuess?.iss; // non-cryptographic decode used only to guide verification options
      const origin = new URL(request.url).origin;
      const verified = await verifyToken(token, {
        issuer,
        clockSkewInMs: 10_000,
      }).catch(() => undefined);

      const userId = verified?.payload?.sub;
      if (userId) {
        const clerk = createClerkClient({ secretKey: env.CLERK_SECRET_KEY });
        const user = await clerk.users.getUser(userId);
        const displayName = [user.firstName, user.lastName].filter(Boolean).join(' ').trim()
          || user.username
          || user.emailAddresses?.[0]?.emailAddress
          || user.id;
        return new Response(
          JSON.stringify({
            message: `Welcome, ${displayName}! This is only visible to authenticated users.`,
            email: user.emailAddresses?.[0]?.emailAddress,
            verifiedBy: 'sdk-verifyToken',
          }),
          { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders } }
        );
      } else {
        console.log('[welcome] SDK verifyToken returned no userId; falling back');
      }
    }
  } catch (e) {
    // Ignore; fallback to BAPI verification below
  }

  // --- Helpers ---
  async function decodeJwtPayload(token) {
    if (!token) return undefined;
    const parts = token.split('.');
    if (parts.length < 2) return undefined;
    const b64 = s => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
    try {
      const json = atob(b64(parts[1]));
      return JSON.parse(json);
    } catch {
      return undefined;
    }
  }

  async function getDisplayName(userId, secretKey) {
    if (!userId) {
      return 'user';
    }
    try {
      const r = await fetch(`https://api.clerk.com/v1/users/${userId}`, {
        headers: { 'Authorization': `Bearer ${secretKey}` }
      });
      if (!r.ok) {
        console.error('[welcome] getDisplayName Clerk users fetch failed', {
          status: r.status,
          statusText: r.statusText,
        });
        return userId;
      }
      const u = await r.json();
      const name = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
      const username = u.username;
      const email = Array.isArray(u.email_addresses) && u.email_addresses[0]?.email_address;
      return (name || username || email || userId);
    } catch {
      console.error('[welcome] getDisplayName Clerk users fetch threw, returning userId fallback');
      return userId;
    }
  }

  // Fallback: Verify via Clerk Sessions Verify endpoint
  const authHeader = request.headers.get('Authorization');
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map(p => p.trim())
    .find(p => p.startsWith('__session='))
    ?.split('=')[1];
  const sessionCookieDecoded = sessionCookie ? decodeURIComponent(sessionCookie) : undefined;

  if ((!authHeader || !authHeader.startsWith('Bearer ')) && !sessionCookieDecoded) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }),
      { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  try {
    const tokenFromHeader = !!(authHeader && authHeader.startsWith('Bearer '));
    const token = tokenFromHeader ? authHeader.split(' ')[1] : sessionCookieDecoded;

    const verifyResponse = await fetch('https://api.clerk.com/v1/sessions/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CLERK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ token })
    });

    const verifyData = verifyResponse.ok ? await verifyResponse.json().catch(() => null) : null;
    const userId = verifyData?.user_id || verifyData?.session?.user_id;

    if (!verifyResponse.ok || !userId) {
      return new Response(
        JSON.stringify({ error: 'Forbidden: invalid or expired session' }),
        { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
      );
    }

    const displayName = await getDisplayName(userId, env.CLERK_SECRET_KEY);
    return new Response(
      JSON.stringify({
        message: `Welcome, ${displayName}! This is only visible to authenticated users.`,
        verifiedBy: 'bapi'
      }),
      { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders } }
    );

  } catch {
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }
}
