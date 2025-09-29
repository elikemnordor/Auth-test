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
        authorizedParties: [origin],
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
    console.log('[welcome] SDK verifyToken path failed, falling back to manual verification', String(e?.message || e));
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
      console.log('[welcome] getDisplayName called without userId, falling back to "user"');
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

// --- Helpers ---
async function verifyWithJWKS(token, expectedIssuer, expectedAzp) {
  if (!token) return { ok: false, error: 'missing token' };
  const [hB64, pB64, sB64] = token.split('.');
  if (!hB64 || !pB64 || !sB64) return { ok: false, error: 'malformed token' };

  const decode = b64 => atob(b64.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64.length / 4) * 4, '='));
  const enc = new TextEncoder();
  const toBytes = str => enc.encode(str);
  const sigBytes = Uint8Array.from(atob(sB64.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(sB64.length / 4) * 4, '=')), c => c.charCodeAt(0));

  let header, payload;
  try {
    header = JSON.parse(decode(hB64));
    payload = JSON.parse(decode(pB64));
  } catch (e) {
    return { ok: false, error: 'invalid json in jwt' };
  }

  const iss = payload.iss;
  const azp = payload.azp;
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) return { ok: false, error: 'token expired' };
  if (expectedIssuer && iss && expectedIssuer !== iss) return { ok: false, error: `issuer mismatch: ${iss} !== ${expectedIssuer}` };
  if (expectedAzp && azp && expectedAzp !== azp) return { ok: false, error: `azp mismatch: ${azp} !== ${expectedAzp}` };

  const jwksUrl = (iss || '').replace(/\/$/, '') + '/.well-known/jwks.json';
  const jwksRes = await fetch(jwksUrl, { cf: { cacheEverything: true, cacheTtl: 300 } });
  if (!jwksRes.ok) return { ok: false, error: `jwks fetch failed: ${jwksRes.status}` };
  const { keys } = await jwksRes.json();
  const jwk = (keys || []).find(k => k.kid === header.kid);
  if (!jwk) return { ok: false, error: 'kid not found in jwks' };

  let algo;
  if (header.alg === 'RS256') {
    algo = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  } else if (header.alg === 'EdDSA' && jwk.crv === 'Ed25519') {
    algo = { name: 'Ed25519' };
  } else if (header.alg === 'ES256') {
    algo = { name: 'ECDSA', hash: 'SHA-256' };
  } else {
    return { ok: false, error: `unsupported alg: ${header.alg}` };
  }

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    algo,
    false,
    ['verify']
  );

  const data = toBytes(`${hB64}.${pB64}`);
  const verified = await crypto.subtle.verify(algo, key, sigBytes, data);
  return verified ? { ok: true, payload } : { ok: false, error: 'signature invalid' };
}

  // Get the authorization header
  const authHeader = request.headers.get('Authorization');
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map(p => p.trim())
    .find(p => p.startsWith('__session='))
    ?.split('=')[1];
  const sessionCookieDecoded = sessionCookie ? decodeURIComponent(sessionCookie) : undefined;

  if ((!authHeader || !authHeader.startsWith('Bearer ')) && !sessionCookie) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized: no token found in Authorization header or __session cookie' }),
      { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  try {
    // Verify the token with Clerk's API
    const tokenFromHeader = !!(authHeader && authHeader.startsWith('Bearer '));
    const tokenSource = tokenFromHeader ? 'authorization_header' : (sessionCookieDecoded ? '__session_cookie' : 'none');
    const token = tokenFromHeader ? authHeader.split(' ')[1] : sessionCookieDecoded;
    console.log('[welcome] token selection', {
      tokenSource,
      hasToken: !!token,
      tokenLength: token ? token.length : 0,
    });

    const verifyResponse = await fetch('https://api.clerk.com/v1/sessions/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${context.env.CLERK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ token })
    });
    const verifyText = await verifyResponse.clone().text().catch((err) => {
      console.error('[welcome] Failed to read verify response text', err);
      return '';
    });

    let verifyData;
    if (verifyText && verifyText.trim().length > 0) {
      try {
        verifyData = JSON.parse(verifyText);
        const { user_id, session } = verifyData;
        console.log('[welcome] verifyData summary', {
          user_id,
          sessionUserId: session?.user_id,
          sessionId: session?.id,
          organizationId: session?.organization_id,
        });
      } catch (err) {
        console.error('[welcome] Failed to parse verify response JSON', err, { raw: verifyText.slice(0, 200) });
      }
    } else {
      console.log('[welcome] verify response body empty');
    }

    const bapiHasUser = verifyResponse.ok && !!(verifyData?.user_id || verifyData?.session?.user_id);
    console.log('[welcome] BAPI user present?', { ok: verifyResponse.ok, bapiHasUser });
    if (!bapiHasUser) {
      const detailsText = verifyText;
      // Try to decode JWT for debugging claims (non-cryptographic)
      const parts = (token || '').split('.');
      let claims = {};
      try {
        if (parts.length >= 2) {
          const b64 = (s) => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
          const json = atob(b64(parts[1]));
          const hdr = atob(b64(parts[0]));
          claims = { header: JSON.parse(hdr), payload: JSON.parse(json) };
        }
      } catch (_) {}

      // Fallback: Verify using JWKS from the token issuer
      const jwksFallback = await verifyWithJWKS(token, claims.payload?.iss, new URL(request.url).origin).catch(e => ({ ok: false, error: String(e) }));
      if (jwksFallback.ok) {
        const payload = decodeJwtPayload(token);
        const displayName = await getDisplayName(payload?.sub, context.env.CLERK_SECRET_KEY);
        return new Response(
          JSON.stringify({
            message: `Welcome, ${displayName}! This is only visible to authenticated users.`,
            verifiedBy: 'jwks'
          }),
          { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders } }
        );
      }

      return new Response(
        JSON.stringify({ 
          error: 'Invalid token', 
          details: detailsText, 
          tokenSource: tokenFromHeader ? 'authorization_header' : (sessionCookieDecoded ? '__session_cookie' : 'none'),
          claims: claims.payload ? {
            iss: claims.payload.iss,
            aud: claims.payload.aud,
            azp: claims.payload.azp,
            sid: claims.payload.sid,
            sub: claims.payload.sub,
            exp: claims.payload.exp,
            iat: claims.payload.iat,
            kid: claims.header?.kid,
          } : undefined,
          bapiStatus: verifyResponse.status,
          jwksFallback
        }),
        { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
      );
    }

    // Token is valid, personalize the message
    const payload = decodeJwtPayload(token);
    console.log('[welcome] decoded token payload', {
      sub: payload?.sub,
      iss: payload?.iss,
      azp: payload?.azp,
      sid: payload?.sid,
    });
    const userId = verifyData?.user_id || verifyData?.session?.user_id || payload?.sub;
    console.log('[welcome] resolved userId for display', { userId });
    const displayName = await getDisplayName(userId, context.env.CLERK_SECRET_KEY);
    console.log('[welcome] resolved displayName', { displayName });
    return new Response(
      JSON.stringify({
        message: `Welcome, ${displayName}! This is only visible to authenticated users.`,
        verifiedBy: 'bapi'
      }),
      {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          ...corsHeaders,
        }
      }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }
}
