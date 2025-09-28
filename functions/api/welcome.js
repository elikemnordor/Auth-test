export async function onRequest(context) {
  const { request } = context;

  // Basic CORS headers (tune origin in production if needed)
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Get the authorization header
  const authHeader = request.headers.get('Authorization');
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map(p => p.trim())
    .find(p => p.startsWith('__session='))
    ?.split('=')[1];

  if ((!authHeader || !authHeader.startsWith('Bearer ')) && !sessionCookie) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized: no token found in Authorization header or __session cookie' }),
      { status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
    );
  }

  try {
    // Verify the token with Clerk's API
    const tokenFromHeader = !!(authHeader && authHeader.startsWith('Bearer '));
    const token = tokenFromHeader ? authHeader.split(' ')[1] : sessionCookie;
    const audience = new URL(request.url).origin;
    const verifyResponse = await fetch('https://api.clerk.com/v1/sessions/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${context.env.CLERK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ token, audience })
    });

    if (!verifyResponse.ok) {
      const detailsText = await verifyResponse.text().catch(() => '');
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
      return new Response(
        JSON.stringify({ 
          error: 'Invalid token', 
          details: detailsText, 
          tokenSource: tokenFromHeader ? 'authorization_header' : (sessionCookie ? '__session_cookie' : 'none'),
          claims: claims.payload ? {
            iss: claims.payload.iss,
            aud: claims.payload.aud,
            azp: claims.payload.azp,
            sid: claims.payload.sid,
            sub: claims.payload.sub,
            exp: claims.payload.exp,
            iat: claims.payload.iat,
            kid: claims.header?.kid,
          } : undefined
        }),
        { status: 403, headers: { 'Content-Type': 'application/json', ...corsHeaders } }
      );
    }

    // Token is valid, return the protected message
    return new Response(
      JSON.stringify({
        message: "Welcome to the protected content! This is only visible to authenticated users."
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
