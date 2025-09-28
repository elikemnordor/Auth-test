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
    const token = (authHeader && authHeader.startsWith('Bearer '))
      ? authHeader.split(' ')[1]
      : sessionCookie;
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
      return new Response(
        JSON.stringify({ error: 'Invalid token', details: detailsText }),
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
