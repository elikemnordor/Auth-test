export async function onRequest(context) {
  const { request } = context;
  
  // Get the authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(
      JSON.stringify({ error: 'Unauthorized' }), 
      { status: 401, headers: { 'Content-Type': 'application/json' } }
    );
  }

  try {
    // Verify the token with Clerk's API
    const token = authHeader.split(' ')[1];
    const verifyResponse = await fetch('https://api.clerk.com/v1/sessions/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${context.env.CLERK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ token })
    });

    if (!verifyResponse.ok) {
      return new Response(
        JSON.stringify({ error: 'Invalid token' }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
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
          'Cache-Control': 'no-store' 
        } 
      }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
}
