// app/api/callback/outlook/route.ts
import { NextRequest, NextResponse } from 'next/server';

// Define interface for Microsoft OAuth tokens
interface MicrosoftTokens {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
}

// Handle the Microsoft/Outlook OAuth callback
async function handleOutlookCallback(code: string): Promise<MicrosoftTokens> {
  try {
    const tokenEndpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    
    const params = new URLSearchParams({
      client_id: process.env.MICROSOFT_CLIENT_ID || '',
      client_secret: process.env.MICROSOFT_CLIENT_SECRET || '',
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: `${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/api/callback/outlook`,
      scope: 'https://graph.microsoft.com/calendars.read https://graph.microsoft.com/calendars.readwrite'
    });

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`Microsoft OAuth token exchange failed: ${response.status} - ${errorData}`);
    }

    const tokens = await response.json();
    return tokens;
  } catch (error) {
    console.error('Error handling Outlook OAuth callback:', error);
    throw new Error(`Outlook OAuth callback failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const code = searchParams.get('code');
  const error = searchParams.get('error');
  const errorDescription = searchParams.get('error_description');

  // Handle OAuth errors
  if (error) {
    console.error('Microsoft OAuth error:', error, errorDescription);
    return NextResponse.redirect(
      new URL(`/auth/error?error=${encodeURIComponent(error)}&description=${encodeURIComponent(errorDescription || '')}`, request.url)
    );
  }

  // Handle missing authorization code
  if (!code) {
    console.error('No authorization code received from Microsoft');
    return NextResponse.redirect(
      new URL('/auth/error?error=no_code', request.url)
    );
  }

  try {
    const tokens = await handleOutlookCallback(code);
    console.log('Microsoft tokens received:', {
      access_token: tokens.access_token ? 'received' : 'missing',
      refresh_token: tokens.refresh_token ? 'received' : 'missing',
      expires_in: tokens.expires_in
    });

    // Redirect to success page
    const successUrl = new URL('/auth/success', request.url);
    
    // Add token info to URL params
    successUrl.searchParams.set('provider', 'outlook');
    if (tokens.access_token) {
      successUrl.searchParams.set('access_token', 'received');
    }
    if (tokens.refresh_token) {
      successUrl.searchParams.set('refresh_token', 'received');
    }

    return NextResponse.redirect(successUrl);
  } catch (error) {
    console.error('Outlook OAuth callback error:', error);
    return NextResponse.redirect(
      new URL(`/auth/error?error=callback_failed&provider=outlook`, request.url)
    );
  }
}

// Handle POST requests (for manual token exchange)
export async function POST(request: NextRequest) {
  try {
    const { code } = await request.json();

    if (!code) {
      return NextResponse.json(
        { success: false, error: 'Authorization code is required' },
        { status: 400 }
      );
    }

    const tokens = await handleOutlookCallback(code);

    return NextResponse.json({
      success: true,
      data: {
        access_token: tokens.access_token ? 'received' : null,
        refresh_token: tokens.refresh_token ? 'received' : null,
        expires_in: tokens.expires_in,
        scope: tokens.scope,
        token_type: tokens.token_type,
        provider: 'outlook'
      },
      message: 'Outlook OAuth callback successful'
    });
  } catch (error) {
    console.error('Outlook OAuth POST callback error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'OAuth callback failed',
        provider: 'outlook'
      },
      { status: 500 }
    );
  }
}
/*export {}
