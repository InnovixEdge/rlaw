// app/api/callback/google/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { google } from 'googleapis';

// Define interface for OAuth tokens
interface GoogleTokens {
  access_token?: string | null;
  refresh_token?: string | null;
  scope?: string | null;
  token_type?: string | null;
  expiry_date?: number | null;
}

// Handle the Google OAuth callback
async function handleGoogleCallback(code: string): Promise<GoogleTokens> {
  try {
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      `${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/api/callback/google`
    );

    // Exchange the authorization code for tokens
    const { tokens } = await oauth2Client.getToken(code);
    
    return tokens;
  } catch (error) {
    console.error('Error handling Google OAuth callback:', error);
    throw new Error(`OAuth callback failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const code = searchParams.get('code');
  const error = searchParams.get('error');
  const state = searchParams.get('state');

  // Handle OAuth errors
  if (error) {
    console.error('Google OAuth error:', error);
    return NextResponse.redirect(
      new URL(`/auth/error?error=${encodeURIComponent(error)}`, request.url)
    );
  }

  // Handle missing authorization code
  if (!code) {
    console.error('No authorization code received');
    return NextResponse.redirect(
      new URL('/auth/error?error=no_code', request.url)
    );
  }

  try {
    const tokens = await handleGoogleCallback(code);
    console.log('Google tokens:', tokens);

    // Redirect to dashboard or success page
    const successUrl = new URL('/auth/success', request.url);
    
    // Add token info to URL params (you might want to store these more securely)
    if (tokens.access_token) {
      successUrl.searchParams.set('access_token', 'received');
    }
    if (tokens.refresh_token) {
      successUrl.searchParams.set('refresh_token', 'received');
    }

    return NextResponse.redirect(successUrl);
  } catch (error) {
    console.error('Google OAuth callback error:', error);
    return NextResponse.redirect(
      new URL(`/auth/error?error=${encodeURIComponent('callback_failed')}`, request.url)
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

    const tokens = await handleGoogleCallback(code);

    return NextResponse.json({
      success: true,
      data: {
        access_token: tokens.access_token ? 'received' : null,
        refresh_token: tokens.refresh_token ? 'received' : null,
        expires_in: tokens.expiry_date,
        scope: tokens.scope,
        token_type: tokens.token_type
      },
      message: 'Google OAuth callback successful'
    });
  } catch (error) {
    console.error('Google OAuth POST callback error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'OAuth callback failed'
      },
      { status: 500 }
    );
  }
}
