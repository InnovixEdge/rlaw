import { google } from 'googleapis';
import fetch from 'node-fetch';
import { storeTokensForUser } from './oauth-store'; // or whatever filename you choose for token storage logic


// Configuration values loaded from environment variables
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT = process.env.GOOGLE_REDIRECT || '';

const OUTLOOK_CLIENT_ID = process.env.OUTLOOK_CLIENT_ID || '';
const OUTLOOK_CLIENT_SECRET = process.env.OUTLOOK_CLIENT_SECRET || '';
const OUTLOOK_REDIRECT = process.env.OUTLOOK_REDIRECT || '';

// Create an OAuth2 client for Google
const googleOAuth2 = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT
);

export function googleAuthUrl() {
  const scopes = ['https://www.googleapis.com/auth/calendar'];
  return googleOAuth2.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent',
  });
}

export async function handleGoogleCallback(code: string) {
  const { tokens } = await googleOAuth2.getToken(code);
  await storeTokensForUser('user123', { googleAccessToken: tokens.access_token });
  return tokens;
}

// Outlook OAuth implementation using Microsoft identity platform
export function outlookAuthUrl() {
  const params = new URLSearchParams({
    client_id: OUTLOOK_CLIENT_ID,
    response_type: 'code',
    redirect_uri: OUTLOOK_REDIRECT,
    response_mode: 'query',
    scope: 'https://graph.microsoft.com/Calendars.ReadWrite offline_access',
  });
  return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params.toString()}`;
}

export async function handleOutlookCallback(code: string) {
  const params = new URLSearchParams({
    client_id: OUTLOOK_CLIENT_ID,
    client_secret: OUTLOOK_CLIENT_SECRET,
    redirect_uri: OUTLOOK_REDIRECT,
    code,
    grant_type: 'authorization_code',
  });

  const response = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  const tokens = await response.json();
  await storeTokensForUser('user123', { outlookAccessToken: tokens.access_token });
  return tokens;
}

