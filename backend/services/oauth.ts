import { google } from 'googleapis'
import fetch from 'node-fetch'
import { storeTokensForUser } from './oauth-store'

// === Hardcoded Redirect URIs for production ===
const GOOGLE_REDIRECT = 'https://rlaw.vercel.app/api/auth/google/callback'
const OUTLOOK_REDIRECT = 'https://rlaw.vercel.app/api/auth/outlook/callback'

// === Load client secrets from env vars ===
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || ''
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || ''
const OUTLOOK_CLIENT_ID = process.env.OUTLOOK_CLIENT_ID || ''
const OUTLOOK_CLIENT_SECRET = process.env.OUTLOOK_CLIENT_SECRET || ''

// === Validate critical credentials ===
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  throw new Error('Missing Google OAuth credentials')
}
if (!OUTLOOK_CLIENT_ID || !OUTLOOK_CLIENT_SECRET) {
  throw new Error('Missing Outlook OAuth credentials')
}

// === Token response shape for Outlook ===
interface OutlookTokenResponse {
  access_token?: string | null
  token_type?: string
  expires_in?: number
  scope?: string
  refresh_token?: string
}

// === Google OAuth2 client ===
const googleOAuth2 = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT
)

// === Generate Google auth URL ===
export function googleAuthUrl() {
  const scopes = ['https://www.googleapis.com/auth/calendar']
  return googleOAuth2.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent',
    redirect_uri: GOOGLE_REDIRECT
  })
}

// === Handle Google OAuth2 callback ===
export async function handleGoogleCallback(code: string) {
  const { tokens } = await googleOAuth2.getToken({
    code,
    redirect_uri: GOOGLE_REDIRECT
  })
  await storeTokensForUser('user123', {
    googleAccessToken: tokens.access_token ?? undefined
  })
  return tokens
}

// === Generate Outlook auth URL ===
export function outlookAuthUrl() {
  const params = new URLSearchParams({
    client_id: OUTLOOK_CLIENT_ID,
    response_type: 'code',
    redirect_uri: OUTLOOK_REDIRECT,
    response_mode: 'query',
    scope: 'https://graph.microsoft.com/Calendars.ReadWrite offline_access'
  })

  return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params.toString()}`
}

// === Handle Outlook OAuth2 callback ===
export async function handleOutlookCallback(code: string) {
  const params = new URLSearchParams({
    client_id: OUTLOOK_CLIENT_ID,
    client_secret: OUTLOOK_CLIENT_SECRET,
    redirect_uri: OUTLOOK_REDIRECT,
    code,
    grant_type: 'authorization_code'
  })

  const response = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  })

  const tokens = await response.json() as OutlookTokenResponse
  await storeTokensForUser('user123', {
    outlookAccessToken: tokens.access_token ?? undefined
  })

  return tokens
}
