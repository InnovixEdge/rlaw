import { google } from 'googleapis'
import fetch from 'node-fetch'
import { storeTokensForUser } from './oauth-store'

// === Load environment variables ===
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || ''
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || ''
const GOOGLE_REDIRECT = process.env.GOOGLE_REDIRECT_URI || ''

const OUTLOOK_CLIENT_ID = process.env.OUTLOOK_CLIENT_ID || ''
const OUTLOOK_CLIENT_SECRET = process.env.OUTLOOK_CLIENT_SECRET || ''
const OUTLOOK_REDIRECT = process.env.OUTLOOK_REDIRECT_URI || ''

// === Validate critical environment variables ===
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT) {
  throw new Error('Missing one or more Google OAuth environment variables.')
}

if (!OUTLOOK_CLIENT_ID || !OUTLOOK_CLIENT_SECRET || !OUTLOOK_REDIRECT) {
  throw new Error('Missing one or more Outlook OAuth environment variables.')
}

// Optional: log redirect URIs during dev
if (process.env.NODE_ENV !== 'production') {
  console.log('[OAuth DEBUG] GOOGLE_REDIRECT:', GOOGLE_REDIRECT)
  console.log('[OAuth DEBUG] OUTLOOK_REDIRECT:', OUTLOOK_REDIRECT)
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
    redirect_uri: GOOGLE_REDIRECT // required explicitly
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
    redirect_uri: OUTL_
