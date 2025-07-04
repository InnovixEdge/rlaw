import { NextRequest, NextResponse } from 'next/server'
import { handleGoogleCallback } from '@/backend/services/oauth'

export async function GET(req: NextRequest) {
  const url = new URL(req.url)
  const code = url.searchParams.get('code')

  if (!code) {
    return NextResponse.json({ error: 'Missing code parameter from Google callback.' }, { status: 400 })
  }

  try {
    const tokens = await handleGoogleCallback(code)
    console.log('[Google Callback] Tokens stored:', tokens)
    return NextResponse.redirect(`${process.env.NEXT_PUBLIC_APP_URL || 'https://rlaw.vercel.app'}/dashboard`)
  } catch (err) {
    console.error('[Google Callback Error]', err)
    return NextResponse.json({ error: 'Failed to handle Google callback.' }, { status: 500 })
  }
}
