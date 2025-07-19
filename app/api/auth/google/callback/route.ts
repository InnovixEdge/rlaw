import { NextRequest, NextResponse } from 'next/server'
import { handleGoogleCallback } from '@/lib/services/oauth'

export async function GET(req: NextRequest) {
  const url = new URL(req.url)
  const code = url.searchParams.get('code')

  if (!code) {
    return NextResponse.json({ error: 'Missing code parameter from Google callback.' }, { status: 400 })
  }

  try {
    const tokens = await handleGoogleCallback()
    console.log('[Google Callback] Tokens stored:', tokens)

    // Hardcoded redirect to your dashboard
    //return NextResponse.redirect('https://rlaw.vercel.app/dashboard')
    return NextResponse.redirect(`${process.env.NEXT_PUBLIC_APP_URL}/`);

  } catch (err) {
    console.error('[Google Callback Error]', err)
    return NextResponse.json({ error: 'Failed to handle Google callback.' }, { status: 500 })
  }
}
