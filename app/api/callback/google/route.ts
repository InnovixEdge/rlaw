import { NextRequest, NextResponse } from 'next/server'
//import { handleGoogleCallback } from '@/backend/services/oauth'

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')

  if (!code) {
    return new NextResponse('Missing code parameter', { status: 400 })
  }

  try {
    const tokens = await handleGoogleCallback(code)
    console.log('Google tokens:', tokens)

    // Redirect to dashboard or success page
    return NextResponse.redirect(new URL('/dashboard', request.url))
  } catch (err) {
    console.error('OAuth callback error:', err)
    return new NextResponse('OAuth callback failed', { status: 500 })
  }
}
