import { googleAuthUrl } from '@/lib/services/oauth';
import { NextResponse } from 'next/server';

export async function GET() {
  const url = googleAuthUrl();
  return NextResponse.redirect(url);
}
