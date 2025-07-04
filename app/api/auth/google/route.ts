import { googleAuthUrl } from '@/backend/services/oauth';
import { NextResponse } from 'next/server';

export async function GET() {
  const url = googleAuthUrl();
  return NextResponse.redirect(url);
}
