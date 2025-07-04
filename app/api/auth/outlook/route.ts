import { outlookAuthUrl } from '@/backend/services/oauth';
import { NextResponse } from 'next/server';

export async function GET() {
  const url = outlookAuthUrl();
  return NextResponse.redirect(url);
}
