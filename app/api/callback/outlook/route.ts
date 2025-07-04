import { handleOutlookCallback } from '@/backend/services/oauth';
import { NextResponse } from 'next/server';

export async function GET(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get('code');
  if (!code) return NextResponse.json({ error: 'Missing code' }, { status: 400 });

  await handleOutlookCallback(code);
  return NextResponse.redirect('/success');
}
