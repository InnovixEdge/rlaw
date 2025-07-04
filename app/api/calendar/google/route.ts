import { NextResponse } from 'next/server';
import { getGoogleCalendarEvents } from '@/backend/services/google-calendar';

export async function GET() {
  const events = await getGoogleCalendarEvents('user123');
  return NextResponse.json(events);
}
