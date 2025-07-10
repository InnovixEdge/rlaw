import { NextResponse } from 'next/server';
//import { getGoogleCalendarEvents } from '@/backend/services/google-calendar';

export async function GET() {
  try {
    const events = await getGoogleCalendarEvents('user123');
    return NextResponse.json(events);
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 500 });
  }
}
