import { NextResponse } from 'next/server';
//import { getOutlookCalendarEvents } from '@/backend/services/outlook-calendar';

export async function GET() {
  try {
    const events = await getOutlookCalendarEvents('user123');
    return NextResponse.json(events);
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 500 });
  }
}
