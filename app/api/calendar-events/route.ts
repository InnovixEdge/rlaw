import { getGoogleCalendarEvents } from '@/backend/services/google-calendar';
import { getOutlookCalendarEvents } from '@/backend/services/outlook-calendar';
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const userId = 'user123'; // Replace with dynamic logic later if needed

    const [googleEvents, outlookEvents] = await Promise.all([
      getGoogleCalendarEvents(userId),
      getOutlookCalendarEvents(userId),
    ]);

    return NextResponse.json({ googleEvents, outlookEvents });
  } catch (error) {
    console.error('Calendar API error:', error);
    return NextResponse.json({ error: 'Failed to fetch calendar events' }, { status: 500 });
  }
}
