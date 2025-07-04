import { listGoogleEvents } from '@/backend/services/google-calendar';
import { listOutlookEvents } from '@/backend/services/outlook-calendar';
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const userId = 'user123'; // eventually replace with dynamic logic
    const [googleEvents, outlookEvents] = await Promise.all([
      listGoogleEvents(userId),
      listOutlookEvents(userId),
    ]);

    return NextResponse.json({ googleEvents, outlookEvents });
  } catch (error) {
    console.error('Calendar API error:', error);
    return NextResponse.json({ error: 'Failed to fetch calendar events' }, { status: 500 });
  }
}
