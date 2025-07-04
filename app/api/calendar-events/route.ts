import { listGoogleEvents } from '@/backend/services/google-calendar';
import { listOutlookEvents } from '@/backend/services/outlook-calendar';
import { NextResponse } from 'next/server';

export async function GET() {
  const userId = 'user123'; // Use actual user ID logic

  const [googleEvents, outlookEvents] = await Promise.all([
    listGoogleEvents(userId),
    listOutlookEvents(userId),
  ]);

  return NextResponse.json({
    google: googleEvents,
    outlook: outlookEvents,
  });
}
