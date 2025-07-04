import { NextResponse } from 'next/server';
import { getOutlookCalendarEvents } from '@/backend/services/outlook-calendar';

export async function GET() {
  const events = await getOutlookCalendarEvents('user123');
  return NextResponse.json(events);
}
