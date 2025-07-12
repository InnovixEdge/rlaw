import { NextResponse } from 'next/server';

// Temporary fix - replace the missing function
async function getGoogleCalendarEvents(userId: string) {
  // For now, return mock data to fix the build
  return [
    {
      id: '1',
      summary: 'Sample Legal Event',
      start: { dateTime: new Date().toISOString() },
      end: { dateTime: new Date(Date.now() + 3600000).toISOString() }
    }
  ];
}

export async function GET() {
  try {
    const events = await getGoogleCalendarEvents('user123');
    return NextResponse.json(events);
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 500 });
  }
}
