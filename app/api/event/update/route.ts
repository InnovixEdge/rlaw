import { NextRequest } from 'next/server';
import { google } from 'googleapis';
import fetch from 'node-fetch';

type CalendarEvent = {
  id: string;
  start?: string;
  end?: string;
  title?: string;
};

async function getTokensForUser(userId: string) {
  return { googleAccessToken: '', outlookAccessToken: '' }; // Replace with real logic
}

export async function PATCH(req: NextRequest) {
  const event: CalendarEvent = await req.json();
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(event.id);

  try {
    if (googleAccessToken) {
      const calendar = google.calendar({ version: 'v3', auth: googleAccessToken });
      await calendar.events.patch({
        calendarId: 'primary',
        eventId: event.id,
        requestBody: {
          summary: event.title,
          start: event.start ? { dateTime: event.start } : undefined,
          end: event.end ? { dateTime: event.end } : undefined,
        },
      });
    }

    if (outlookAccessToken) {
      await fetch(`https://graph.microsoft.com/v1.0/me/events/${event.id}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${outlookAccessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subject: event.title,
          start: event.start ? { dateTime: event.start, timeZone: 'UTC' } : undefined,
          end: event.end ? { dateTime: event.end, timeZone: 'UTC' } : undefined,
        }),
      });
    }

    return new Response(JSON.stringify({ success: true, event }), { status: 200 });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
