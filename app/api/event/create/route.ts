import { NextRequest } from 'next/server';
import { google } from 'googleapis';
import fetch from 'node-fetch';

type CalendarEvent = {
  id: string;
  start: string;
  end: string;
  title: string;
};

async function getTokensForUser(userId: string) {
  return { googleAccessToken: '', outlookAccessToken: '' }; // Replace with real token retrieval
}

export async function POST(req: NextRequest) {
  const event: CalendarEvent = await req.json();
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(event.id);

  try {
    // Google Calendar
    if (googleAccessToken) {
      const calendar = google.calendar({ version: 'v3', auth: googleAccessToken });
      await calendar.events.insert({
        calendarId: 'primary',
        requestBody: {
          summary: event.title,
          start: { dateTime: event.start },
          end: { dateTime: event.end },
        },
      });
    }

    // Outlook Calendar
    if (outlookAccessToken) {
      await fetch('https://graph.microsoft.com/v1.0/me/events', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${outlookAccessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          subject: event.title,
          start: { dateTime: event.start, timeZone: 'UTC' },
          end: { dateTime: event.end, timeZone: 'UTC' },
        }),
      });
    }

    return new Response(JSON.stringify({ success: true, event }), { status: 200 });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
