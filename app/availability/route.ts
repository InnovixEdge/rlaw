import { NextRequest } from 'next/server';
import dayjs from 'dayjs';
import { google } from 'googleapis';
import fetch from 'node-fetch';

interface CalendarEvent {
  id: string;
  start: string;
  end: string;
  title: string;
}

interface AvailabilitySlot {
  start: string;
  end: string;
}

async function getTokensForUser(userId: string) {
  return { googleAccessToken: '', outlookAccessToken: '' }; // Replace with real token logic
}

async function fetchGoogleEvents(userId: string, accessToken: string, start: string, end: string): Promise<CalendarEvent[]> {
  const calendar = google.calendar({ version: 'v3', auth: accessToken });
  const res = await calendar.events.list({
    calendarId: 'primary',
    timeMin: start,
    timeMax: end,
    singleEvents: true,
    orderBy: 'startTime',
  });
  return (res.data.items || []).map(e => ({
    id: e.id!,
    start: e.start?.dateTime || e.start?.date!,
    end: e.end?.dateTime || e.end?.date!,
    title: e.summary || '',
  }));
}

async function fetchOutlookEvents(userId: string, accessToken: string, start: string, end: string): Promise<CalendarEvent[]> {
  const response = await fetch(`https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=${start}&endDateTime=${end}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json() as { value: any[] };
  return (data.value || []).map(e => ({
    id: e.id,
    start: e.start.dateTime,
    end: e.end.dateTime,
    title: e.subject,
  }));
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const userIds = searchParams.getAll('userId');
  const start = searchParams.get('start');
  const end = searchParams.get('end');

  if (!userIds.length || !start || !end) {
    return new Response(JSON.stringify({ error: 'Missing query parameters' }), { status: 400 });
  }

  const events: CalendarEvent[] = [];

  for (const id of userIds) {
    const { googleAccessToken, outlookAccessToken } = await getTokensForUser(id);
    events.push(
      ...(await fetchGoogleEvents(id, googleAccessToken, start, end)),
      ...(await fetchOutlookEvents(id, outlookAccessToken, start, end))
    );
  }

  events.sort((a, b) => dayjs(a.start).unix() - dayjs(b.start).unix());

  const slots: AvailabilitySlot[] = [];
  let cursor = dayjs(start);

  for (const event of events) {
    const eventStart = dayjs(event.start);
    if (eventStart.isAfter(cursor)) {
      slots.push({ start: cursor.toISOString(), end: eventStart.toISOString() });
    }
    const eventEnd = dayjs(event.end);
    if (eventEnd.isAfter(cursor)) {
      cursor = eventEnd;
    }
  }

  if (cursor.isBefore(dayjs(end))) {
    slots.push({ start: cursor.toISOString(), end: dayjs(end).toISOString() });
  }

  return new Response(JSON.stringify(slots), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}
