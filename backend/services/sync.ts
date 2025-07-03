import { google } from 'googleapis';
import fetch from 'node-fetch';
import dayjs from 'dayjs';

// In a real application these tokens would be stored in a database along with
// refresh logic. For this example they are fetched from a placeholder helper.
async function getTokensForUser(userId: string) {
  // TODO: replace with persistent storage
  return { googleAccessToken: '', outlookAccessToken: '' };
}

// Placeholder interfaces for event and availability blocks
interface CalendarEvent {
  id: string;
  start: string; // ISO datetime
  end: string;   // ISO datetime
  title: string;
}

interface AvailabilitySlot {
  start: string;
  end: string;
}

/**
 * Fetch events from Google Calendar for a single user.
 * In production you should store and refresh OAuth tokens securely.
 */
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

/**
 * Fetch events from Outlook calendar using Microsoft Graph.
 */
async function fetchOutlookEvents(userId: string, accessToken: string, start: string, end: string): Promise<CalendarEvent[]> {
  const response = await fetch(`https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=${start}&endDateTime=${end}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();
  return (data.value || []).map((e: any) => ({
    id: e.id,
    start: e.start.dateTime,
    end: e.end.dateTime,
    title: e.subject,
  }));
}

/**
 * Merge events from multiple calendars and compute free slots.
 * This implementation is simplified for demonstration.
 */
export async function fetchAvailability(userIds: string[], start: string, end: string): Promise<AvailabilitySlot[]> {
  const events: CalendarEvent[] = [];

  for (const id of userIds) {
    const { googleAccessToken, outlookAccessToken } = await getTokensForUser(id);

    events.push(
      ...(await fetchGoogleEvents(id, googleAccessToken, start, end)),
      ...(await fetchOutlookEvents(id, outlookAccessToken, start, end))
    );
  }

  // Sort events chronologically
  events.sort((a, b) => dayjs(a.start).unix() - dayjs(b.start).unix());

  const slots: AvailabilitySlot[] = [];
  let cursor = dayjs(start);
  // Walk through each event chronologically and record any gaps between the
  // current cursor and the start of the next event. Each gap represents an
  // available slot for scheduling.
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
  return slots;
}

/** Create a calendar event on both Google and Outlook. */
export async function createEvent(event: CalendarEvent) {
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(event.id);

  // Insert event into Google Calendar
  if (googleAccessToken) {
    const calendar = google.calendar({ version: 'v3', auth: googleAccessToken });
    await calendar.events.insert({ calendarId: 'primary', requestBody: {
      summary: event.title,
      start: { dateTime: event.start },
      end: { dateTime: event.end },
    }});
  }

  // Insert event into Outlook calendar via Microsoft Graph
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

  return event;
}

export async function updateEvent(id: string, event: Partial<CalendarEvent>) {
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(id);

  if (googleAccessToken) {
    const calendar = google.calendar({ version: 'v3', auth: googleAccessToken });
    await calendar.events.patch({
      calendarId: 'primary',
      eventId: id,
      requestBody: {
        summary: event.title,
        start: event.start ? { dateTime: event.start } : undefined,
        end: event.end ? { dateTime: event.end } : undefined,
      },
    });
  }

  if (outlookAccessToken) {
    await fetch(`https://graph.microsoft.com/v1.0/me/events/${id}`, {
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

  return { id, ...event };
}

export async function deleteEvent(id: string) {
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(id);

  if (googleAccessToken) {
    const calendar = google.calendar({ version: 'v3', auth: googleAccessToken });
    await calendar.events.delete({ calendarId: 'primary', eventId: id });
  }

  if (outlookAccessToken) {
    await fetch(`https://graph.microsoft.com/v1.0/me/events/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${outlookAccessToken}` },
    });
  }
}
