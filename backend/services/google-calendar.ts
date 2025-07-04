import { google } from 'googleapis';
import { kv } from '@vercel/kv';

export async function getGoogleCalendarEvents(userId: string) {
  const tokens = await kv.get<{ googleAccessToken?: string }>(`tokens:${userId}`);
  if (!tokens?.googleAccessToken) throw new Error('No Google access token found.');

  const calendar = google.calendar({ version: 'v3' });
  const res = await calendar.events.list({
    calendarId: 'primary',
    auth: tokens.googleAccessToken,
    timeMin: new Date().toISOString(),
    maxResults: 10,
    singleEvents: true,
    orderBy: 'startTime',
  });

  return res.data.items || [];
}
