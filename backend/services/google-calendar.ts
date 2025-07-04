import { google } from 'googleapis';
import { kv } from '@vercel/kv';

export async function getGoogleCalendarEvents(userId: string) {
  const tokens = await kv.hgetall<{ googleAccessToken?: string }>(`tokens:${userId}`);
  if (!tokens?.googleAccessToken) throw new Error('No Google access token');

  const oauth2Client = new google.auth.OAuth2();
  oauth2Client.setCredentials({ access_token: tokens.googleAccessToken });

  const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
  const res = await calendar.events.list({
    calendarId: 'primary',
    timeMin: new Date().toISOString(),
    maxResults: 50,
    singleEvents: true,
    orderBy: 'startTime',
  });

  return res.data.items || [];
}
