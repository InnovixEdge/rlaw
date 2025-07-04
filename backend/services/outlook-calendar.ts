import fetch from 'node-fetch';
import { kv } from '@vercel/kv';
import { getTokensForUser } from './oauth-store';

export async function getOutlookCalendarEvents(userId: string) {
  const tokens = await kv.hgetall<{ outlookAccessToken?: string }>(`tokens:${userId}`);
  if (!tokens?.outlookAccessToken) throw new Error('No Outlook access token');

  const res = await fetch('https://graph.microsoft.com/v1.0/me/calendar/events', {
    headers: {
      Authorization: `Bearer ${tokens.outlookAccessToken}`,
    },
  });

  if (!res.ok) throw new Error('Failed to fetch Outlook events');

  const data: unknown = await res.json();
  if (typeof data !== 'object' || data === null || !('value' in data)) {
    throw new Error('Invalid response format from Outlook API');
  }

  return (data as { value: any[] }).value || [];
}
