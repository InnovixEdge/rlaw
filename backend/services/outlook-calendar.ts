import fetch from 'node-fetch';
import { kv } from '@vercel/kv';

export async function listOutlookEvents(userId: string) {
  const tokens = await kv.hgetall<{ outlookAccessToken?: string }>(`tokens:${userId}`);
  if (!tokens?.outlookAccessToken) throw new Error('No Outlook access token');

  const res = await fetch('https://graph.microsoft.com/v1.0/me/calendar/events', {
    headers: {
      Authorization: `Bearer ${tokens.outlookAccessToken}`,
    },
  });

  if (!res.ok) throw new Error('Failed to fetch Outlook events');
  const data = await res.json() as { value?: any[] };
  return data.value ?? [];
}
