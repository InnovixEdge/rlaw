import { kv } from '@vercel/kv';

export async function getOutlookCalendarEvents(userId: string) {
  const tokens = await kv.get<{ outlookAccessToken?: string }>(`tokens:${userId}`);
  if (!tokens?.outlookAccessToken) throw new Error('No Outlook access token found.');

  const response = await fetch('https://graph.microsoft.com/v1.0/me/events', {
    headers: {
      Authorization: `Bearer ${tokens.outlookAccessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Outlook events');
  }

  const data = await response.json();
  return data.value || [];
}
