import { NextRequest } from 'next/server';
import { google } from 'googleapis';
import fetch from 'node-fetch';

type DeletePayload = {
  id: string;
};

async function getTokensForUser(userId: string) {
  return { googleAccessToken: '', outlookAccessToken: '' }; // Replace with real logic
}

export async function DELETE(req: NextRequest) {
  const { id }: DeletePayload = await req.json();
  const { googleAccessToken, outlookAccessToken } = await getTokensForUser(id);

  try {
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

    return new Response(JSON.stringify({ success: true, id }), { status: 200 });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
