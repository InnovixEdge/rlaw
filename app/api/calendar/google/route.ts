// app/api/calendar/google/route.ts
import { NextResponse } from 'next/server';
import { google } from 'googleapis';

// Define the interface directly in this file
interface CalendarEvent {
  id: string;
  summary: string;
  description?: string;
  start: {
    dateTime?: string;
    date?: string;
  };
  end: {
    dateTime?: string;
    date?: string;
  };
  attendees?: Array<{
    email: string;
    responseStatus: string;
  }>;
  location?: string;
}

class GoogleCalendarService {
  private async getAuthClient() {
    // OAuth2 setup
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'http://localhost:3000/api/auth/callback'
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
    });

    return oauth2Client;
  }

  async getCalendarEvents(userId: string): Promise<CalendarEvent[]> {
    try {
      const auth = await this.getAuthClient();
      const calendar = google.calendar({ version: 'v3', auth });

      const response = await calendar.events.list({
        calendarId: 'primary',
        timeMin: new Date().toISOString(),
        timeMax: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
        maxResults: 50,
        singleEvents: true,
        orderBy: 'startTime',
      });

      return response.data.items?.map(event => ({
        id: event.id!,
        summary: event.summary || 'No Title',
        description: event.description || undefined,
        start: {
          dateTime: event.start?.dateTime || undefined,
          date: event.start?.date || undefined,
        },
        end: {
          dateTime: event.end?.dateTime || undefined,
          date: event.end?.date || undefined,
        },
        attendees: event.attendees?.map(attendee => ({
          email: attendee.email || '',
          responseStatus: attendee.responseStatus || 'needsAction',
        })) || undefined,
        location: event.location || undefined,
      })) || [];
    } catch (error) {
      console.error('Error fetching Google Calendar events:', error);
      throw new Error(`Failed to fetch calendar events: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async createEvent(eventData: Partial<CalendarEvent>): Promise<CalendarEvent> {
    try {
      const auth = await this.getAuthClient();
      const calendar = google.calendar({ version: 'v3', auth });

      const event = {
        summary: eventData.summary,
        description: eventData.description,
        start: eventData.start,
        end: eventData.end,
        attendees: eventData.attendees,
        location: eventData.location,
      };

      const response = await calendar.events.insert({
        calendarId: 'primary',
        requestBody: event,
      });

      return response.data as CalendarEvent;
    } catch (error) {
      console.error('Error creating calendar event:', error);
      throw new Error(`Failed to create calendar event: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

const calendarService = new GoogleCalendarService();

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId') || 'default';
    
    const events = await calendarService.getCalendarEvents(userId);
    
    return NextResponse.json({ 
      success: true, 
      data: events,
      count: events.length 
    });
  } catch (err) {
    console.error('Calendar API error:', err);
    return NextResponse.json(
      { 
        success: false, 
        error: err instanceof Error ? err.message : 'Unknown error occurred' 
      }, 
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const eventData = await request.json();
    const newEvent = await calendarService.createEvent(eventData);
    
    return NextResponse.json({ 
      success: true, 
      data: newEvent 
    }, { status: 201 });
  } catch (err) {
    console.error('Calendar API error:', err);
    return NextResponse.json(
      { 
        success: false, 
        error: err instanceof Error ? err.message : 'Unknown error occurred' 
      }, 
      { status: 500 }
    );
  }
}
