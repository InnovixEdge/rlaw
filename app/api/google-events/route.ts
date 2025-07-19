// app/api/google-events/route.ts
import { NextResponse } from 'next/server';
import { google } from 'googleapis';

// Define the interface for Google calendar events
interface GoogleCalendarEvent {
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

// Google Calendar service function
async function getGoogleCalendarEvents(userId: string): Promise<GoogleCalendarEvent[]> {
  try {
    // Initialize Google Auth
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'http://localhost:3000/api/auth/callback'
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
    });

    const calendar = google.calendar({ version: 'v3', auth: oauth2Client });

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
    
    // Return mock data if API fails (for development/testing)
    return [
      {
        id: 'sample-1',
        summary: 'Sample Legal Consultation',
        description: 'Client meeting regarding contract review',
        start: {
          dateTime: new Date().toISOString(),
        },
        end: {
          dateTime: new Date(Date.now() + 3600000).toISOString(),
        },
        location: 'Law Office'
      },
      {
        id: 'sample-2',
        summary: 'Court Hearing - Case #12345',
        description: 'Motion hearing at county courthouse',
        start: {
          dateTime: new Date(Date.now() + 86400000).toISOString(), // tomorrow
        },
        end: {
          dateTime: new Date(Date.now() + 86400000 + 7200000).toISOString(), // tomorrow + 2 hours
        },
        location: 'County Courthouse, Room 204'
      }
    ];
  }
}

export async function GET() {
  try {
    const userId = 'user123'; // eventually dynamic
    const events = await getGoogleCalendarEvents(userId);
    
    return NextResponse.json({
      success: true,
      data: events,
      count: events.length,
      source: 'google',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Google Events API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch Google calendar events',
        source: 'google'
      },
      { status: 500 }
    );
  }
}

// Handle POST requests for creating events
export async function POST(request: Request) {
  try {
    const eventData = await request.json();
    
    // Initialize Google Auth
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'http://localhost:3000/api/auth/callback'
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN,
    });

    const calendar = google.calendar({ version: 'v3', auth: oauth2Client });

    const response = await calendar.events.insert({
      calendarId: 'primary',
      requestBody: {
        summary: eventData.summary,
        description: eventData.description,
        start: eventData.start,
        end: eventData.end,
        location: eventData.location,
        attendees: eventData.attendees,
      },
    });

    return NextResponse.json({
      success: true,
      data: response.data,
      source: 'google'
    }, { status: 201 });
  } catch (error) {
    console.error('Error creating Google calendar event:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create Google calendar event',
        source: 'google'
      },
      { status: 500 }
    );
  }
}
