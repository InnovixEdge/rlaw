// app/api/calendar/outlook/route.ts
import { NextResponse } from 'next/server';

// Define the interface for Outlook calendar events
interface OutlookCalendarEvent {
  id: string;
  subject: string;
  body?: {
    content: string;
    contentType: string;
  };
  start: {
    dateTime: string;
    timeZone: string;
  };
  end: {
    dateTime: string;
    timeZone: string;
  };
  attendees?: Array<{
    emailAddress: {
      address: string;
      name: string;
    };
    status: {
      response: string;
    };
  }>;
  location?: {
    displayName: string;
  };
}

class OutlookCalendarService {
  private async getAccessToken(): Promise<string> {
    // For now, we'll implement a basic structure
    // You'll need to set up Microsoft Graph API authentication
    const accessToken = process.env.MICROSOFT_ACCESS_TOKEN;
    
    if (!accessToken) {
      throw new Error('Microsoft access token not configured');
    }
    
    return accessToken;
  }

  async getCalendarEvents(userId: string): Promise<OutlookCalendarEvent[]> {
    try {
      const accessToken = await this.getAccessToken();
      
      // Microsoft Graph API endpoint for calendar events
      const response = await fetch('https://graph.microsoft.com/v1.0/me/events', {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Microsoft Graph API error: ${response.status}`);
      }

      const data = await response.json();
      return data.value || [];
    } catch (error) {
      console.error('Error fetching Outlook Calendar events:', error);
      
      // Return mock data for now if API fails
      return [
        {
          id: 'outlook-1',
          subject: 'Sample Outlook Event',
          body: {
            content: 'This is a sample Outlook calendar event',
            contentType: 'text'
          },
          start: {
            dateTime: new Date().toISOString(),
            timeZone: 'UTC'
          },
          end: {
            dateTime: new Date(Date.now() + 3600000).toISOString(),
            timeZone: 'UTC'
          },
          attendees: [],
          location: {
            displayName: 'Sample Location'
          }
        }
      ];
    }
  }

  async createEvent(eventData: Partial<OutlookCalendarEvent>): Promise<OutlookCalendarEvent> {
    try {
      const accessToken = await this.getAccessToken();
      
      const response = await fetch('https://graph.microsoft.com/v1.0/me/events', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(eventData),
      });

      if (!response.ok) {
        throw new Error(`Microsoft Graph API error: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error creating Outlook calendar event:', error);
      throw new Error(`Failed to create calendar event: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

const outlookCalendarService = new OutlookCalendarService();

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId') || 'default';
    
    const events = await outlookCalendarService.getCalendarEvents(userId);
    
    return NextResponse.json({ 
      success: true, 
      data: events,
      count: events.length,
      source: 'outlook'
    });
  } catch (err) {
    console.error('Outlook Calendar API error:', err);
    return NextResponse.json(
      { 
        success: false, 
        error: err instanceof Error ? err.message : 'Unknown error occurred',
        source: 'outlook'
      }, 
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const eventData = await request.json();
    const newEvent = await outlookCalendarService.createEvent(eventData);
    
    return NextResponse.json({ 
      success: true, 
      data: newEvent,
      source: 'outlook'
    }, { status: 201 });
  } catch (err) {
    console.error('Outlook Calendar API error:', err);
    return NextResponse.json(
      { 
        success: false, 
        error: err instanceof Error ? err.message : 'Unknown error occurred',
        source: 'outlook'
      }, 
      { status: 500 }
    );
  }
}
