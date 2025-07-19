// app/api/outlook-events/route.ts
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
  isAllDay?: boolean;
  importance?: string;
  categories?: string[];
}

// Outlook Calendar service function
async function getOutlookCalendarEvents(userId: string): Promise<OutlookCalendarEvent[]> {
  try {
    // Check if Microsoft access token is configured
    const accessToken = process.env.MICROSOFT_ACCESS_TOKEN;
    
    if (!accessToken || accessToken === 'NOT_CONFIGURED_YET' || accessToken === 'placeholder_microsoft_access_token_not_set') {
      console.log('Microsoft access token not configured, returning mock data');
      throw new Error('Microsoft access token not configured');
    }
    
    // Microsoft Graph API endpoint for calendar events
    const response = await fetch('https://graph.microsoft.com/v1.0/me/events?$top=50&$orderby=start/dateTime', {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Microsoft Graph API error: ${response.status} - ${response.statusText}`);
    }

    const data = await response.json();
    
    // Transform Microsoft Graph events to our format
    return data.value?.map((event: any) => ({
      id: event.id,
      subject: event.subject || 'No Title',
      body: event.body ? {
        content: event.body.content || '',
        contentType: event.body.contentType || 'text'
      } : undefined,
      start: {
        dateTime: event.start?.dateTime || new Date().toISOString(),
        timeZone: event.start?.timeZone || 'UTC'
      },
      end: {
        dateTime: event.end?.dateTime || new Date(Date.now() + 3600000).toISOString(),
        timeZone: event.end?.timeZone || 'UTC'
      },
      attendees: event.attendees?.map((attendee: any) => ({
        emailAddress: {
          address: attendee.emailAddress?.address || '',
          name: attendee.emailAddress?.name || ''
        },
        status: {
          response: attendee.status?.response || 'none'
        }
      })) || [],
      location: event.location?.displayName ? {
        displayName: event.location.displayName
      } : undefined,
      isAllDay: event.isAllDay || false,
      importance: event.importance || 'normal',
      categories: event.categories || []
    })) || [];
  } catch (error) {
    console.error('Error fetching Outlook Calendar events:', error);
    
    // Return mock data if API fails (for development/testing)
    return [
      {
        id: 'outlook-sample-1',
        subject: 'Legal Case Review - Smith vs. Johnson',
        body: {
          content: 'Quarterly review of ongoing litigation case. Review discovery documents and prepare next steps.',
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
        location: {
          displayName: 'Conference Room A'
        },
        importance: 'high',
        categories: ['Legal', 'Case Review']
      },
      {
        id: 'outlook-sample-2',
        subject: 'Client Deposition - Estate Planning',
        body: {
          content: 'Deposition for estate planning client. Witness testimony regarding will execution.',
          contentType: 'text'
        },
        start: {
          dateTime: new Date(Date.now() + 86400000).toISOString(), // tomorrow
          timeZone: 'UTC'
        },
        end: {
          dateTime: new Date(Date.now() + 86400000 + 10800000).toISOString(), // tomorrow + 3 hours
          timeZone: 'UTC'
        },
        attendees: [
          {
            emailAddress: {
              address: 'client@example.com',
              name: 'John Client'
            },
            status: {
              response: 'accepted'
            }
          }
        ],
        location: {
          displayName: 'Law Office - Deposition Room'
        },
        importance: 'high',
        categories: ['Deposition', 'Estate Planning']
      },
      {
        id: 'outlook-sample-3',
        subject: 'Filing Deadline - Motion for Summary Judgment',
        body: {
          content: 'Deadline to file motion for summary judgment in Case #2024-CV-1234',
          contentType: 'text'
        },
        start: {
          dateTime: new Date(Date.now() + 172800000).toISOString(), // day after tomorrow
          timeZone: 'UTC'
        },
        end: {
          dateTime: new Date(Date.now() + 172800000 + 3600000).toISOString(), // day after tomorrow + 1 hour
          timeZone: 'UTC'
        },
        importance: 'high',
        categories: ['Deadline', 'Filing']
      }
    ];
  }
}

export async function GET() {
  try {
    const userId = 'user123';
    const events = await getOutlookCalendarEvents(userId);
    
    return NextResponse.json({
      success: true,
      data: events,
      count: events.length,
      source: 'outlook',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Outlook Events API error:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch Outlook calendar events',
        source: 'outlook'
      },
      { status: 500 }
    );
  }
}

// Handle POST requests for creating events
export async function POST(request: Request) {
  try {
    const eventData = await request.json();
    
    const accessToken = process.env.MICROSOFT_ACCESS_TOKEN;
    
    if (!accessToken || accessToken === 'NOT_CONFIGURED_YET' || accessToken === 'placeholder_microsoft_access_token_not_set') {
      throw new Error('Microsoft access token not configured');
    }

    const response = await fetch('https://graph.microsoft.com/v1.0/me/events', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        subject: eventData.subject,
        body: eventData.body,
        start: eventData.start,
        end: eventData.end,
        location: eventData.location,
        attendees: eventData.attendees,
        importance: eventData.importance || 'normal',
        categories: eventData.categories || []
      }),
    });

    if (!response.ok) {
      throw new Error(`Microsoft Graph API error: ${response.status} - ${response.statusText}`);
    }

    const newEvent = await response.json();

    return NextResponse.json({
      success: true,
      data: newEvent,
      source: 'outlook'
    }, { status: 201 });
  } catch (error) {
    console.error('Error creating Outlook calendar event:', error);
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create Outlook calendar event',
        source: 'outlook'
      },
      { status: 500 }
    );
  }
}
