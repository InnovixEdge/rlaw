import { getOutlookCalendarEvents } from '@/backend/services/outlook-calendar'
import { NextResponse } from 'next/server'

export async function GET() {
  try {
    const userId = 'user123'
    const events = await getOutlookCalendarEvents(userId)
    return NextResponse.json(events)
  } catch (error) {
    console.error('Outlook Events API error:', error)
    return NextResponse.json({ error: 'Failed to fetch Outlook calendar events' }, { status: 500 })
  }
}
