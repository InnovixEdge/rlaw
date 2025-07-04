import { listGoogleEvents } from '@/backend/services/google-calendar'
import { NextResponse } from 'next/server'

export async function GET() {
  try {
    const userId = 'user123' // eventually dynamic
    const events = await listGoogleEvents(userId)
    return NextResponse.json(events)
  } catch (error) {
    console.error('Google Events API error:', error)
    return NextResponse.json({ error: 'Failed to fetch Google calendar events' }, { status: 500 })
  }
}
