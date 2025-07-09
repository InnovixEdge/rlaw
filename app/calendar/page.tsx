'use client'

import { useEffect, useState } from 'react'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'

const localizer = momentLocalizer(moment)

interface Event {
  title: string
  start: Date
  end: Date
  staff?: string
  available?: boolean
}

export default function CalendarPage() {
  const [view, setView] = useState<typeof Views[keyof typeof Views]>(Views.MONTH)
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchEvents() {
      try {
        const res = await fetch('/api/google-events')
        if (!res.ok) {
          throw new Error('Network response was not ok')
        }
        const data = await res.json()

        // Transform fetched events to match the Event type
        const googleEvents = data.map((event: any) => ({
          title: event.summary,
          start: new Date(event.start.dateTime || event.start.date),
          end: new Date(event.end.dateTime || event.end.date),
          available: !event.summary, // or your own logic to identify availability
        }))

        setEvents(googleEvents)
      } catch (error) {
        console.error('Error fetching events:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchEvents()
  }, [])

  function eventStyleGetter(event: Event) {
    const backgroundColor = event.available ? '#38bdf8' : '#f87171'
    const borderColor = event.staff === 'Attorney Lee' ? '#4ade80' : '#facc15'

    return {
      style: {
        backgroundColor,
        borderLeft: `4px solid ${borderColor}`,
        color: 'black',
        fontWeight: '500',
      },
    }
  }

  if (loading) {
    return <div className="p-4">Loading calendar events...</div>
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>
      <Calendar
        localizer={localizer}
        events={events}
        defaultView={view}
        views={['month', 'week', 'day']}
        startAccessor="start"
        endAccessor="end"
        style={{ height: 600 }}
        onView={(view: typeof Views[keyof typeof Views]) => setView(view)}
        eventPropGetter={eventStyleGetter}
      />
    </div>
  )
}
