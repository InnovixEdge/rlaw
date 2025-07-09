'use client'

import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

const allEvents = [
  {
    id: 0,
    title: 'Consultation - Jane Doe',
    start: new Date(2025, 6, 10, 10, 0),
    end: new Date(2025, 6, 10, 11, 0),
    staff: 'Attorney Smith',
    available: false
  },
  {
    id: 1,
    title: 'Available Slot',
    start: new Date(2025, 6, 10, 11, 0),
    end: new Date(2025, 6, 10, 12, 0),
    staff: 'Attorney Smith',
    available: true
  },
  {
    id: 2,
    title: 'Available Slot',
    start: new Date(2025, 6, 11, 14, 0),
    end: new Date(2025, 6, 11, 15, 0),
    staff: 'Attorney Lee',
    available: true
  }
]

export default function CalendarPage() {
  const [view, setView] = useState(Views.MONTH)
  const [showAvailableOnly, setShowAvailableOnly] = useState(false)

  const filteredEvents = showAvailableOnly
    ? allEvents.filter((event) => event.available)
    : allEvents

  function eventStyleGetter(event: any) {
    const backgroundColor = event.available ? '#38bdf8' : '#f87171'
    const borderColor = event.staff === 'Attorney Lee' ? '#4ade80' : '#facc15'

    return {
      style: {
        backgroundColor,
        borderLeft: `4px solid ${borderColor}`,
        color: 'black',
        fontWeight: '500'
      }
    }
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>

      <label className="mb-4 inline-flex items-center space-x-2">
        <input
          type="checkbox"
          checked={showAvailableOnly}
          onChange={(e) => setShowAvailableOnly(e.target.checked)}
        />
        <span>Show Available Slots Only</span>
      </label>

      <Calendar
        localizer={localizer}
        events={filteredEvents}
        defaultView={view}
        views={['month', 'week', 'day']}
        startAccessor="start"
        endAccessor="end"
        style={{ height: 600 }}
        onView={(view) => setView(view)}
        eventPropGetter={eventStyleGetter}
      />
    </div>
  )
}
