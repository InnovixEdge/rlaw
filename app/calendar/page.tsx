'use client'

import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

const events = [
  {
    id: 0,
    title: 'Consultation - Jane Doe',
    start: new Date(2025, 6, 10, 10, 0),
    end: new Date(2025, 6, 10, 11, 0),
    staff: 'Attorney Smith'
  },
  {
    id: 1,
    title: 'Available Slot',
    start: new Date(2025, 6, 10, 11, 0),
    end: new Date(2025, 6, 10, 12, 0),
    staff: 'Attorney Smith',
    available: true
  }
]

type CalendarView = 'month' | 'week' | 'day'

export default function CalendarPage() {
  const [view, setView] = useState<CalendarView>('month')

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
        onView={(view: CalendarView) => setView(view)}
      />
    </div>
  )
}
