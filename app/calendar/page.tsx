'use client'

import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useEffect, useState } from 'react'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { formatISO } from 'date-fns'

const localizer = momentLocalizer(moment)

export default function CalendarPage() {
  const [view, setView] = useState(Views.MONTH)
  const [events, setEvents] = useState([])
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    title: '',
    start: '',
    end: ''
  })

  useEffect(() => {
    fetch('/api/google-events')
      .then(res => res.json())
      .then(data => setEvents(data))
  }, [])

  function eventStyleGetter(event: any) {
    return {
      style: {
        backgroundColor: '#38bdf8',
        color: 'black',
        fontWeight: '500'
      }
    }
  }

  const handleSubmit = async () => {
    await fetch('/api/add-google-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    })
    setShowForm(false)
    setFormData({ title: '', start: '', end: '' })
    const updated = await fetch('/api/google-events').then(res => res.json())
    setEvents(updated)
  }

  const handleSelectEvent = async (event: any) => {
    const confirm = window.confirm(`Book this slot: ${event.title}?`)
    if (!confirm) return

    await fetch('/api/add-google-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'Booked Appointment',
        start: event.start,
        end: event.end
      })
    })
    const updated = await fetch('/api/google-events').then(res => res.json())
    setEvents(updated)
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>

      <Button className="mb-4" onClick={() => setShowForm(true)}>
        Add Event
      </Button>

      {showForm && (
        <Dialog open={showForm} onOpenChange={setShowForm}>
          <div className="bg-white p-4 rounded shadow w-[300px]">
            <h2 className="font-semibold mb-2">Add Event</h2>
            <Label>Title</Label>
            <Input
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="mb-2"
            />
            <Label>Start</Label>
            <Input
              type="datetime-local"
              value={formData.start}
              onChange={(e) => setFormData({ ...formData, start: e.target.value })}
              className="mb-2"
            />
            <Label>End</Label>
            <Input
              type="datetime-local"
              value={formData.end}
              onChange={(e) => setFormData({ ...formData, end: e.target.value })}
              className="mb-2"
            />
            <Button onClick={handleSubmit}>Submit</Button>
          </div>
        </Dialog>
      )}

      <Calendar
        localizer={localizer}
        events={events.map(e => ({
          ...e,
          start: new Date(e.start),
          end: new Date(e.end)
        }))}
        defaultView={view}
        views={['month', 'week', 'day']}
        startAccessor="start"
        endAccessor="end"
        style={{ height: 600 }}
        onView={(v) => setView(v)}
        eventPropGetter={eventStyleGetter}
        onSelectEvent={handleSelectEvent}
      />
    </div>
  )
}
