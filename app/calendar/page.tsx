'use client'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useEffect, useState } from 'react'
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogDescription,
  DialogFooter,
  DialogTrigger,
  DialogClose
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

const localizer = momentLocalizer(moment)

export default function CalendarPage() {
  const [view, setView] = useState(Views.MONTH)
  const [events, setEvents] = useState([])
  const [showAvailableOnly, setShowAvailableOnly] = useState(false)
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

  // Filter events based on availability toggle
  const filteredEvents = showAvailableOnly 
    ? events.filter(event => event.title?.toLowerCase().includes('available') || event.title?.toLowerCase().includes('open'))
    : events

  function eventStyleGetter(event: any) {
    // Color coding based on event type
    const title = event.title?.toLowerCase() || ''
    
    if (title.includes('available') || title.includes('open')) {
      return {
        style: {
          backgroundColor: '#10b981', // Green for available slots
          color: 'white',
          fontWeight: '500'
        }
      }
    } else if (title.includes('booked') || title.includes('appointment')) {
      return {
        style: {
          backgroundColor: '#ef4444', // Red for booked slots
          color: 'white',
          fontWeight: '500'
        }
      }
    }
    
    return {
      style: {
        backgroundColor: '#38bdf8', // Default blue
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
    setFormData({ title: '', start: '', end: '' })
    
    // Refresh events
    const updated = await fetch('/api/google-events').then(res => res.json())
    setEvents(updated)
  }

  const handleSelectEvent = async (event: any) => {
    const isAvailable = event.title?.toLowerCase().includes('available') || event.title?.toLowerCase().includes('open')
    
    if (isAvailable) {
      const confirm = window.confirm(`Book this available slot: ${event.title}?`)
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
      
      // Refresh events
      const updated = await fetch('/api/google-events').then(res => res.json())
      setEvents(updated)
    } else {
      alert('This slot is already booked or unavailable.')
    }
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>
      
      {/* Action buttons */}
      <div className="flex gap-2 mb-4">
        <Dialog>
          <DialogTrigger asChild>
            <Button>Add Event</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New Event</DialogTitle>
              <DialogDescription>
                Create a new calendar event or appointment slot.
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4">
              <div>
                <Label htmlFor="title">Event Title</Label>
                <Input
                  id="title"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="e.g., Available Consultation Slot"
                />
              </div>
              
              <div>
                <Label htmlFor="start">Start Time</Label>
                <Input
                  id="start"
                  type="datetime-local"
                  value={formData.start}
                  onChange={(e) => setFormData({ ...formData, start: e.target.value })}
                />
              </div>
              
              <div>
                <Label htmlFor="end">End Time</Label>
                <Input
                  id="end"
                  type="datetime-local"
                  value={formData.end}
                  onChange={(e) => setFormData({ ...formData, end: e.target.value })}
                />
              </div>
            </div>
            
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <DialogClose asChild>
                <Button onClick={handleSubmit}>Add Event</Button>
              </DialogClose>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        
        {/* Availability toggle */}
        <Button 
          variant={showAvailableOnly ? "default" : "outline"}
          onClick={() => setShowAvailableOnly(!showAvailableOnly)}
        >
          {showAvailableOnly ? "Show All Events" : "Show Available Only"}
        </Button>
      </div>

      {/* Legend */}
      <div className="mb-4 p-3 bg-gray-50 rounded-lg">
        <h3 className="font-semibold mb-2">Legend:</h3>
        <div className="flex gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-green-500 rounded"></div>
            <span>Available Slots</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-red-500 rounded"></div>
            <span>Booked Appointments</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-blue-400 rounded"></div>
            <span>Other Events</span>
          </div>
        </div>
        <p className="text-xs text-gray-600 mt-1">
          {showAvailableOnly ? 
            `Showing ${filteredEvents.length} available slots` : 
            `Showing ${filteredEvents.length} total events`
          }
        </p>
      </div>

      {/* Calendar */}
      <Calendar
        localizer={localizer}
        events={filteredEvents.map(e => ({
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
