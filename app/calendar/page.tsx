'use client'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

// Add a type for events
interface CalendarEvent {
  title: string
  start: string | Date
  end: string | Date
  [key: string]: any
}

export default function CalendarPage() {
  const [view, setView] = useState(Views.MONTH)
  // Mock data for testing - remove this when API is working
  const [events, setEvents] = useState<CalendarEvent[]>([
    {
      title: 'Available Consultation Slot',
      start: new Date(2025, 6, 10, 9, 0), // July 10, 9 AM
      end: new Date(2025, 6, 10, 10, 0)   // July 10, 10 AM
    },
    {
      title: 'Available Legal Review',
      start: new Date(2025, 6, 11, 14, 0), // July 11, 2 PM
      end: new Date(2025, 6, 11, 15, 0)    // July 11, 3 PM
    },
    {
      title: 'Booked Appointment - John Doe',
      start: new Date(2025, 6, 12, 10, 0), // July 12, 10 AM
      end: new Date(2025, 6, 12, 11, 0)    // July 12, 11 AM
    },
    {
      title: 'Team Meeting',
      start: new Date(2025, 6, 9, 15, 0),  // July 9, 3 PM
      end: new Date(2025, 6, 9, 16, 0)     // July 9, 4 PM
    }
  ])
  
  const [showAvailableOnly, setShowAvailableOnly] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    title: '',
    start: '',
    end: ''
  })

  // Filter events based on availability toggle
  const filteredEvents = showAvailableOnly 
    ? events.filter(event => event.title?.toLowerCase().includes('available') || event.title?.toLowerCase().includes('open'))
    : events

  function eventStyleGetter(event: CalendarEvent) {
    const title = event.title?.toLowerCase() || ''
    
    if (title.includes('available') || title.includes('open')) {
      return {
        style: {
          backgroundColor: '#10b981',
          color: 'white',
          fontWeight: '500'
        }
      }
    } else if (title.includes('booked') || title.includes('appointment')) {
      return {
        style: {
          backgroundColor: '#ef4444',
          color: 'white',
          fontWeight: '500'
        }
      }
    }
    
    return {
      style: {
        backgroundColor: '#38bdf8',
        color: 'black',
        fontWeight: '500'
      }
    }
  }

  const handleSubmit = async () => {
    // For now, just add to local state - replace with API call later
    const newEvent: CalendarEvent = {
      title: formData.title,
      start: new Date(formData.start),
      end: new Date(formData.end)
    }
    
    setEvents([...events, newEvent])
    setShowForm(false)
    setFormData({ title: '', start: '', end: '' })
    
    // TODO: Replace with actual API call
    // await fetch('/api/add-google-event', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify(formData)
    // })
  }

  const handleSelectEvent = async (event: CalendarEvent) => {
    const isAvailable = event.title?.toLowerCase().includes('available') || event.title?.toLowerCase().includes('open')
    
    if (isAvailable) {
      const confirm = window.confirm(`Book this available slot: ${event.title}?`)
      if (!confirm) return
      
      // For now, just update locally - replace with API call later
      const updatedEvents = events.map(e => 
        e === event 
          ? { ...e, title: 'Booked Appointment - New Client' }
          : e
      )
      setEvents(updatedEvents)
      
      // TODO: Replace with actual API call
      // await fetch('/api/add-google-event', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({
      //     title: 'Booked Appointment',
      //     start: event.start,
      //     end: event.end
      //   })
      // })
    } else {
      alert('This slot is already booked or unavailable.')
    }
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>
      
      {/* Status banner */}
      <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
        <p className="text-sm text-yellow-800">
          📋 <strong>Demo Mode:</strong> Using mock data. Connect your Google Calendar API to sync real events.
        </p>
      </div>
      
      {/* Action buttons */}
      <div className="flex gap-2 mb-4">
        <button
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          onClick={() => setShowForm(true)}
        >
          Add Event
        </button>
        
        <button
          className={`px-4 py-2 rounded-md ${showAvailableOnly 
            ? 'bg-green-600 text-white' 
            : 'border border-gray-300 bg-transparent hover:bg-gray-50'
          }`}
          onClick={() => setShowAvailableOnly(!showAvailableOnly)}
        >
          {showAvailableOnly ? "Show All Events" : "Show Available Only"}
        </button>
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

      {/* Simple form modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg w-full max-w-md mx-4">
            <h2 className="text-lg font-semibold mb-4">Add New Event</h2>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Event Title
                </label>
                <input
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  placeholder="e.g., Available Consultation Slot"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Start Time
                </label>
                <input
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  type="datetime-local"
                  value={formData.start}
                  onChange={(e) => setFormData({ ...formData, start: e.target.value })}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  End Time
                </label>
                <input
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  type="datetime-local"
                  value={formData.end}
                  onChange={(e) => setFormData({ ...formData, end: e.target.value })}
                />
              </div>
            </div>
            
            <div className="flex justify-end gap-2 mt-6">
              <button
                className="px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-50"
                onClick={() => setShowForm(false)}
              >
                Cancel
              </button>
              <button
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                onClick={handleSubmit}
              >
                Add Event
              </button>
            </div>
          </div>
        </div>
      )}

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
        onView={(v: any) => setView(v)}
        eventPropGetter={eventStyleGetter}
        onSelectEvent={handleSelectEvent}
      />
    </div>
  )
}
