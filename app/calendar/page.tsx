'use client'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

// Staff member definitions
const STAFF_MEMBERS = [
  { id: 'lee', name: 'Attorney Lee', color: '#10b981' },      // Green
  { id: 'smith', name: 'Attorney Smith', color: '#3b82f6' }, // Blue  
  { id: 'jones', name: 'Attorney Jones', color: '#8b5cf6' }, // Purple
  { id: 'davis', name: 'Attorney Davis', color: '#f59e0b' }, // Orange
]

// Time slot templates
const SLOT_TEMPLATES = [
  { id: 'consultation', name: 'Initial Consultation', duration: 60, title: 'Available Initial Consultation' },
  { id: 'follow-up', name: 'Follow-up Meeting', duration: 30, title: 'Available Follow-up' },
  { id: 'court-prep', name: 'Court Prep Session', duration: 90, title: 'Available Court Prep' },
  { id: 'document-review', name: 'Document Review', duration: 45, title: 'Available Document Review' },
  { id: 'custom', name: 'Custom Duration', duration: 30, title: 'Available Slot' }
]

interface CalendarEvent {
  title: string
  start: string | Date
  end: string | Date
  staff?: string | null
  type?: 'available' | 'booked' | 'meeting' | 'other'
  [key: string]: any
}

export default function CalendarPage() {
  const [view, setView] = useState(Views.MONTH)
  
  // Enhanced mock data with staff assignments
  const [events, setEvents] = useState<CalendarEvent[]>([
    {
      title: 'Available Consultation Slot',
      start: new Date(2025, 6, 10, 9, 0),
      end: new Date(2025, 6, 10, 10, 0),
      staff: 'lee',
      type: 'available'
    },
    {
      title: 'Available Legal Review',
      start: new Date(2025, 6, 11, 14, 0),
      end: new Date(2025, 6, 11, 15, 0),
      staff: 'smith',
      type: 'available'
    },
    {
      title: 'Client Meeting - John Doe',
      start: new Date(2025, 6, 12, 10, 0),
      end: new Date(2025, 6, 12, 11, 0),
      staff: 'lee',
      type: 'booked'
    },
    {
      title: 'Available Court Prep Session',
      start: new Date(2025, 6, 13, 13, 0),
      end: new Date(2025, 6, 13, 14, 30),
      staff: 'jones',
      type: 'available'
    },
    {
      title: 'Team Meeting',
      start: new Date(2025, 6, 9, 15, 0),
      end: new Date(2025, 6, 9, 16, 0),
      staff: null,
      type: 'meeting'
    },
    {
      title: 'Client Consultation - Jane Smith',
      start: new Date(2025, 6, 14, 11, 0),
      end: new Date(2025, 6, 14, 12, 0),
      staff: 'davis',
      type: 'booked'
    }
  ])
  
  const [showAvailableOnly, setShowAvailableOnly] = useState(false)
  const [selectedStaff, setSelectedStaff] = useState('all')
  const [showForm, setShowForm] = useState(false)
  const [showBulkForm, setShowBulkForm] = useState(false)
  
  const [formData, setFormData] = useState({
    title: '',
    start: '',
    end: '',
    staff: 'lee',
    type: 'available'
  })

  const [bulkFormData, setBulkFormData] = useState({
    staff: 'lee',
    template: 'consultation',
    customDuration: 30,
    startDate: '',
    endDate: '',
    startTime: '09:00',
    endTime: '17:00',
    recurring: 'none', // none, daily, weekly
    weekdays: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
    excludeWeekends: true
  })

  // Filter events based on toggles
  const filteredEvents = events.filter(event => {
    if (showAvailableOnly && event.type !== 'available') {
      return false
    }
    if (selectedStaff !== 'all' && event.staff !== selectedStaff) {
      return false
    }
    return true
  })

  // Get staff member info
  const getStaffInfo = (staffId: string | null | undefined) => {
    if (!staffId) return null
    return STAFF_MEMBERS.find(s => s.id === staffId)
  }

  function eventStyleGetter(event: CalendarEvent) {
    const staffInfo = getStaffInfo(event.staff)
    
    if (staffInfo) {
      return {
        style: {
          backgroundColor: staffInfo.color,
          color: 'white',
          fontWeight: '500',
          border: event.type === 'available' ? '2px solid #fff' : 'none'
        }
      }
    }
    
    return {
      style: {
        backgroundColor: '#6b7280',
        color: 'white',
        fontWeight: '500'
      }
    }
  }

  const handleSubmit = async () => {
    const newEvent: CalendarEvent = {
      title: formData.title,
      start: new Date(formData.start),
      end: new Date(formData.end),
      staff: formData.staff,
      type: formData.type as 'available' | 'booked' | 'meeting' | 'other'
    }
    
    setEvents([...events, newEvent])
    setShowForm(false)
    setFormData({ title: '', start: '', end: '', staff: 'lee', type: 'available' })
  }

  const handleBulkSubmit = async () => {
    const template = SLOT_TEMPLATES.find(t => t.id === bulkFormData.template)
    const duration = bulkFormData.template === 'custom' ? bulkFormData.customDuration : template?.duration || 30
    
    const newEvents: CalendarEvent[] = []
    const startDate = new Date(bulkFormData.startDate)
    const endDate = new Date(bulkFormData.endDate)
    
    // Parse time strings
    const [startHour, startMin] = bulkFormData.startTime.split(':').map(Number)
    const [endHour, endMin] = bulkFormData.endTime.split(':').map(Number)
    
    for (let date = new Date(startDate); date <= endDate; date.setDate(date.getDate() + 1)) {
      // Skip weekends if excluded
      if (bulkFormData.excludeWeekends && (date.getDay() === 0 || date.getDay() === 6)) {
        continue
      }
      
      // Check if this weekday is selected
      const weekdayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
      const currentWeekday = weekdayNames[date.getDay()]
      if (!bulkFormData.weekdays.includes(currentWeekday)) {
        continue
      }
      
      // Create slots for this day
      let currentTime = startHour * 60 + startMin // minutes from midnight
      const endTime = endHour * 60 + endMin
      
      while (currentTime + duration <= endTime) {
        const slotStart = new Date(date)
        slotStart.setHours(Math.floor(currentTime / 60), currentTime % 60, 0, 0)
        
        const slotEnd = new Date(slotStart)
        slotEnd.setMinutes(slotEnd.getMinutes() + duration)
        
        newEvents.push({
          title: template?.title || 'Available Slot',
          start: slotStart,
          end: slotEnd,
          staff: bulkFormData.staff,
          type: 'available'
        })
        
        currentTime += duration
      }
    }
    
    setEvents([...events, ...newEvents])
    setShowBulkForm(false)
    alert(`Created ${newEvents.length} availability slots!`)
  }

  const handleSelectEvent = async (event: CalendarEvent) => {
    const staffInfo = getStaffInfo(event.staff)
    const staffName = staffInfo ? staffInfo.name : 'Team'
    
    if (event.type === 'available') {
      const confirm = window.confirm(
        `Book this slot with ${staffName}?\n\n${event.title}\n${moment(event.start).format('MMMM Do, h:mm A')} - ${moment(event.end).format('h:mm A')}`
      )
      if (!confirm) return
      
      const updatedEvents = events.map(e => 
        e === event 
          ? { ...e, title: `Client Meeting - New Client`, type: 'booked' as const }
          : e
      )
      setEvents(updatedEvents)
    } else {
      alert(`This is a ${event.type} event with ${staffName}: ${event.title}`)
    }
  }

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Firm Calendar</h1>
      
      {/* Status banner */}
      <div className="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
        <p className="text-sm text-yellow-800">
          📋 <strong>Demo Mode:</strong> Using mock data with staff assignments. Connect your Google Calendar API to sync real events.
        </p>
      </div>
      
      {/* Control buttons */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          onClick={() => setShowForm(true)}
        >
          Add Single Event
        </button>
        
        <button
          className="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 font-medium"
          onClick={() => setShowBulkForm(true)}
        >
          ⚡ Bulk Create Availability
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
        
        <select
          className="px-4 py-2 border border-gray-300 rounded-md bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={selectedStaff}
          onChange={(e) => setSelectedStaff(e.target.value)}
        >
          <option value="all">All Staff</option>
          {STAFF_MEMBERS.map(staff => (
            <option key={staff.id} value={staff.id}>
              {staff.name}
            </option>
          ))}
        </select>
      </div>

      {/* Staff Legend */}
      <div className="mb-4 p-3 bg-gray-50 rounded-lg">
        <h3 className="font-semibold mb-2">Staff Legend:</h3>
        <div className="flex flex-wrap gap-4 text-sm mb-2">
          {STAFF_MEMBERS.map(staff => (
            <div key={staff.id} className="flex items-center gap-2">
              <div 
                className="w-4 h-4 rounded" 
                style={{ backgroundColor: staff.color }}
              ></div>
              <span>{staff.name}</span>
            </div>
          ))}
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 bg-gray-500 rounded"></div>
            <span>Team Events</span>
          </div>
        </div>
        <div className="text-xs text-gray-600 flex gap-4">
          <span>📍 <strong>Available slots</strong> have white borders</span>
          <span>📊 Showing {filteredEvents.length} events 
            {selectedStaff !== 'all' && ` for ${getStaffInfo(selectedStaff)?.name}`}
            {showAvailableOnly && ' (available only)'}
          </span>
        </div>
      </div>

      {/* Single Event Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white p-6 rounded-lg w-full max-w-md mx-4">
            <h2 className="text-lg font-semibold mb-4">Add Single Event</h2>
            
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
              
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Staff Member
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={formData.staff}
                    onChange={(e) => setFormData({ ...formData, staff: e.target.value })}
                  >
                    {STAFF_MEMBERS.map(staff => (
                      <option key={staff.id} value={staff.id}>
                        {staff.name}
                      </option>
                    ))}
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Event Type
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={formData.type}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  >
                    <option value="available">Available Slot</option>
                    <option value="booked">Booked</option>
                    <option value="meeting">Meeting</option>
                    <option value="other">Other</option>
                  </select>
                </div>
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

      {/* Bulk Create Form Modal */}
      {showBulkForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white p-6 rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold mb-6 text-purple-800">⚡ Bulk Create Availability Slots</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Left Column */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Staff Member
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    value={bulkFormData.staff}
                    onChange={(e) => setBulkFormData({ ...bulkFormData, staff: e.target.value })}
                  >
                    {STAFF_MEMBERS.map(staff => (
                      <option key={staff.id} value={staff.id}>
                        {staff.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Slot Template
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                    value={bulkFormData.template}
                    onChange={(e) => setBulkFormData({ ...bulkFormData, template: e.target.value })}
                  >
                    {SLOT_TEMPLATES.map(template => (
                      <option key={template.id} value={template.id}>
                        {template.name} ({template.duration} min)
                      </option>
                    ))}
                  </select>
                </div>

                {bulkFormData.template === 'custom' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Custom Duration (minutes)
                    </label>
                    <input
                      type="number"
                      min="15"
                      max="240"
                      step="15"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                      value={bulkFormData.customDuration}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, customDuration: parseInt(e.target.value) })}
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Start Date
                    </label>
                    <input
                      type="date"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                      value={bulkFormData.startDate}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, startDate: e.target.value })}
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      End Date
                    </label>
                    <input
                      type="date"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                      value={bulkFormData.endDate}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, endDate: e.target.value })}
                    />
                  </div>
                </div>
              </div>

              {/* Right Column */}
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Start Time
                    </label>
                    <input
                      type="time"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                      value={bulkFormData.startTime}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, startTime: e.target.value })}
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      End Time
                    </label>
                    <input
                      type="time"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-500"
                      value={bulkFormData.endTime}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, endTime: e.target.value })}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Days of Week
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((day) => (
                      <label key={day} className="flex items-center">
                        <input
                          type="checkbox"
                          className="mr-2"
                          checked={bulkFormData.weekdays.includes(day.toLowerCase())}
                          onChange={(e) => {
                            const dayLower = day.toLowerCase()
                            if (e.target.checked) {
                              setBulkFormData({
                                ...bulkFormData,
                                weekdays: [...bulkFormData.weekdays, dayLower]
                              })
                            } else {
                              setBulkFormData({
                                ...bulkFormData,
                                weekdays: bulkFormData.weekdays.filter(d => d !== dayLower)
                              })
                            }
                          }}
                        />
                        <span className="text-sm">{day}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-gray-50 rounded-md">
                  <h4 className="font-medium text-sm mb-2">Preview:</h4>
                  <div className="text-xs text-gray-600 space-y-1">
                    <div>📅 Date Range: {bulkFormData.startDate || 'Not set'} to {bulkFormData.endDate || 'Not set'}</div>
                    <div>⏰ Time: {bulkFormData.startTime} - {bulkFormData.endTime}</div>
                    <div>👤 Staff: {STAFF_MEMBERS.find(s => s.id === bulkFormData.staff)?.name}</div>
                    <div>📝 Template: {SLOT_TEMPLATES.find(t => t.id === bulkFormData.template)?.name}</div>
                    <div>📆 Days: {bulkFormData.weekdays.join(', ')}</div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t">
              <button
                className="px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-50"
                onClick={() => setShowBulkForm(false)}
              >
                Cancel
              </button>
              <button
                className="px-6 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 font-medium"
                onClick={handleBulkSubmit}
                disabled={!bulkFormData.startDate || !bulkFormData.endDate}
              >
                Create Slots
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
