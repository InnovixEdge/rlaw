'use client'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

// Modern, sophisticated color palette
const STAFF_MEMBERS = [
  { id: 'lee', name: 'Attorney Lee', color: '#10b981', gradient: 'from-emerald-400 to-emerald-600' },
  { id: 'smith', name: 'Attorney Smith', color: '#3b82f6', gradient: 'from-blue-400 to-blue-600' },
  { id: 'jones', name: 'Attorney Jones', color: '#8b5cf6', gradient: 'from-violet-400 to-violet-600' },
  { id: 'davis', name: 'Attorney Davis', color: '#f59e0b', gradient: 'from-amber-400 to-amber-600' },
]

const SLOT_TEMPLATES = [
  { id: 'consultation', name: 'Initial Consultation', duration: 60, title: 'Available Initial Consultation', icon: '👥' },
  { id: 'follow-up', name: 'Follow-up Meeting', duration: 30, title: 'Available Follow-up', icon: '🔄' },
  { id: 'court-prep', name: 'Court Prep Session', duration: 90, title: 'Available Court Prep', icon: '⚖️' },
  { id: 'document-review', name: 'Document Review', duration: 45, title: 'Available Document Review', icon: '📋' },
  { id: 'custom', name: 'Custom Duration', duration: 30, title: 'Available Slot', icon: '⏱️' }
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
    recurring: 'none',
    weekdays: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
    excludeWeekends: true
  })

  const filteredEvents = events.filter(event => {
    if (showAvailableOnly && event.type !== 'available') {
      return false
    }
    if (selectedStaff !== 'all' && event.staff !== selectedStaff) {
      return false
    }
    return true
  })

  const getStaffInfo = (staffId: string | null | undefined) => {
    if (!staffId) return null
    return STAFF_MEMBERS.find(s => s.id === staffId)
  }

  function eventStyleGetter(event: CalendarEvent) {
    const staffInfo = getStaffInfo(event.staff)
    
    if (staffInfo) {
      return {
        style: {
          background: event.type === 'available' 
            ? `linear-gradient(135deg, ${staffInfo.color}dd, ${staffInfo.color}bb)`
            : `linear-gradient(135deg, ${staffInfo.color}, ${staffInfo.color}dd)`,
          color: 'white',
          fontWeight: '600',
          border: event.type === 'available' ? '2px solid white' : 'none',
          borderRadius: '8px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          fontSize: '12px'
        }
      }
    }
    
    return {
      style: {
        background: 'linear-gradient(135deg, #6b7280, #4b5563)',
        color: 'white',
        fontWeight: '600',
        borderRadius: '8px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
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
    
    const [startHour, startMin] = bulkFormData.startTime.split(':').map(Number)
    const [endHour, endMin] = bulkFormData.endTime.split(':').map(Number)
    
    for (let date = new Date(startDate); date <= endDate; date.setDate(date.getDate() + 1)) {
      if (bulkFormData.excludeWeekends && (date.getDay() === 0 || date.getDay() === 6)) {
        continue
      }
      
      const weekdayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']
      const currentWeekday = weekdayNames[date.getDay()]
      if (!bulkFormData.weekdays.includes(currentWeekday)) {
        continue
      }
      
      let currentTime = startHour * 60 + startMin
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
    alert(`✨ Successfully created ${newEvents.length} availability slots!`)
  }

  const handleSelectEvent = async (event: CalendarEvent) => {
    const staffInfo = getStaffInfo(event.staff)
    const staffName = staffInfo ? staffInfo.name : 'Team'
    
    if (event.type === 'available') {
      const confirm = window.confirm(
        `💼 Book this slot with ${staffName}?\n\n${event.title}\n📅 ${moment(event.start).format('MMMM Do, h:mm A')} - ${moment(event.end).format('h:mm A')}`
      )
      if (!confirm) return
      
      const updatedEvents = events.map(e => 
        e === event 
          ? { ...e, title: `Client Meeting - New Client`, type: 'booked' as const }
          : e
      )
      setEvents(updatedEvents)
    } else {
      alert(`📋 This is a ${event.type} event with ${staffName}: ${event.title}`)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      <div className="container mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-gray-800 to-gray-600 bg-clip-text text-transparent mb-2">
            ⚖️ Firm Calendar
          </h1>
          <p className="text-gray-600 text-lg">Manage your legal practice with elegance and efficiency</p>
        </div>
        
        {/* Status Banner */}
        <div className="mb-6 p-4 bg-gradient-to-r from-amber-50 to-orange-50 border border-amber-200 rounded-2xl shadow-sm">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-amber-400 to-orange-500 rounded-full flex items-center justify-center">
              <span className="text-white text-lg">📋</span>
            </div>
            <div>
              <p className="text-amber-800 font-semibold">Demo Mode Active</p>
              <p className="text-amber-700 text-sm">Using mock data with staff assignments. Connect your Google Calendar API to sync real events.</p>
            </div>
          </div>
        </div>
        
        {/* Control Panel */}
        <div className="mb-6 p-6 bg-white/70 backdrop-blur-sm rounded-2xl shadow-lg border border-white/20">
          <div className="flex flex-wrap gap-3 mb-4">
            {/* Add Single Event Button */}
            <button
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 font-medium flex items-center gap-2"
              onClick={() => setShowForm(true)}
            >
              <span>➕</span>
              Add Single Event
            </button>
            
            {/* Bulk Create Button */}
            <button
              className="px-6 py-3 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-xl hover:from-purple-600 hover:to-purple-700 transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 font-medium flex items-center gap-2"
              onClick={() => setShowBulkForm(true)}
            >
              <span>⚡</span>
              Bulk Create Availability
            </button>
            
            {/* Availability Toggle */}
            <button
              className={`px-6 py-3 rounded-xl transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 font-medium flex items-center gap-2 ${showAvailableOnly 
                ? 'bg-gradient-to-r from-emerald-500 to-emerald-600 text-white' 
                : 'bg-white border-2 border-gray-200 text-gray-700 hover:border-gray-300'
              }`}
              onClick={() => setShowAvailableOnly(!showAvailableOnly)}
            >
              <span>{showAvailableOnly ? '✅' : '👁️'}</span>
              {showAvailableOnly ? "Show All Events" : "Show Available Only"}
            </button>
            
            {/* Staff Filter */}
            <select
              className="px-6 py-3 border-2 border-gray-200 rounded-xl bg-white/90 hover:border-gray-300 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 font-medium text-gray-700 shadow-lg"
              value={selectedStaff}
              onChange={(e) => setSelectedStaff(e.target.value)}
            >
              <option value="all">👥 All Staff</option>
              {STAFF_MEMBERS.map(staff => (
                <option key={staff.id} value={staff.id}>
                  {staff.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Beautiful Staff Legend */}
        <div className="mb-6 p-6 bg-white/70 backdrop-blur-sm rounded-2xl shadow-lg border border-white/20">
          <h3 className="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
            <span>🎨</span>
            Staff Color Legend
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-4">
            {STAFF_MEMBERS.map(staff => (
              <div key={staff.id} className="group">
                <div className="p-4 bg-white rounded-xl shadow-md hover:shadow-lg transition-all duration-300 transform hover:-translate-y-1 border border-gray-100">
                  <div className="flex items-center gap-3">
                    <div 
                      className="w-6 h-6 rounded-full shadow-lg border-2 border-white"
                      style={{ 
                        background: `linear-gradient(135deg, ${staff.color}, ${staff.color}dd)`
                      }}
                    ></div>
                    <div>
                      <span className="text-sm font-semibold text-gray-800 block">{staff.name}</span>
                      <span className="text-xs text-gray-500">Legal Professional</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
            <div className="group">
              <div className="p-4 bg-white rounded-xl shadow-md hover:shadow-lg transition-all duration-300 transform hover:-translate-y-1 border border-gray-100">
                <div className="flex items-center gap-3">
                  <div className="w-6 h-6 bg-gradient-to-br from-gray-400 to-gray-600 rounded-full shadow-lg border-2 border-white"></div>
                  <div>
                    <span className="text-sm font-semibold text-gray-800 block">Team Events</span>
                    <span className="text-xs text-gray-500">Group Activities</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="flex flex-wrap gap-6 text-sm text-gray-600 bg-gradient-to-r from-blue-50 to-indigo-50 p-4 rounded-xl">
            <div className="flex items-center gap-2">
              <span className="text-lg">💎</span>
              <span><strong>Available slots</strong> have white borders and subtle transparency</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-lg">📊</span>
              <span>Displaying {filteredEvents.length} events 
                {selectedStaff !== 'all' && ` for ${getStaffInfo(selectedStaff)?.name}`}
                {showAvailableOnly && ' (available appointments only)'}
              </span>
            </div>
          </div>
        </div>

        {/* Enhanced Single Event Form Modal */}
        {showForm && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white/95 backdrop-blur-sm p-8 rounded-3xl w-full max-w-md shadow-2xl border border-white/20">
              <h2 className="text-2xl font-bold text-gray-800 mb-6 flex items-center gap-3">
                <span className="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center text-white">➕</span>
                Add Single Event
              </h2>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Event Title
                  </label>
                  <input
                    className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 bg-white/90"
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    placeholder="e.g., Available Consultation Slot"
                  />
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                      Staff Member
                    </label>
                    <select
                      className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 bg-white/90"
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
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                      Event Type
                    </label>
                    <select
                      className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 bg-white/90"
                      value={formData.type}
                      onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                    >
                      <option value="available">📅 Available Slot</option>
                      <option value="booked">✅ Booked</option>
                      <option value="meeting">👥 Meeting</option>
                      <option value="other">📋 Other</option>
                    </select>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Start Time
                  </label>
                  <input
                    className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 bg-white/90"
                    type="datetime-local"
                    value={formData.start}
                    onChange={(e) => setFormData({ ...formData, start: e.target.value })}
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    End Time
                  </label>
                  <input
                    className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-200 bg-white/90"
                    type="datetime-local"
                    value={formData.end}
                    onChange={(e) => setFormData({ ...formData, end: e.target.value })}
                  />
                </div>
              </div>
              
              <div className="flex gap-3 mt-8">
                <button
                  className="flex-1 px-6 py-3 border-2 border-gray-300 text-gray-700 rounded-xl hover:bg-gray-50 transition-all duration-200 font-medium"
                  onClick={() => setShowForm(false)}
                >
                  Cancel
                </button>
                <button
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-lg font-medium"
                  onClick={handleSubmit}
                >
                  Create Event
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Enhanced Bulk Create Form Modal */}
        {showBulkForm && (
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className="bg-white/95 backdrop-blur-sm p-8 rounded-3xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl border border-white/20">
              <h2 className="text-3xl font-bold text-gray-800 mb-8 flex items-center gap-4">
                <span className="w-12 h-12 bg-gradient-to-br from-purple-500 to-purple-600 rounded-full flex items-center justify-center text-white text-xl">⚡</span>
                Bulk Create Availability Slots
              </h2>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Left Column */}
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                      Staff Member
                    </label>
                    <select
                      className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
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
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                      Appointment Template
                    </label>
                    <select
                      className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                      value={bulkFormData.template}
                      onChange={(e) => setBulkFormData({ ...bulkFormData, template: e.target.value })}
                    >
                      {SLOT_TEMPLATES.map(template => (
                        <option key={template.id} value={template.id}>
                          {template.icon} {template.name} ({template.duration} min)
                        </option>
                      ))}
                    </select>
                  </div>

                  {bulkFormData.template === 'custom' && (
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">
                        Custom Duration (minutes)
                      </label>
                      <input
                        type="number"
                        min="15"
                        max="240"
                        step="15"
                        className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                        value={bulkFormData.customDuration}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, customDuration: parseInt(e.target.value) })}
                      />
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">
                        Start Date
                      </label>
                      <input
                        type="date"
                        className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                        value={bulkFormData.startDate}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, startDate: e.target.value })}
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">
                        End Date
                      </label>
                      <input
                        type="date"
                        className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                        value={bulkFormData.endDate}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, endDate: e.target.value })}
                      />
                    </div>
                  </div>
                </div>

                {/* Right Column */}
                <div className="space-y-6">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">
                        Start Time
                      </label>
                      <input
                        type="time"
                        className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                        value={bulkFormData.startTime}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, startTime: e.target.value })}
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-semibold text-gray-700 mb-2">
                        End Time
                      </label>
                      <input
                        type="time"
                        className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-200 bg-white/90"
                        value={bulkFormData.endTime}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, endTime: e.target.value })}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                      Days of Week
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                      {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((day) => (
                        <label key={day} className="flex items-center p-3 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors cursor-pointer">
                          <input
                            type="checkbox"
                            className="mr-3 w-4 h-4 text-purple-600 focus:ring-purple-500 rounded"
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
                          <span className="text-sm font-medium">{day}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-purple-50 to-indigo-50 rounded-2xl border border-purple-100">
                    <h4 className="font-bold text-purple-800 mb-3 flex items-center gap-2">
                      <span>👁️</span>
                      Preview
                    </h4>
                    <div className="text-sm text-purple-700 space-y-2">
                      <div className="flex items-center gap-2">
                        <span>📅</span>
                        <span><strong>Date Range:</strong> {bulkFormData.startDate || 'Not set'} to {bulkFormData.endDate || 'Not set'}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>⏰</span>
                        <span><strong>Time:</strong> {bulkFormData.startTime} - {bulkFormData.endTime}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>👤</span>
                        <span><strong>Staff:</strong> {STAFF_MEMBERS.find(s => s.id === bulkFormData.staff)?.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>📝</span>
                        <span><strong>Template:</strong> {SLOT_TEMPLATES.find(t => t.id === bulkFormData.template)?.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>📆</span>
                        <span><strong>Days:</strong> {bulkFormData.weekdays.join(', ')}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="flex gap-4 mt-8 pt-6 border-t border-gray-200">
                <button
                  className="flex-1 px-6 py-3 border-2 border-gray-300 text-gray-700 rounded-xl hover:bg-gray-50 transition-all duration-200 font-medium"
                  onClick={() => setShowBulkForm(false)}
                >
                  Cancel
                </button>
                <button
                  className="flex-1 px-6 py-3 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-xl hover:from-purple-600 hover:to-purple-700 transition-all duration-200 shadow-lg font-medium disabled:opacity-50"
                  onClick={handleBulkSubmit}
                  disabled={!bulkFormData.startDate || !bulkFormData.endDate}
                >
                  ✨ Create Availability Slots
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Beautiful Calendar Container */}
        <div className="bg-white/70 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 p-6">
          <style jsx global>{`
            .rbc-calendar {
              font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            }
            .rbc-header {
              background: linear-gradient(135deg, #f8fafc, #e2e8f0);
              font-weight: 600;
              color: #374151;
              border-bottom: 2px solid #e5e7eb;
              padding: 12px 8px;
            }
            .rbc-month-view, .rbc-time-view {
              border: none;
              border-radius: 12px;
              overflow: hidden;
            }
            .rbc-day-bg {
              border-right: 1px solid #f1f5f9;
            }
            .rbc-date-cell {
              text-align: center;
              padding: 8px;
              font-weight: 500;
            }
            .rbc-today {
              background-color: rgba(59, 130, 246, 0.1);
            }
            .rbc-off-range-bg {
              background-color: #f8fafc;
            }
            .rbc-event {
              font-size: 11px;
              padding: 2px 6px;
              margin: 1px;
            }
            .rbc-toolbar {
              margin-bottom: 20px;
              padding: 16px;
              background: linear-gradient(135deg, #f8fafc, #e2e8f0);
              border-radius: 16px;
              border: 1px solid #e5e7eb;
            }
            .rbc-toolbar button {
              background: white;
              border: 2px solid #e5e7eb;
              border-radius: 8px;
              padding: 8px 16px;
              margin: 0 4px;
              font-weight: 500;
              transition: all 0.2s;
            }
            .rbc-toolbar button:hover {
              border-color: #3b82f6;
              background: #eff6ff;
            }
            .rbc-toolbar button.rbc-active {
              background: linear-gradient(135deg, #3b82f6, #2563eb);
              color: white;
              border-color: #3b82f6;
            }
          `}</style>
          
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
            style={{ height: 700 }}
            onView={(v: any) => setView(v)}
            eventPropGetter={eventStyleGetter}
            onSelectEvent={handleSelectEvent}
          />
        </div>
      </div>
    </div>
  )
}
