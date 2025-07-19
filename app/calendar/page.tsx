'use client'
import { Calendar, momentLocalizer, Views } from 'react-big-calendar'
import 'react-big-calendar/lib/css/react-big-calendar.css'
import moment from 'moment'
import { useState } from 'react'

const localizer = momentLocalizer(moment)

// Ultra-modern color palette with vibrant gradients
const STAFF_MEMBERS = [
  { 
    id: 'lee', 
    name: 'Attorney Lee', 
    color: '#10b981', 
    gradient: 'from-emerald-400 via-emerald-500 to-emerald-600',
    lightBg: 'from-emerald-50 to-emerald-100'
  },
  { 
    id: 'smith', 
    name: 'Attorney Smith', 
    color: '#3b82f6', 
    gradient: 'from-blue-400 via-blue-500 to-blue-600',
    lightBg: 'from-blue-50 to-blue-100'
  },
  { 
    id: 'jones', 
    name: 'Attorney Jones', 
    color: '#8b5cf6', 
    gradient: 'from-purple-400 via-purple-500 to-purple-600',
    lightBg: 'from-purple-50 to-purple-100'
  },
  { 
    id: 'davis', 
    name: 'Attorney Davis', 
    color: '#f59e0b', 
    gradient: 'from-amber-400 via-amber-500 to-amber-600',
    lightBg: 'from-amber-50 to-amber-100'
  },
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
            ? `linear-gradient(135deg, ${staffInfo.color}ee, ${staffInfo.color}cc)`
            : `linear-gradient(135deg, ${staffInfo.color}, ${staffInfo.color}dd)`,
          color: 'white',
          fontWeight: '600',
          border: event.type === 'available' ? '3px solid white' : 'none',
          borderRadius: '12px',
          boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
          fontSize: '12px',
          fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
        }
      }
    }
    
    return {
      style: {
        background: 'linear-gradient(135deg, #64748b, #475569)',
        color: 'white',
        fontWeight: '600',
        borderRadius: '12px',
        boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif'
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
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50/30" style={{ fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif' }}>
      <div className="container mx-auto px-8 py-12 max-w-7xl">
        
        {/* Ultra Modern Header - Inspired by Matalino AI */}
        <div className="text-center mb-16">
          <h1 className="text-6xl md:text-7xl font-bold mb-6 leading-tight">
            <span className="bg-gradient-to-r from-slate-900 via-blue-900 to-slate-900 bg-clip-text text-transparent">
              Legal
            </span>{' '}
            <span className="bg-gradient-to-r from-blue-600 via-purple-600 to-emerald-600 bg-clip-text text-transparent">
              Calendar
            </span>
          </h1>
          <p className="text-xl md:text-2xl text-slate-600 max-w-3xl mx-auto font-light leading-relaxed">
            Intelligent scheduling for modern legal practices
          </p>
          
          {/* Feature Pills */}
          <div className="flex flex-wrap justify-center gap-4 mt-8">
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-emerald-50 to-emerald-100 rounded-full border border-emerald-200">
              <span className="text-emerald-600">📈</span>
              <span className="text-emerald-800 font-medium text-sm">Smart Scheduling</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-blue-50 to-blue-100 rounded-full border border-blue-200">
              <span className="text-blue-600">⚡</span>
              <span className="text-blue-800 font-medium text-sm">Bulk Creation</span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-50 to-purple-100 rounded-full border border-purple-200">
              <span className="text-purple-600">🎯</span>
              <span className="text-purple-800 font-medium text-sm">Staff Management</span>
            </div>
          </div>
        </div>
        
        {/* Demo Mode Banner */}
        <div className="mb-8 p-6 bg-gradient-to-r from-amber-50 via-orange-50 to-amber-50 border border-amber-200/50 rounded-3xl shadow-sm backdrop-blur-sm">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-gradient-to-br from-amber-400 to-orange-500 rounded-2xl flex items-center justify-center shadow-lg">
              <span className="text-white text-xl">🚀</span>
            </div>
            <div>
              <h3 className="text-amber-900 font-bold text-lg">Demo Environment</h3>
              <p className="text-amber-800">Experience the power of intelligent legal scheduling with sample data</p>
            </div>
          </div>
        </div>
        
        {/* Action Controls */}
        <div className="mb-8 p-8 bg-white/80 backdrop-blur-xl rounded-3xl shadow-xl border border-white/30">
          <div className="flex flex-wrap gap-4 justify-center lg:justify-start">
            
            {/* Add Event Button */}
            <button
              className="group px-8 py-4 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-2xl hover:from-blue-600 hover:via-blue-700 hover:to-blue-800 transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:-translate-y-1 font-semibold flex items-center gap-3"
              onClick={() => setShowForm(true)}
            >
              <span className="text-xl">➕</span>
              <span>Add Event</span>
            </button>
            
            {/* Bulk Create Button */}
            <button
              className="group px-8 py-4 bg-gradient-to-r from-purple-500 via-purple-600 to-purple-700 text-white rounded-2xl hover:from-purple-600 hover:via-purple-700 hover:to-purple-800 transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:-translate-y-1 font-semibold flex items-center gap-3"
              onClick={() => setShowBulkForm(true)}
            >
              <span className="text-xl">⚡</span>
              <span>Bulk Create</span>
            </button>
            
            {/* Availability Toggle */}
            <button
              className={`group px-8 py-4 rounded-2xl transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:-translate-y-1 font-semibold flex items-center gap-3 ${showAvailableOnly 
                ? 'bg-gradient-to-r from-emerald-500 via-emerald-600 to-emerald-700 text-white hover:from-emerald-600 hover:via-emerald-700 hover:to-emerald-800' 
                : 'bg-white border-2 border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50'
              }`}
              onClick={() => setShowAvailableOnly(!showAvailableOnly)}
            >
              <span className="text-xl">{showAvailableOnly ? '✅' : '👁️'}</span>
              <span>{showAvailableOnly ? "All Events" : "Available Only"}</span>
            </button>
            
            {/* Staff Filter */}
            <select
              className="px-8 py-4 border-2 border-slate-200 rounded-2xl bg-white/90 hover:border-slate-300 focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 font-semibold text-slate-700 shadow-xl min-w-48"
              value={selectedStaff}
              onChange={(e) => setSelectedStaff(e.target.value)}
            >
              <option value="all">👥 All Staff Members</option>
              {STAFF_MEMBERS.map(staff => (
                <option key={staff.id} value={staff.id}>
                  {staff.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* PROMINENT Staff Color Legend */}
        <div className="mb-8 p-8 bg-white/80 backdrop-blur-xl rounded-3xl shadow-xl border border-white/30">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold bg-gradient-to-r from-slate-800 to-slate-600 bg-clip-text text-transparent mb-2">
              Staff Color Guide
            </h2>
            <p className="text-slate-600 text-lg">Match calendar events to attorneys by color</p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {STAFF_MEMBERS.map(staff => (
              <div key={staff.id} className="group">
                <div className={`p-6 bg-gradient-to-br ${staff.lightBg} rounded-2xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 border border-white/50`}>
                  <div className="text-center">
                    <div 
                      className={`w-16 h-16 mx-auto mb-4 rounded-2xl shadow-xl bg-gradient-to-br ${staff.gradient} flex items-center justify-center`}
                    >
                      <span className="text-white text-2xl font-bold">
                        {staff.name.split(' ')[1].charAt(0)}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-800 mb-1">{staff.name}</h3>
                    <p className="text-sm text-slate-600">Legal Professional</p>
                    <div className="mt-4 text-xs text-slate-500">
                      Events appear in this color
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
            <div className="p-4 bg-gradient-to-br from-emerald-50 to-emerald-100 rounded-xl border border-emerald-200">
              <div className="text-emerald-600 text-2xl mb-2">💎</div>
              <span className="text-emerald-800 font-semibold">Available slots have white borders</span>
            </div>
            <div className="p-4 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl border border-blue-200">
              <div className="text-blue-600 text-2xl mb-2">📊</div>
              <span className="text-blue-800 font-semibold">Showing {filteredEvents.length} total events</span>
            </div>
            <div className="p-4 bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl border border-purple-200">
              <div className="text-purple-600 text-2xl mb-2">👤</div>
              <span className="text-purple-800 font-semibold">
                {selectedStaff !== 'all' ? `Filtered: ${getStaffInfo(selectedStaff)?.name}` : 'All staff shown'}
              </span>
            </div>
          </div>
        </div>

        {/* Modern Forms - keeping the existing modal forms but with improved styling */}
        {showForm && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <div className="bg-white/95 backdrop-blur-xl p-10 rounded-3xl w-full max-w-lg shadow-2xl border border-white/30">
              <h2 className="text-3xl font-bold text-slate-800 mb-8 text-center">
                Create New Event
              </h2>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-3">
                    Event Title
                  </label>
                  <input
                    className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/90 font-medium"
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    placeholder="e.g., Available Consultation Slot"
                  />
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-bold text-slate-700 mb-3">
                      Staff Member
                    </label>
                    <select
                      className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/90 font-medium"
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
                    <label className="block text-sm font-bold text-slate-700 mb-3">
                      Event Type
                    </label>
                    <select
                      className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/90 font-medium"
                      value={formData.type}
                      onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                    >
                      <option value="available">📅 Available</option>
                      <option value="booked">✅ Booked</option>
                      <option value="meeting">👥 Meeting</option>
                      <option value="other">📋 Other</option>
                    </select>
                  </div>
                </div>
                
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-3">
                    Start Time
                  </label>
                  <input
                    className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/90 font-medium"
                    type="datetime-local"
                    value={formData.start}
                    onChange={(e) => setFormData({ ...formData, start: e.target.value })}
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-bold text-slate-700 mb-3">
                    End Time
                  </label>
                  <input
                    className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-300 bg-white/90 font-medium"
                    type="datetime-local"
                    value={formData.end}
                    onChange={(e) => setFormData({ ...formData, end: e.target.value })}
                  />
                </div>
              </div>
              
              <div className="flex gap-4 mt-10">
                <button
                  className="flex-1 px-8 py-4 border-2 border-slate-300 text-slate-700 rounded-xl hover:bg-slate-50 transition-all duration-300 font-bold"
                  onClick={() => setShowForm(false)}
                >
                  Cancel
                </button>
                <button
                  className="flex-1 px-8 py-4 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-xl hover:from-blue-600 hover:to-blue-700 transition-all duration-300 shadow-xl font-bold"
                  onClick={handleSubmit}
                >
                  Create Event
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Bulk Form Modal */}
        {showBulkForm && (
          <div className="fixed inset-0 bg-black/60 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <div className="bg-white/95 backdrop-blur-xl p-10 rounded-3xl w-full max-w-5xl max-h-[90vh] overflow-y-auto shadow-2xl border border-white/30">
              <h2 className="text-4xl font-bold text-slate-800 mb-10 text-center">
                Bulk Availability Creation
              </h2>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                {/* Left Column - keeping existing bulk form structure but with better styling */}
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-bold text-slate-700 mb-3">
                      Staff Member
                    </label>
                    <select
                      className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
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
                    <label className="block text-sm font-bold text-slate-700 mb-3">
                      Appointment Template
                    </label>
                    <select
                      className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
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
                      <label className="block text-sm font-bold text-slate-700 mb-3">
                        Custom Duration (minutes)
                      </label>
                      <input
                        type="number"
                        min="15"
                        max="240"
                        step="15"
                        className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
                        value={bulkFormData.customDuration}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, customDuration: parseInt(e.target.value) })}
                      />
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-3">
                        Start Date
                      </label>
                      <input
                        type="date"
                        className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
                        value={bulkFormData.startDate}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, startDate: e.target.value })}
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-3">
                        End Date
                      </label>
                      <input
                        type="date"
                        className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
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
                      <label className="block text-sm font-bold text-slate-700 mb-3">
                        Start Time
                      </label>
                      <input
                        type="time"
                        className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
                        value={bulkFormData.startTime}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, startTime: e.target.value })}
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-bold text-slate-700 mb-3">
                        End Time
                      </label>
                      <input
                        type="time"
                        className="w-full px-6 py-4 border-2 border-slate-200 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-500/20 focus:border-purple-500 transition-all duration-300 bg-white/90 font-medium"
                        value={bulkFormData.endTime}
                        onChange={(e) => setBulkFormData({ ...bulkFormData, endTime: e.target.value })}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-bold text-slate-700 mb-4">
                      Days of Week
                    </label>
                    <div className="grid grid-cols-2 gap-3">
                      {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((day) => (
                        <label key={day} className="flex items-center p-4 rounded-xl bg-slate-50 hover:bg-slate-100 transition-colors cursor-pointer border border-slate-200">
                          <input
                            type="checkbox"
                            className="mr-3 w-5 h-5 text-purple-600 focus:ring-purple-500 rounded"
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
                          <span className="font-medium">{day}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-purple-50 to-indigo-50 rounded-2xl border border-purple-200">
                    <h4 className="font-bold text-purple-800 mb-4 text-lg">
                      📋 Preview Summary
                    </h4>
                    <div className="text-sm text-purple-700 space-y-2">
                      <div><strong>Date Range:</strong> {bulkFormData.startDate || 'Not set'} to {bulkFormData.endDate || 'Not set'}</div>
                      <div><strong>Time:</strong> {bulkFormData.startTime} - {bulkFormData.endTime}</div>
                      <div><strong>Staff:</strong> {STAFF_MEMBERS.find(s => s.id === bulkFormData.staff)?.name}</div>
                      <div><strong>Template:</strong> {SLOT_TEMPLATES.find(t => t.id === bulkFormData.template)?.name}</div>
                      <div><strong>Days:</strong> {bulkFormData.weekdays.join(', ')}</div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="flex gap-4 mt-10">
                <button
                  className="flex-1 px-8 py-4 border-2 border-slate-300 text-slate-700 rounded-xl hover:bg-slate-50 transition-all duration-300 font-bold"
                  onClick={() => setShowBulkForm(false)}
                >
                  Cancel
                </button>
                <button
                  className="flex-1 px-8 py-4 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-xl hover:from-purple-600 hover:to-purple-700 transition-all duration-300 shadow-xl font-bold disabled:opacity-50"
                  onClick={handleBulkSubmit}
                  disabled={!bulkFormData.startDate || !bulkFormData.endDate}
                >
                  ✨ Create Availability Slots
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Ultra Modern Calendar Container */}
        <div className="bg-white/80 backdrop-blur-xl rounded-3xl shadow-2xl border border-white/30 p-8">
          <style jsx global>{`
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
            
            .rbc-calendar {
              font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
              font-weight: 500;
            }
            .rbc-header {
              background: linear-gradient(135deg, #f8fafc, #e2e8f0);
              font-weight: 700;
              color: #334155;
              border-bottom: 2px solid #e2e8f0;
              padding: 16px 12px;
              font-size: 14px;
              text-transform: uppercase;
              letter-spacing: 0.5px;
            }
            .rbc-month-view, .rbc-time-view {
              border: none;
              border-radius: 16px;
              overflow: hidden;
              background: white;
            }
            .rbc-day-bg {
              border-right: 1px solid #f1f5f9;
              border-bottom: 1px solid #f1f5f9;
            }
            .rbc-date-cell {
              text-align: center;
              padding: 12px;
              font-weight: 600;
              color: #475569;
            }
            .rbc-today {
              background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(147, 197, 253, 0.1));
            }
            .rbc-off-range-bg {
              background-color: #f8fafc;
            }
            .rbc-event {
              font-size: 12px;
              padding: 4px 8px;
              margin: 2px;
              font-weight: 600;
            }
            .rbc-toolbar {
              margin-bottom: 24px;
              padding: 20px;
              background: linear-gradient(135deg, #f8fafc, #e2e8f0);
              border-radius: 20px;
              border: 2px solid #e2e8f0;
            }
            .rbc-toolbar button {
              background: white;
              border: 2px solid #e2e8f0;
              border-radius: 12px;
              padding: 12px 20px;
              margin: 0 6px;
              font-weight: 600;
              transition: all 0.3s ease;
              font-family: 'Inter', sans-serif;
            }
            .rbc-toolbar button:hover {
              border-color: #3b82f6;
              background: #eff6ff;
              transform: translateY(-2px);
              box-shadow: 0 8px 25px rgba(59, 130, 246, 0.2);
            }
            .rbc-toolbar button.rbc-active {
              background: linear-gradient(135deg, #3b82f6, #2563eb);
              color: white;
              border-color: #3b82f6;
              box-shadow: 0 8px 25px rgba(59, 130, 246, 0.3);
            }
            .rbc-toolbar-label {
              font-weight: 800;
              font-size: 18px;
              color: #1e293b;
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
            style={{ height: 800 }}
            onView={(v: any) => setView(v)}
            eventPropGetter={eventStyleGetter}
            onSelectEvent={handleSelectEvent}
          />
        </div>
      </div>
    </div>
  )
}
