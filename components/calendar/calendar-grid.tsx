
'use client';

import { format, startOfMonth, endOfMonth, startOfWeek, endOfWeek, eachDayOfInterval, isSameMonth, isSameDay, isToday } from 'date-fns';
import { cn } from '@/lib/utils';
import { AppointmentBlock } from './appointment-block';

interface CalendarGridProps {
  currentDate: Date;
  appointments: any[];
  onDayClick: (date: Date) => void;
  onAppointmentClick: (appointment: any) => void;
  selectedStaff: string[];
}

const weekDays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export function CalendarGrid({
  currentDate,
  appointments,
  onDayClick,
  onAppointmentClick,
  selectedStaff,
}: CalendarGridProps) {
  const monthStart = startOfMonth(currentDate);
  const monthEnd = endOfMonth(currentDate);
  const calendarStart = startOfWeek(monthStart);
  const calendarEnd = endOfWeek(monthEnd);
  
  const days = eachDayOfInterval({
    start: calendarStart,
    end: calendarEnd,
  });

  const getDayAppointments = (date: Date) => {
    return appointments?.filter(appointment => {
      const appointmentDate = new Date(appointment.startTime);
      return isSameDay(appointmentDate, date) && 
             (selectedStaff.length === 0 || selectedStaff.includes(appointment.staffId));
    }) || [];
  };

  return (
    <div className="bg-white/80 backdrop-blur-xl rounded-2xl shadow-lg border border-white/30 p-6">
      {/* Week day headers */}
      <div className="calendar-grid mb-2">
        {weekDays.map((day) => (
          <div
            key={day}
            className="p-4 text-center font-semibold text-slate-600 bg-slate-50 border-b border-slate-200"
          >
            {day}
          </div>
        ))}
      </div>
      
      {/* Calendar days */}
      <div className="calendar-grid">
        {days.map((day) => {
          const dayAppointments = getDayAppointments(day);
          const isCurrentMonth = isSameMonth(day, currentDate);
          const isDayToday = isToday(day);
          
          return (
            <div
              key={day.toISOString()}
              className={cn(
                'calendar-day',
                !isCurrentMonth && 'other-month',
                isDayToday && 'today'
              )}
              onClick={() => onDayClick(day)}
            >
              <div className="flex justify-between items-start mb-2">
                <span className={cn(
                  'text-sm font-semibold',
                  isCurrentMonth ? 'text-slate-900' : 'text-slate-400',
                  isDayToday && 'text-blue-600'
                )}>
                  {format(day, 'd')}
                </span>
                {dayAppointments.length > 3 && (
                  <span className="text-xs text-slate-500 bg-slate-200 px-2 py-1 rounded-full">
                    +{dayAppointments.length - 3}
                  </span>
                )}
              </div>
              
              <div className="space-y-1">
                {dayAppointments.slice(0, 3).map((appointment) => (
                  <AppointmentBlock
                    key={appointment.id}
                    appointment={appointment}
                    onClick={() => onAppointmentClick(appointment)}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
