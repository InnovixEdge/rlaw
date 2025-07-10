
'use client';

import { format } from 'date-fns';
import { cn } from '@/lib/utils';
import { Clock, User } from 'lucide-react';

interface AppointmentBlockProps {
  appointment: any;
  onClick: () => void;
}

const staffColors = {
  'staff-1': '#10b981',
  'staff-2': '#3b82f6', 
  'staff-3': '#8b5cf6',
  'staff-4': '#f59e0b',
  'staff-5': '#ef4444',
  'staff-6': '#06b6d4',
};

export function AppointmentBlock({ appointment, onClick }: AppointmentBlockProps) {
  const startTime = new Date(appointment.startTime);
  const endTime = new Date(appointment.endTime);
  const staffColor = staffColors[appointment.staffId as keyof typeof staffColors] || '#64748b';
  
  const isAvailable = appointment.status === 'AVAILABLE';
  
  return (
    <div
      className={cn(
        'appointment-block',
        isAvailable && 'available'
      )}
      style={{
        background: isAvailable 
          ? `linear-gradient(135deg, ${staffColor}ee, ${staffColor}cc)`
          : `linear-gradient(135deg, ${staffColor}, ${staffColor}dd)`
      }}
      onClick={onClick}
    >
      <div className="flex items-center gap-1 mb-1">
        <Clock className="h-3 w-3" />
        <span className="text-xs">
          {format(startTime, 'h:mm a')}
        </span>
      </div>
      
      <div className="text-xs font-medium truncate mb-1">
        {appointment.title}
      </div>
      
      {appointment.clientName && (
        <div className="flex items-center gap-1">
          <User className="h-3 w-3" />
          <span className="text-xs truncate">
            {appointment.clientName}
          </span>
        </div>
      )}
    </div>
  );
}
