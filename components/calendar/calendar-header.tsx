
'use client';

import { Button } from '@/components/ui/button';
import { ChevronLeft, ChevronRight, Calendar } from 'lucide-react';
import { format } from 'date-fns';

interface CalendarHeaderProps {
  currentDate: Date;
  onPreviousMonth: () => void;
  onNextMonth: () => void;
  onToday: () => void;
}

export function CalendarHeader({
  currentDate,
  onPreviousMonth,
  onNextMonth,
  onToday,
}: CalendarHeaderProps) {
  return (
    <div className="flex items-center justify-between p-6 bg-white/80 backdrop-blur-xl rounded-2xl shadow-lg border border-white/30 mb-6">
      <div className="flex items-center gap-4">
        <Button
          variant="outline"
          size="icon"
          onClick={onPreviousMonth}
          className="hover:bg-blue-50 hover:border-blue-200 transition-colors"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        
        <Button
          variant="outline"
          size="icon"
          onClick={onNextMonth}
          className="hover:bg-blue-50 hover:border-blue-200 transition-colors"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
        
        <Button
          variant="outline"
          onClick={onToday}
          className="hover:bg-blue-50 hover:border-blue-200 transition-colors"
        >
          <Calendar className="h-4 w-4 mr-2" />
          Today
        </Button>
      </div>
      
      <div className="text-center">
        <h2 className="text-3xl font-bold bg-gradient-to-r from-slate-800 to-slate-600 bg-clip-text text-transparent">
          {format(currentDate, 'MMMM yyyy')}
        </h2>
      </div>
      
      <div className="w-32" /> {/* Spacer for balanced layout */}
    </div>
  );
}
