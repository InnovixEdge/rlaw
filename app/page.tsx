'use client';
import { useEffect, useState } from 'react';
import FullCalendar from '@fullcalendar/react';
import dayGridPlugin from '@fullcalendar/daygrid';
import interactionPlugin from '@fullcalendar/interaction';
import { getAvailability, createEvent } from '../lib/api';

export default function Home() {
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    // Example: fetch availability for user1 and user2 for the current month
    const start = new Date();
    const end = new Date();
    end.setMonth(end.getMonth() + 1);
    getAvailability(['user1', 'user2'], start.toISOString(), end.toISOString()).then(setEvents);
  }, []);

  const handleDateClick = (arg: any) => {
    const title = prompt('Event title');
    if (title) {
      const event = { start: arg.dateStr, end: arg.dateStr, title };
      createEvent(event).then(() => {
        setEvents([...events, event]);
      });
    }
  };

  return (
    <div className="p-4">
      <FullCalendar
        plugins={[dayGridPlugin, interactionPlugin]}
        initialView="dayGridMonth"
        events={events}
        dateClick={handleDateClick}
        height="auto"
      />
    </div>
  );
}
