
'use client';

import { useState, useEffect } from 'react';
import { addMonths, subMonths } from 'date-fns';
import { useSession } from 'next-auth/react';
import { Header } from '@/components/layout/header';
import { Sidebar } from '@/components/layout/sidebar';
import { CalendarHeader } from '@/components/calendar/calendar-header';
import { CalendarGrid } from '@/components/calendar/calendar-grid';
import { AppointmentModal } from '@/components/appointments/appointment-modal';
import { SettingsModal } from '@/components/settings/settings-modal';
import { AuthGuard } from '@/components/auth/auth-guard';
import { toast } from 'sonner';

export default function Dashboard() {
  const { data: session, status } = useSession();
  const [currentDate, setCurrentDate] = useState(new Date());
  const [appointments, setAppointments] = useState([]);
  const [staff, setStaff] = useState([]);
  const [selectedStaff, setSelectedStaff] = useState<string[]>([]);
  const [showAppointmentModal, setShowAppointmentModal] = useState(false);
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [selectedAppointment, setSelectedAppointment] = useState<any>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Fetch initial data
  useEffect(() => {
    if (session?.user?.id) {
      fetchStaff();
      fetchAppointments();
    } else if (status === 'authenticated') {
      // Session exists but no user ID, set loading to false
      setIsLoading(false);
    }
  }, [session, status]);

  const fetchStaff = async () => {
    try {
      const response = await fetch('/api/staff');
      if (response.ok) {
        const staffData = await response.json();
        setStaff(staffData);
        setSelectedStaff(staffData.map((s: any) => s.id));
      } else {
        console.error('Failed to fetch staff:', response.status);
        toast.error('Failed to load staff members');
      }
    } catch (error) {
      console.error('Error fetching staff:', error);
      toast.error('Failed to load staff members');
    }
  };

  const fetchAppointments = async () => {
    try {
      setIsLoading(true);
      const response = await fetch('/api/appointments');
      if (response.ok) {
        const appointmentsData = await response.json();
        setAppointments(appointmentsData);
      } else {
        console.error('Failed to fetch appointments:', response.status);
        toast.error('Failed to load appointments');
      }
    } catch (error) {
      console.error('Error fetching appointments:', error);
      toast.error('Failed to load appointments');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePreviousMonth = () => {
    setCurrentDate(subMonths(currentDate, 1));
  };

  const handleNextMonth = () => {
    setCurrentDate(addMonths(currentDate, 1));
  };

  const handleToday = () => {
    setCurrentDate(new Date());
  };

  const handleNewAppointment = () => {
    setSelectedAppointment(null);
    setShowAppointmentModal(true);
  };

  const handleAppointmentClick = (appointment: any) => {
    setSelectedAppointment(appointment);
    setShowAppointmentModal(true);
  };

  const handleDayClick = (date: Date) => {
    setSelectedAppointment(null);
    setShowAppointmentModal(true);
    // Could pre-fill the date in the modal
  };

  const handleAppointmentSave = async (appointmentData: any) => {
    try {
      const url = selectedAppointment ? `/api/appointments/${selectedAppointment.id}` : '/api/appointments';
      const method = selectedAppointment ? 'PUT' : 'POST';
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(appointmentData),
      });

      if (response.ok) {
        toast.success(selectedAppointment ? 'Appointment updated' : 'Appointment created');
        setShowAppointmentModal(false);
        fetchAppointments();
      } else {
        toast.error('Failed to save appointment');
      }
    } catch (error) {
      console.error('Error saving appointment:', error);
      toast.error('Failed to save appointment');
    }
  };

  const handleAppointmentDelete = async (appointmentId: string) => {
    try {
      const response = await fetch(`/api/appointments/${appointmentId}`, {
        method: 'DELETE',
      });

      if (response.ok) {
        toast.success('Appointment deleted');
        setShowAppointmentModal(false);
        fetchAppointments();
      } else {
        toast.error('Failed to delete appointment');
      }
    } catch (error) {
      console.error('Error deleting appointment:', error);
      toast.error('Failed to delete appointment');
    }
  };

  const handleBulkCreate = () => {
    // TODO: Implement bulk create functionality
    toast.info('Bulk create feature coming soon');
  };

  const handleExportCalendar = () => {
    // TODO: Implement export functionality
    toast.info('Export feature coming soon');
  };

  if (isLoading && status === 'authenticated') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50/30 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-slate-600 text-lg">Loading calendar...</p>
        </div>
      </div>
    );
  }

  return (
    <AuthGuard>
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50/30">
        <Header 
          onNewAppointment={handleNewAppointment}
          onOpenSettings={() => setShowSettingsModal(true)}
        />
        
        <div className="flex">
          <Sidebar
            staff={staff}
            selectedStaff={selectedStaff}
            onStaffSelectionChange={setSelectedStaff}
            onBulkCreate={handleBulkCreate}
            onExportCalendar={handleExportCalendar}
            isCollapsed={sidebarCollapsed}
            onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
          />
          
          <main className="flex-1 p-8">
            <div className="max-w-7xl mx-auto">
              <CalendarHeader
                currentDate={currentDate}
                onPreviousMonth={handlePreviousMonth}
                onNextMonth={handleNextMonth}
                onToday={handleToday}
              />
              
              <CalendarGrid
                currentDate={currentDate}
                appointments={appointments}
                onDayClick={handleDayClick}
                onAppointmentClick={handleAppointmentClick}
                selectedStaff={selectedStaff}
              />
            </div>
          </main>
        </div>

        <AppointmentModal
          isOpen={showAppointmentModal}
          onClose={() => setShowAppointmentModal(false)}
          onSave={handleAppointmentSave}
          onDelete={handleAppointmentDelete}
          appointment={selectedAppointment}
          staff={staff}
        />

        <SettingsModal
          isOpen={showSettingsModal}
          onClose={() => setShowSettingsModal(false)}
          staff={staff}
          onStaffUpdate={fetchStaff}
        />
      </div>
    </AuthGuard>
  );
}
