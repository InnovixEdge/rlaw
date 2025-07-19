
export interface Staff {
  id: string;
  name: string;
  email: string;
  phone?: string;
  position?: string;
  department?: string;
  color: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    name: string;
    email: string;
    role: string;
  };
}

export interface Appointment {
  id: string;
  title: string;
  description?: string;
  startTime: Date;
  endTime: Date;
  status: 'SCHEDULED' | 'CONFIRMED' | 'CANCELLED' | 'COMPLETED' | 'NO_SHOW';
  type: 'CONSULTATION' | 'FOLLOW_UP' | 'COURT_PREP' | 'DOCUMENT_REVIEW' | 'MEETING' | 'OTHER';
  clientName: string;
  clientEmail: string;
  clientPhone?: string;
  clientNotes?: string;
  staffId: string;
  createdById: string;
  createdAt: Date;
  updatedAt: Date;
  staff?: Staff;
  createdBy?: {
    id: string;
    name: string;
    email: string;
  };
}

export interface User {
  id: string;
  name?: string;
  email: string;
  role: 'ADMIN' | 'STAFF' | 'MANAGER';
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  staffProfile?: Staff;
}

export interface CalendarIntegration {
  id: string;
  userId: string;
  provider: 'GOOGLE' | 'OUTLOOK';
  isActive: boolean;
  accessToken?: string;
  refreshToken?: string;
  tokenExpiry?: Date;
  providerData?: any;
  createdAt: Date;
  updatedAt: Date;
}

export interface NotificationSetting {
  id: string;
  userId: string;
  emailEnabled: boolean;
  emailConfirmation: boolean;
  emailReminder: boolean;
  emailReminderMinutes: number;
  smsEnabled: boolean;
  smsConfirmation: boolean;
  smsReminder: boolean;
  smsReminderMinutes: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface AppointmentNotification {
  id: string;
  appointmentId: string;
  type: 'CONFIRMATION' | 'REMINDER' | 'CANCELLATION' | 'RESCHEDULE';
  method: 'EMAIL' | 'SMS' | 'BOTH';
  recipientEmail: string;
  recipientPhone?: string;
  subject?: string;
  message: string;
  status: 'PENDING' | 'SENT' | 'FAILED' | 'CANCELLED';
  sentAt?: Date;
  errorMessage?: string;
  createdAt: Date;
}
