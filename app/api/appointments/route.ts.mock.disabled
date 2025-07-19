// app/api/appointments/route.ts
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// Mock appointment data for development (replace with real database later)
const mockAppointments = [
  {
    id: '1',
    title: 'Estate Planning Consultation',
    description: 'Initial consultation for will and trust planning',
    startTime: new Date('2025-07-14T09:00:00Z'),
    endTime: new Date('2025-07-14T10:00:00Z'),
    clientName: 'Sarah Johnson',
    clientEmail: 'sarah.johnson@email.com',
    clientPhone: '(555) 123-4567',
    clientNotes: 'Referred by John Smith. Needs comprehensive estate plan.',
    type: 'CONSULTATION',
    status: 'SCHEDULED',
    staff: {
      id: 'staff-1',
      name: 'Attorney John Davis',
      email: 'john.davis@lawfirm.com',
      color: '#3B82F6',
    },
    createdBy: {
      id: 'user-1',
      name: 'Office Manager',
      email: 'manager@lawfirm.com',
    },
    createdAt: new Date('2025-07-12T10:00:00Z'),
  },
  {
    id: '2',
    title: 'Contract Review Meeting',
    description: 'Review and discuss commercial lease agreement',
    startTime: new Date('2025-07-14T14:00:00Z'),
    endTime: new Date('2025-07-14T15:30:00Z'),
    clientName: 'Mike Wilson',
    clientEmail: 'mike.wilson@business.com',
    clientPhone: '(555) 987-6543',
    clientNotes: 'Business owner looking to lease new office space.',
    type: 'CONTRACT_REVIEW',
    status: 'SCHEDULED',
    staff: {
      id: 'staff-1',
      name: 'Attorney John Davis',
      email: 'john.davis@lawfirm.com',
      color: '#3B82F6',
    },
    createdBy: {
      id: 'user-1',
      name: 'Office Manager',
      email: 'manager@lawfirm.com',
    },
    createdAt: new Date('2025-07-11T14:30:00Z'),
  },
  {
    id: '3',
    title: 'Deposition Preparation',
    description: 'Prepare client for upcoming deposition in Smith v. Johnson case',
    startTime: new Date('2025-07-15T10:00:00Z'),
    endTime: new Date('2025-07-15T12:00:00Z'),
    clientName: 'Emily Rodriguez',
    clientEmail: 'emily.rodriguez@email.com',
    clientPhone: '(555) 456-7890',
    clientNotes: 'Key witness in personal injury case. First deposition.',
    type: 'DEPOSITION_PREP',
    status: 'SCHEDULED',
    staff: {
      id: 'staff-2',
      name: 'Attorney Lisa Chen',
      email: 'lisa.chen@lawfirm.com',
      color: '#10B981',
    },
    createdBy: {
      id: 'user-1',
      name: 'Office Manager',
      email: 'manager@lawfirm.com',
    },
    createdAt: new Date('2025-07-10T09:15:00Z'),
  },
  {
    id: '4',
    title: 'Family Law Consultation',
    description: 'Divorce consultation and child custody discussion',
    startTime: new Date('2025-07-16T09:00:00Z'),
    endTime: new Date('2025-07-16T10:30:00Z'),
    clientName: 'Robert Martinez',
    clientEmail: 'robert.martinez@email.com',
    clientPhone: '(555) 321-0987',
    clientNotes: 'Sensitive case. Client seeking joint custody arrangement.',
    type: 'FAMILY_LAW',
    status: 'SCHEDULED',
    staff: {
      id: 'staff-3',
      name: 'Attorney Rachel Green',
      email: 'rachel.green@lawfirm.com',
      color: '#F59E0B',
    },
    createdBy: {
      id: 'user-1',
      name: 'Office Manager',
      email: 'manager@lawfirm.com',
    },
    createdAt: new Date('2025-07-09T16:45:00Z'),
  },
  {
    id: '5',
    title: 'Court Filing Deadline Review',
    description: 'Final review of motion for summary judgment before filing',
    startTime: new Date('2025-07-17T13:00:00Z'),
    endTime: new Date('2025-07-17T14:00:00Z'),
    clientName: 'Corporate Client ABC Inc.',
    clientEmail: 'legal@abcinc.com',
    clientPhone: '(555) 111-2222',
    clientNotes: 'Deadline is tomorrow. Critical case for client.',
    type: 'COURT_FILING',
    status: 'SCHEDULED',
    staff: {
      id: 'staff-1',
      name: 'Attorney John Davis',
      email: 'john.davis@lawfirm.com',
      color: '#3B82F6',
    },
    createdBy: {
      id: 'user-1',
      name: 'Office Manager',
      email: 'manager@lawfirm.com',
    },
    createdAt: new Date('2025-07-08T11:20:00Z'),
  }
];

// Mock staff data
const mockStaff = [
  {
    id: 'staff-1',
    name: 'Attorney John Davis',
    email: 'john.davis@lawfirm.com',
    color: '#3B82F6',
  },
  {
    id: 'staff-2',
    name: 'Attorney Lisa Chen',
    email: 'lisa.chen@lawfirm.com',
    color: '#10B981',
  },
  {
    id: 'staff-3',
    name: 'Attorney Rachel Green',
    email: 'rachel.green@lawfirm.com',
    color: '#F59E0B',
  }
];

export async function GET(request: Request) {
  try {
    // For now, skip authentication check since we don't have database
    // In real version, this would check session
    
    // Return mock appointments with same structure as real API
    const appointments = mockAppointments.map(appointment => ({
      ...appointment,
      // Ensure dates are serialized properly
      startTime: appointment.startTime.toISOString(),
      endTime: appointment.endTime.toISOString(),
      createdAt: appointment.createdAt.toISOString(),
    }));

    return NextResponse.json(appointments);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    // For now, skip authentication check
    // In real version, this would check session
    
    const data = await request.json();
    const {
      title,
      description,
      startTime,
      endTime,
      clientName,
      clientEmail,
      clientPhone,
      clientNotes,
      staffId,
      type,
      status,
    } = data;

    // Validate required fields
    if (!title || !startTime || !endTime || !clientName || !clientEmail || !staffId) {
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    // Check if staff exists in mock data
    const staff = mockStaff.find(s => s.id === staffId);
    if (!staff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 400 }
      );
    }

    // For mock version, we'll skip actual conflict checking
    // In real version, this would check database for conflicts

    // Create mock appointment
    const newAppointment = {
      id: `mock-${Date.now()}`, // Generate a simple ID
      title,
      description: description || null,
      startTime: new Date(startTime).toISOString(),
      endTime: new Date(endTime).toISOString(),
      clientName,
      clientEmail,
      clientPhone: clientPhone || null,
      clientNotes: clientNotes || null,
      type: type || 'CONSULTATION',
      status: status || 'SCHEDULED',
      staff,
      createdBy: {
        id: 'mock-user',
        name: 'Mock User',
        email: 'mock@lawfirm.com',
      },
      createdAt: new Date().toISOString(),
    };

    // In real version, this would save to database
    // For now, just return the created appointment
    return NextResponse.json(newAppointment, { status: 201 });
  } catch (error) {
    console.error('Error creating appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
