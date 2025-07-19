// app/api/appointments/[id]/route.ts
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// Same mock data as main appointments route
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

// GET single appointment by ID
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
    const appointment = mockAppointments.find(apt => apt.id === params.id);
    
    if (!appointment) {
      return NextResponse.json(
        { error: 'Appointment not found' },
        { status: 404 }
      );
    }

    // Return appointment with serialized dates
    const serializedAppointment = {
      ...appointment,
      startTime: appointment.startTime.toISOString(),
      endTime: appointment.endTime.toISOString(),
      createdAt: appointment.createdAt.toISOString(),
    };

    return NextResponse.json(serializedAppointment);
  } catch (error) {
    console.error('Error fetching appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// UPDATE appointment by ID
export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
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

    // Check if appointment exists in mock data
    const existingAppointment = mockAppointments.find(apt => apt.id === params.id);
    if (!existingAppointment) {
      return NextResponse.json(
        { error: 'Appointment not found' },
        { status: 404 }
      );
    }

    // Validate staff exists
    const staff = mockStaff.find(s => s.id === staffId);
    if (!staff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 400 }
      );
    }

    // For mock version, skip actual conflict checking
    // In real version, this would check database for scheduling conflicts

    // Create updated appointment (in real version, this would update database)
    const updatedAppointment = {
      ...existingAppointment,
      title,
      description: description || null,
      startTime: new Date(startTime),
      endTime: new Date(endTime),
      clientName,
      clientEmail,
      clientPhone: clientPhone || null,
      clientNotes: clientNotes || null,
      type: type || 'CONSULTATION',
      status: status || 'SCHEDULED',
      staff,
      updatedAt: new Date(), // Add timestamp for when it was "updated"
    };

    // Return updated appointment with serialized dates
    const serializedAppointment = {
      ...updatedAppointment,
      startTime: updatedAppointment.startTime.toISOString(),
      endTime: updatedAppointment.endTime.toISOString(),
      createdAt: updatedAppointment.createdAt.toISOString(),
      updatedAt: updatedAppointment.updatedAt.toISOString(),
    };

    return NextResponse.json(serializedAppointment);
  } catch (error) {
    console.error('Error updating appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// DELETE appointment by ID
export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
    // Check if appointment exists in mock data
    const existingAppointment = mockAppointments.find(apt => apt.id === params.id);
    if (!existingAppointment) {
      return NextResponse.json(
        { error: 'Appointment not found' },
        { status: 404 }
      );
    }

    // In real version, this would delete from database
    // For mock version, we just simulate successful deletion
    return NextResponse.json({ 
      message: 'Appointment deleted successfully',
      deletedId: params.id,
      deletedAppointment: {
        id: existingAppointment.id,
        title: existingAppointment.title,
        clientName: existingAppointment.clientName,
      }
    });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
