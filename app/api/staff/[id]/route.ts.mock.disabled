// app/api/staff/[id]/route.ts
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// Same mock staff data as main staff route
const mockStaff = [
  {
    id: 'staff-1',
    userId: 'user-2',
    name: 'Attorney John Davis',
    email: 'john.davis@lawfirm.com',
    phone: '(555) 123-4567',
    position: 'Senior Partner',
    department: 'Corporate Law',
    color: '#3B82F6',
    isActive: true,
    specialties: ['Corporate Law', 'Contract Law', 'Business Formation'],
    barNumber: 'CA12345',
    licenseState: 'California',
    user: {
      id: 'user-2',
      name: 'John Davis',
      email: 'john.davis@lawfirm.com',
      role: 'ATTORNEY',
    },
    createdAt: new Date('2025-01-01T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  },
  {
    id: 'staff-2',
    userId: 'user-3',
    name: 'Attorney Lisa Chen',
    email: 'lisa.chen@lawfirm.com',
    phone: '(555) 234-5678',
    position: 'Associate Attorney',
    department: 'Litigation',
    color: '#10B981',
    isActive: true,
    specialties: ['Personal Injury', 'Employment Law', 'Civil Litigation'],
    barNumber: 'CA23456',
    licenseState: 'California',
    user: {
      id: 'user-3',
      name: 'Lisa Chen',
      email: 'lisa.chen@lawfirm.com',
      role: 'ATTORNEY',
    },
    createdAt: new Date('2025-02-15T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  },
  {
    id: 'staff-3',
    userId: 'user-4',
    name: 'Rachel Green',
    email: 'rachel.green@lawfirm.com',
    phone: '(555) 345-6789',
    position: 'Family Law Attorney',
    department: 'Family Law',
    color: '#F59E0B',
    isActive: true,
    specialties: ['Divorce', 'Child Custody', 'Adoption', 'Domestic Relations'],
    barNumber: 'CA34567',
    licenseState: 'California',
    user: {
      id: 'user-4',
      name: 'Rachel Green',
      email: 'rachel.green@lawfirm.com',
      role: 'ATTORNEY',
    },
    createdAt: new Date('2025-03-10T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  },
  {
    id: 'staff-4',
    userId: 'user-5',
    name: 'Michael Thompson',
    email: 'michael.thompson@lawfirm.com',
    phone: '(555) 456-7890',
    position: 'Paralegal',
    department: 'Litigation Support',
    color: '#8B5CF6',
    isActive: true,
    specialties: ['Legal Research', 'Document Preparation', 'Case Management'],
    certification: 'Certified Paralegal (CP)',
    user: {
      id: 'user-5',
      name: 'Michael Thompson',
      email: 'michael.thompson@lawfirm.com',
      role: 'STAFF',
    },
    createdAt: new Date('2025-04-20T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  },
  {
    id: 'staff-5',
    userId: 'user-1',
    name: 'Sarah Wilson',
    email: 'sarah.wilson@lawfirm.com',
    phone: '(555) 567-8901',
    position: 'Office Manager',
    department: 'Administration',
    color: '#EF4444',
    isActive: true,
    specialties: ['Client Relations', 'Scheduling', 'Administrative Support'],
    user: {
      id: 'user-1',
      name: 'Sarah Wilson',
      email: 'sarah.wilson@lawfirm.com',
      role: 'ADMIN',
    },
    createdAt: new Date('2024-12-01T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  }
];

// Mock appointments to check for conflicts (simplified version)
const mockAppointments = [
  { id: '1', staffId: 'staff-1', status: 'SCHEDULED', title: 'Estate Planning Consultation' },
  { id: '2', staffId: 'staff-1', status: 'SCHEDULED', title: 'Contract Review Meeting' },
  { id: '3', staffId: 'staff-2', status: 'SCHEDULED', title: 'Deposition Preparation' },
  // staff-3, staff-4, staff-5 have no active appointments for testing deletion
];

// GET single staff member by ID
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
    const staff = mockStaff.find(s => s.id === params.id);
    
    if (!staff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 404 }
      );
    }

    // Return staff with serialized dates
    const staffResponse = {
      ...staff,
      createdAt: staff.createdAt.toISOString(),
      updatedAt: staff.updatedAt.toISOString(),
    };

    return NextResponse.json(staffResponse);
  } catch (error) {
    console.error('Error fetching staff member:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// UPDATE staff member by ID
export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
    const data = await request.json();
    const { name, email, phone, position, department, color, specialties, barNumber, licenseState, isActive } = data;

    // Check if staff exists in mock data
    const existingStaff = mockStaff.find(s => s.id === params.id);
    if (!existingStaff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 404 }
      );
    }

    // Validate required fields
    if (!name || !email) {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    // Check for email conflicts (excluding current staff member)
    if (email !== existingStaff.email) {
      const emailConflict = mockStaff.find(s => 
        s.id !== params.id && 
        s.email.toLowerCase() === email.toLowerCase()
      );
      
      if (emailConflict) {
        return NextResponse.json(
          { error: 'Another staff member with this email already exists' },
          { status: 400 }
        );
      }
    }

    // Create updated staff object
    const updatedStaff = {
      ...existingStaff,
      name,
      email: email.toLowerCase(),
      phone: phone || null,
      position: position || existingStaff.position,
      department: department || existingStaff.department,
      color: color || existingStaff.color,
      specialties: specialties || existingStaff.specialties,
      barNumber: barNumber || existingStaff.barNumber,
      licenseState: licenseState || existingStaff.licenseState,
      isActive: isActive !== undefined ? isActive : existingStaff.isActive,
      updatedAt: new Date(),
      user: {
        ...existingStaff.user,
        name,
        email: email.toLowerCase(),
        role: position?.toLowerCase().includes('attorney') ? 'ATTORNEY' : existingStaff.user.role,
      }
    };

    // Log the "updated" staff member (for development purposes)
    console.log('Mock staff update:', updatedStaff);

    // Return updated staff with serialized dates
    const staffResponse = {
      ...updatedStaff,
      createdAt: updatedStaff.createdAt.toISOString(),
      updatedAt: updatedStaff.updatedAt.toISOString(),
    };

    return NextResponse.json(staffResponse);
  } catch (error) {
    console.error('Error updating staff member:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// DELETE (soft delete) staff member by ID
export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    // For now, skip authentication check
    
    // Check if staff exists in mock data
    const existingStaff = mockStaff.find(s => s.id === params.id);
    if (!existingStaff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 404 }
      );
    }

    // Check if staff has any active appointments (business rule)
    const activeAppointments = mockAppointments.filter(apt => 
      apt.staffId === params.id && 
      apt.status !== 'CANCELLED'
    );

    if (activeAppointments.length > 0) {
      return NextResponse.json(
        { 
          error: 'Cannot delete staff member with active appointments',
          activeAppointmentCount: activeAppointments.length,
          activeAppointments: activeAppointments.map(apt => ({
            id: apt.id,
            title: apt.title,
            status: apt.status
          }))
        },
        { status: 400 }
      );
    }

    // In real version, this would soft delete by setting isActive to false
    // For mock version, we just simulate successful deletion
    console.log(`Mock staff deletion: ${existingStaff.name} (${existingStaff.email}) marked as inactive`);

    return NextResponse.json({ 
      message: 'Staff member deleted successfully',
      deletedStaff: {
        id: existingStaff.id,
        name: existingStaff.name,
        email: existingStaff.email,
        position: existingStaff.position,
        isActive: false // Would be set to false in real database
      }
    });
  } catch (error) {
    console.error('Error deleting staff member:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
