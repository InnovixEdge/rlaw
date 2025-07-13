// app/api/staff/route.ts
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// Mock staff data for a legal practice
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
  },
  {
    id: 'staff-6',
    userId: 'user-6',
    name: 'David Martinez',
    email: 'david.martinez@lawfirm.com',
    phone: '(555) 678-9012',
    position: 'Legal Secretary',
    department: 'General Support',
    color: '#06B6D4',
    isActive: true,
    specialties: ['Document Management', 'Client Communication', 'Court Filings'],
    user: {
      id: 'user-6',
      name: 'David Martinez',
      email: 'david.martinez@lawfirm.com',
      role: 'STAFF',
    },
    createdAt: new Date('2025-05-15T10:00:00Z'),
    updatedAt: new Date('2025-07-01T10:00:00Z'),
  }
];

export async function GET(request: Request) {
  try {
    // For now, skip authentication check since we don't have real sessions
    // In real version, this would check session
    
    // Filter for active staff only (same as original)
    const activeStaff = mockStaff.filter(staff => staff.isActive);
    
    // Sort by name (same as original)
    const sortedStaff = activeStaff.sort((a, b) => a.name.localeCompare(b.name));
    
    // Return staff with same structure as real API
    const staffResponse = sortedStaff.map(staff => ({
      id: staff.id,
      userId: staff.userId,
      name: staff.name,
      email: staff.email,
      phone: staff.phone,
      position: staff.position,
      department: staff.department,
      color: staff.color,
      isActive: staff.isActive,
      specialties: staff.specialties,
      barNumber: staff.barNumber,
      licenseState: staff.licenseState,
      certification: staff.certification,
      user: staff.user,
      createdAt: staff.createdAt.toISOString(),
      updatedAt: staff.updatedAt.toISOString(),
    }));

    return NextResponse.json(staffResponse);
  } catch (error) {
    console.error('Error fetching staff:', error);
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
    const { name, email, phone, position, department, color, specialties, barNumber, licenseState } = data;

    // Validate required fields
    if (!name || !email) {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { error: 'Please enter a valid email address' },
        { status: 400 }
      );
    }

    // Check if staff with this email already exists in mock data
    const existingStaff = mockStaff.find(staff => 
      staff.email.toLowerCase() === email.toLowerCase()
    );
    
    if (existingStaff) {
      return NextResponse.json(
        { error: 'Staff member with this email already exists' },
        { status: 400 }
      );
    }

    // Generate IDs
    const userId = `user-${Date.now()}`;
    const staffId = `staff-${Date.now()}`;

    // Create mock user object
    const newUser = {
      id: userId,
      name,
      email: email.toLowerCase(),
      role: position?.toLowerCase().includes('attorney') ? 'ATTORNEY' : 'STAFF',
    };

    // Create mock staff object
    const newStaff = {
      id: staffId,
      userId: userId,
      name,
      email: email.toLowerCase(),
      phone: phone || null,
      position: position || 'Staff Member',
      department: department || 'Roberson Law',
      color: color || '#3b82f6',
      isActive: true,
      specialties: specialties || [],
      barNumber: barNumber || null,
      licenseState: licenseState || null,
      user: newUser,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Log the "created" staff member (for development purposes)
    console.log('Mock staff creation:', newStaff);

    // Return response with same structure as real API
    const staffResponse = {
      ...newStaff,
      createdAt: newStaff.createdAt.toISOString(),
      updatedAt: newStaff.updatedAt.toISOString(),
    };

    return NextResponse.json(staffResponse, { status: 201 });
  } catch (error) {
    console.error('Error creating staff:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
