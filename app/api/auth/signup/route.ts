// app/api/auth/signup/route.ts
import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';

// Mock existing users (simulates database records)
const mockExistingUsers = [
  {
    id: 'user-1',
    name: 'Office Manager',
    email: 'manager@lawfirm.com',
    role: 'ADMIN'
  },
  {
    id: 'user-2', 
    name: 'John Davis',
    email: 'john.davis@lawfirm.com',
    role: 'ATTORNEY'
  },
  {
    id: 'user-3',
    name: 'Lisa Chen', 
    email: 'lisa.chen@lawfirm.com',
    role: 'ATTORNEY'
  }
];

export async function POST(request: Request) {
  try {
    const { name, email, phone, password } = await request.json();

    // Validate required fields
    if (!name || !email || !password) {
      return NextResponse.json(
        { message: 'Name, email, and password are required' },
        { status: 400 }
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { message: 'Please enter a valid email address' },
        { status: 400 }
      );
    }

    // Password strength validation
    if (password.length < 6) {
      return NextResponse.json(
        { message: 'Password must be at least 6 characters long' },
        { status: 400 }
      );
    }

    // Check if user already exists in mock data
    const existingUser = mockExistingUsers.find(user => 
      user.email.toLowerCase() === email.toLowerCase()
    );

    if (existingUser) {
      return NextResponse.json(
        { message: 'User with this email already exists' },
        { status: 400 }
      );
    }

    // Hash password (we can still use bcrypt since it's not database-dependent)
    const hashedPassword = await bcrypt.hash(password, 12);

    // Generate mock user ID
    const userId = `user-${Date.now()}`;

    // Create mock user object (in real version, this would be saved to database)
    const newUser = {
      id: userId,
      name,
      email: email.toLowerCase(),
      password: hashedPassword, // In real app, never return this
      role: 'STAFF',
      createdAt: new Date().toISOString(),
    };

    // Create mock staff profile
    const newStaffProfile = {
      id: `staff-${Date.now()}`,
      userId: userId,
      name,
      email: email.toLowerCase(),
      phone: phone || null,
      position: 'Staff Member',
      department: 'Roberson Law',
      color: '#3b82f6',
      createdAt: new Date().toISOString(),
    };

    // Create mock notification settings
    const notificationSettings = {
      id: `notif-${Date.now()}`,
      userId: userId,
      emailEnabled: true,
      emailConfirmation: true,
      emailReminder: true,
      emailReminderMinutes: 60,
      smsEnabled: false,
      smsConfirmation: false,
      smsReminder: false,
      smsReminderMinutes: 30,
      createdAt: new Date().toISOString(),
    };

    // Log the "created" user (for development purposes)
    console.log('Mock user registration:', {
      user: { ...newUser, password: '[HIDDEN]' },
      staff: newStaffProfile,
      notifications: notificationSettings
    });

    // Return success response (same format as real database version)
    return NextResponse.json(
      { 
        message: 'User created successfully', 
        userId: userId,
        user: {
          id: userId,
          name,
          email: email.toLowerCase(),
          role: 'STAFF',
          createdAt: newUser.createdAt
        },
        staff: newStaffProfile
      },
      { status: 201 }
    );
  } catch (error) {
    console.error('Signup error:', error);
    return NextResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    );
  }
}

// GET method to retrieve user info (optional, for testing)
export async function GET(request: Request) {
  try {
    // Return list of mock users (for development/testing)
    const safeUsers = mockExistingUsers.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }));

    return NextResponse.json({
      message: 'Mock users (for development)',
      users: safeUsers,
      totalUsers: safeUsers.length
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    return NextResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    );
  }
}
