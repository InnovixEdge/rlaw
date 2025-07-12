// Temporarily disable this route
export {}
/*
import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/db';

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

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { message: 'User with this email already exists' },
        { status: 400 }
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: 'STAFF',
      },
    });

    // Create staff profile
    await prisma.staff.create({
      data: {
        userId: user.id,
        name,
        email,
        phone: phone || null,
        position: 'Staff Member',
        department: 'Roberson Law',
        color: '#3b82f6',
      },
    });

    // Create notification settings
    await prisma.notificationSetting.create({
      data: {
        userId: user.id,
        emailEnabled: true,
        emailConfirmation: true,
        emailReminder: true,
        emailReminderMinutes: 60,
        smsEnabled: false,
        smsConfirmation: false,
        smsReminder: false,
        smsReminderMinutes: 30,
      },
    });

    return NextResponse.json(
      { message: 'User created successfully', userId: user.id },
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
*/
