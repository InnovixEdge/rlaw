import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';

export async function POST() {
  try {
    console.log('🌱 Starting database initialization...');

    // Check if users already exist
    const existingUsers = await prisma.user.count();
    if (existingUsers > 0) {
      return NextResponse.json({
        success: false,
        message: 'Database already initialized',
        userCount: existingUsers
      });
    }

    // Create admin user
    const hashedPassword = await bcrypt.hash('johndoe123', 12);
    
    const adminUser = await prisma.user.create({
      data: {
        name: 'John Doe',
        email: 'john@doe.com',
        password: hashedPassword,
        role: 'ADMIN',
      },
    });

    console.log('✅ Created admin user:', adminUser.email);

    // Create admin staff profile
    await prisma.staff.create({
      data: {
        userId: adminUser.id,
        name: 'John Doe',
        email: 'john@doe.com',
        phone: '(555) 123-4567',
        position: 'Managing Attorney',
        department: 'Administration',
        color: '#3b82f6',
      },
    });

    // Create notification settings
    await prisma.notificationSetting.create({
      data: {
        userId: adminUser.id,
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

    console.log('✅ Database initialized successfully!');

    return NextResponse.json({
      success: true,
      message: 'Database initialized successfully!',
      adminUser: {
        email: 'john@doe.com',
        password: 'johndoe123'
      }
    });

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}
