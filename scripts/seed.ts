
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');

  // Create demo admin user
  const hashedPassword = await bcrypt.hash('johndoe123', 12);
  
  const adminUser = await prisma.user.upsert({
    where: { email: 'john@doe.com' },
    update: {},
    create: {
      name: 'John Doe',
      email: 'john@doe.com',
      password: hashedPassword,
      role: 'ADMIN',
    },
  });

  console.log('✅ Created admin user:', adminUser.email);

  // Create admin staff profile
  const adminStaff = await prisma.staff.upsert({
    where: { userId: adminUser.id },
    update: {},
    create: {
      userId: adminUser.id,
      name: 'John Doe',
      email: 'john@doe.com',
      phone: '(555) 123-4567',
      position: 'Managing Attorney',
      department: 'Administration',
      color: '#3b82f6',
    },
  });

  console.log('✅ Created admin staff profile');

  // Create sample staff members
  const staffMembers = [
    {
      name: 'Sarah Johnson',
      email: 'sarah@robersonlaw.com',
      phone: '(555) 234-5678',
      position: 'Senior Attorney',
      department: 'Corporate Law',
      color: '#10b981',
    },
    {
      name: 'Michael Chen',
      email: 'michael@robersonlaw.com',
      phone: '(555) 345-6789',
      position: 'Attorney',
      department: 'Criminal Law',
      color: '#8b5cf6',
    },
    {
      name: 'Emily Rodriguez',
      email: 'emily@robersonlaw.com',
      phone: '(555) 456-7890',
      position: 'Junior Attorney',
      department: 'Family Law',
      color: '#f59e0b',
    },
    {
      name: 'David Kim',
      email: 'david@robersonlaw.com',
      phone: '(555) 567-8901',
      position: 'Legal Assistant',
      department: 'General Practice',
      color: '#ef4444',
    },
  ];

  for (const staffData of staffMembers) {
    // Create user for each staff member
    const user = await prisma.user.upsert({
      where: { email: staffData.email },
      update: {},
      create: {
        name: staffData.name,
        email: staffData.email,
        role: 'STAFF',
        // No password - they'll need to set it separately
      },
    });

    // Create staff profile
    await prisma.staff.upsert({
      where: { userId: user.id },
      update: {},
      create: {
        userId: user.id,
        name: staffData.name,
        email: staffData.email,
        phone: staffData.phone,
        position: staffData.position,
        department: staffData.department,
        color: staffData.color,
      },
    });

    console.log(`✅ Created staff member: ${staffData.name}`);
  }

  // Create admin notification settings
  await prisma.notificationSetting.upsert({
    where: { userId: adminUser.id },
    update: {},
    create: {
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

  console.log('✅ Created notification settings');

  // Get all staff for creating sample appointments
  const allStaff = await prisma.staff.findMany({
    where: { isActive: true },
  });

  // Create sample appointments
  const sampleAppointments = [
    {
      title: 'Initial Consultation - Smith vs. Johnson',
      description: 'Initial consultation for personal injury case',
      startTime: new Date(new Date().setHours(9, 0, 0, 0)),
      endTime: new Date(new Date().setHours(10, 0, 0, 0)),
      clientName: 'Robert Smith',
      clientEmail: 'robert.smith@email.com',
      clientPhone: '(555) 111-2222',
      clientNotes: 'Referred by previous client. Car accident case.',
      type: 'CONSULTATION' as const,
      status: 'SCHEDULED' as const,
      staffId: allStaff[0]?.id,
    },
    {
      title: 'Follow-up Meeting - Davis Estate',
      description: 'Follow-up meeting for estate planning',
      startTime: new Date(new Date().setDate(new Date().getDate() + 1)),
      endTime: new Date(new Date().setDate(new Date().getDate() + 1)),
      clientName: 'Margaret Davis',
      clientEmail: 'margaret.davis@email.com',
      clientPhone: '(555) 333-4444',
      clientNotes: 'Needs to finalize will documents.',
      type: 'FOLLOW_UP' as const,
      status: 'CONFIRMED' as const,
      staffId: allStaff[1]?.id,
    },
    {
      title: 'Document Review - ABC Corp Contract',
      description: 'Review of merger and acquisition documents',
      startTime: new Date(new Date().setDate(new Date().getDate() + 2)),
      endTime: new Date(new Date().setDate(new Date().getDate() + 2)),
      clientName: 'James Wilson',
      clientEmail: 'james.wilson@abccorp.com',
      clientPhone: '(555) 555-6666',
      clientNotes: 'Urgent contract review needed.',
      type: 'DOCUMENT_REVIEW' as const,
      status: 'SCHEDULED' as const,
      staffId: allStaff[2]?.id,
    },
    {
      title: 'Court Preparation - Thompson Case',
      description: 'Preparation for upcoming court hearing',
      startTime: new Date(new Date().setDate(new Date().getDate() + 3)),
      endTime: new Date(new Date().setDate(new Date().getDate() + 3)),
      clientName: 'Lisa Thompson',
      clientEmail: 'lisa.thompson@email.com',
      clientPhone: '(555) 777-8888',
      clientNotes: 'Divorce proceedings - final hearing preparation.',
      type: 'COURT_PREP' as const,
      status: 'SCHEDULED' as const,
      staffId: allStaff[3]?.id,
    },
  ];

  for (const appointmentData of sampleAppointments) {
    if (appointmentData.staffId) {
      await prisma.appointment.create({
        data: {
          ...appointmentData,
          createdById: adminUser.id,
        },
      });
    }
  }

  console.log('✅ Created sample appointments');

  console.log('🎉 Database seed completed successfully!');
  console.log('');
  console.log('Demo Login Credentials:');
  console.log('Email: john@doe.com');
  console.log('Password: johndoe123');
  console.log('');
}

main()
  .catch((e) => {
    console.error('❌ Error during seed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
