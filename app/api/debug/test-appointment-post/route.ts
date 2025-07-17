import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    console.log('🧪 Testing appointment POST...');
    
    // Get the request body
    const body = await request.json();
    console.log('Request body:', body);
    
    // Get session
    const session = await getServerSession(authOptions);
    console.log('Session:', session?.user?.id);
    
    // Try to create appointment with fixed data
    const testData = {
      title: 'Test Appointment',
      clientName: 'Test Client',
      clientEmail: 'test@client.com',
      startTime: new Date('2025-07-17T10:00:00.000Z'),
      endTime: new Date('2025-07-17T11:00:00.000Z'),
      staffId: 'cm123staff', // We know this exists
      createdById: 'cm123admin', // We know this exists
    };
    
    console.log('Creating appointment with data:', testData);
    
    const appointment = await prisma.appointment.create({
      data: testData
    });
    
    console.log('Appointment created successfully:', appointment);
    
    return NextResponse.json({
      success: true,
      message: 'Test appointment created!',
      appointment: appointment,
      requestBody: body,
      sessionUserId: session?.user?.id
    });
    
  } catch (error) {
    console.error('Appointment creation error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}
