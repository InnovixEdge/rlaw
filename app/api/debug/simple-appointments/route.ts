export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';

export async function GET() {
  try {
    console.log('Testing appointments table...');
    
    // Test if appointments table exists and works
    const appointmentCount = await prisma.appointment.count();
    
    return NextResponse.json({
      success: true,
      message: 'Appointments table working',
      count: appointmentCount,
      tableExists: true
    });
    
  } catch (error) {
    console.error('Appointments test error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      errorName: error instanceof Error ? error.name : 'Unknown'
    }, { status: 500 });
  }
}
