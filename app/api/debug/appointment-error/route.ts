export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';

export async function GET() {
  try {
    console.log('🔍 Debugging appointment creation...');
    
    // Test 1: Check session
    const session = await getServerSession(authOptions);
    console.log('Session:', session);
    
    // Test 2: Check staff
    const staffMembers = await prisma.staff.findMany();
    console.log('Staff members:', staffMembers);
    
    // Test 3: Check users
    const users = await prisma.user.findMany({
      select: { id: true, email: true, name: true }
    });
    console.log('Users:', users);
    
    return NextResponse.json({
      success: true,
      debug: {
        hasSession: !!session,
        sessionUserId: session?.user?.id,
        staffCount: staffMembers.length,
        staffMembers: staffMembers,
        userCount: users.length,
        users: users
      }
    });
    
  } catch (error) {
    console.error('Debug error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}
