import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';

export async function GET() {
  try {
    console.log('🔍 Testing password for john@doe.com...');
    
    const user = await prisma.user.findUnique({
      where: { email: 'john@doe.com' }
    });
    
    if (!user || !user.password) {
      return NextResponse.json({
        success: false,
        error: 'User or password not found'
      });
    }
    
    // Test the exact password
    const testPassword = 'johndoe123';
    const isValid = await bcrypt.compare(testPassword, user.password);
    
    console.log('Password test result:', isValid);
    
    return NextResponse.json({
      success: true,
      userEmail: user.email,
      userName: user.name,
      passwordExists: !!user.password,
      passwordLength: user.password.length,
      testPassword: testPassword,
      passwordValid: isValid,
      passwordHash: user.password.substring(0, 20) + '...'
    });
    
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
