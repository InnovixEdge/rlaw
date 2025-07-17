import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();
    
    console.log('Testing auth for:', email);
    
    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        name: true,
        password: true,
        role: true
      }
    });
    
    if (!user) {
      return NextResponse.json({
        success: false,
        error: 'User not found',
        email
      });
    }
    
    console.log('User found:', { id: user.id, email: user.email, hasPassword: !!user.password });
    
    if (!user.password) {
      return NextResponse.json({
        success: false,
        error: 'User has no password',
        user: { ...user, password: undefined }
      });
    }
    
    // Test password
    const isValid = await bcrypt.compare(password, user.password);
    
    return NextResponse.json({
      success: true,
      message: 'Auth test complete',
      user: { ...user, password: undefined },
      passwordValid: isValid,
      passwordLength: user.password.length,
      providedPassword: password
    });
    
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
