import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';

export async function GET() {
  try {
    const testEmail = 'john@doe.com';
    const testPassword = 'johndoe123';
    
    console.log('🔍 Starting detailed password test...');
    
    // Get user from database
    const user = await prisma.user.findUnique({
      where: { email: testEmail }
    });
    
    if (!user || !user.password) {
      return NextResponse.json({
        success: false,
        error: 'User or password not found'
      });
    }
    
    console.log('User found:', user.email);
    console.log('Stored hash:', user.password);
    console.log('Test password:', testPassword);
    
    // Test the password comparison step by step
    console.log('Testing bcrypt.compare...');
    const compareResult = await bcrypt.compare(testPassword, user.password);
    console.log('bcrypt.compare result:', compareResult);
    
    // Also test the hash that we know works
    const knownGoodHash = '$2a$12$3NTJP2rkJ/Dr/w18p27o.e/UdwsMLnjG7FBe/nQvA0DsTwniBIyCy';
    const knownHashTest = await bcrypt.compare(testPassword, knownGoodHash);
    console.log('Known good hash test:', knownHashTest);
    
    // Check if they're exactly the same
    const hashesMatch = user.password === knownGoodHash;
    console.log('Hashes exactly match:', hashesMatch);
    
    return NextResponse.json({
      success: true,
      userEmail: user.email,
      storedHashPrefix: user.password.substring(0, 20),
      storedHashLength: user.password.length,
      testPassword: testPassword,
      compareResult: compareResult,
      knownGoodHashTest: knownHashTest,
      hashesExactlyMatch: hashesMatch,
      storedHash: user.password,
      knownGoodHash: knownGoodHash
    });
    
  } catch (error) {
    console.error('Detailed test error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined
    }, { status: 500 });
  }
}
