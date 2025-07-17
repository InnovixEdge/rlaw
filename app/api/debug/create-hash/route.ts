import { NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';

export async function GET() {
  try {
    const password = 'johndoe123';
    
    // Create hash using the same bcrypt library
    const hash = await bcrypt.hash(password, 12);
    
    // Test it immediately
    const isValid = await bcrypt.compare(password, hash);
    
    return NextResponse.json({
      success: true,
      password: password,
      hash: hash,
      isValid: isValid,
      sqlUpdate: `UPDATE users SET password = '${hash}' WHERE email = 'john@doe.com';`
    });
    
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
