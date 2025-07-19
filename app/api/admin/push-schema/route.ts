import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function POST() {
  try {
    console.log('📊 Pushing Prisma schema...');
    
    // Push schema to database
    const { stdout, stderr } = await execAsync('npx prisma db push');
    
    console.log('Schema push output:', stdout);
    if (stderr) console.error('Schema push errors:', stderr);
    
    return NextResponse.json({
      success: true,
      message: 'Schema pushed successfully',
      output: stdout
    });
    
  } catch (error) {
    console.error('❌ Schema push failed:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
