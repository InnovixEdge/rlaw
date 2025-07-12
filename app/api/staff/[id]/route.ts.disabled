
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/db';
import { authOptions } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if staff exists
    const existingStaff = await prisma.staff.findUnique({
      where: { id: params.id },
    });

    if (!existingStaff) {
      return NextResponse.json(
        { error: 'Staff member not found' },
        { status: 404 }
      );
    }

    // Check if staff has any appointments
    const appointmentCount = await prisma.appointment.count({
      where: {
        staffId: params.id,
        status: {
          not: 'CANCELLED',
        },
      },
    });

    if (appointmentCount > 0) {
      return NextResponse.json(
        { error: 'Cannot delete staff member with active appointments' },
        { status: 400 }
      );
    }

    // Soft delete by setting isActive to false
    await prisma.staff.update({
      where: { id: params.id },
      data: {
        isActive: false,
      },
    });

    return NextResponse.json({ message: 'Staff member deleted successfully' });
  } catch (error) {
    console.error('Error deleting staff:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
