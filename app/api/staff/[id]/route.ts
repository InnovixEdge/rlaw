export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/db';
import { authOptions } from '@/lib/auth';
import { AppointmentStatus, UserRole } from '@prisma/client';

// PATCH: Edit staff (including role)
export async function PATCH(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);

    // Only admins can edit staff
    if (!session?.user?.id || session.user.role !== 'ADMIN') {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    }

    const data = await request.json();
    const {
      name,
      email,
      phone,
      position,
      department,
      color,
      role // Optional: update the user's role
    } = data;

    // Update staff profile
    const staff = await prisma.staff.update({
      where: { id: params.id },
      data: {
        name,
        email,
        phone,
        position,
        department,
        color,
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });

    // If valid role provided, update user role as well
    if (role && Object.values(UserRole).includes(role)) {
      await prisma.user.update({
        where: { id: staff.userId },
        data: { role },
      });
    }

    // Return fresh profile (with updated user/role)
    const updatedStaff = await prisma.staff.findUnique({
      where: { id: params.id },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
          },
        },
      },
    });

    return NextResponse.json(updatedStaff, { status: 200 });
  } catch (error) {
    console.error('Error updating staff:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// DELETE: Soft-delete staff (only if no active appointments)
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

    // Check if staff has any appointments (not CANCELLED)
    const appointmentCount = await prisma.appointment.count({
      where: {
        staffId: params.id,
        status: {
          not: AppointmentStatus.CANCELLED,
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
