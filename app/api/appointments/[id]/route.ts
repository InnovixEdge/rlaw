// Temporarily disable this route - Prisma not configured
export {}
/*
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/db';
import { authOptions } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const data = await request.json();
    const {
      title,
      description,
      startTime,
      endTime,
      clientName,
      clientEmail,
      clientPhone,
      clientNotes,
      staffId,
      type,
      status,
    } = data;

    // Check if appointment exists
    const existingAppointment = await prisma.appointment.findUnique({
      where: { id: params.id },
    });

    if (!existingAppointment) {
      return NextResponse.json(
        { error: 'Appointment not found' },
        { status: 404 }
      );
    }

    // Check for scheduling conflicts (excluding current appointment)
    const conflictingAppointments = await prisma.appointment.findMany({
      where: {
        id: {
          not: params.id,
        },
        staffId,
        status: {
          not: 'CANCELLED',
        },
        OR: [
          {
            startTime: {
              lt: new Date(endTime),
            },
            endTime: {
              gt: new Date(startTime),
            },
          },
        ],
      },
    });

    if (conflictingAppointments.length > 0) {
      return NextResponse.json(
        { error: 'Time slot conflicts with existing appointment' },
        { status: 400 }
      );
    }

    const appointment = await prisma.appointment.update({
      where: { id: params.id },
      data: {
        title,
        description: description || null,
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        clientName,
        clientEmail,
        clientPhone: clientPhone || null,
        clientNotes: clientNotes || null,
        staffId,
        type: type || 'CONSULTATION',
        status: status || 'SCHEDULED',
      },
      include: {
        staff: {
          select: {
            id: true,
            name: true,
            email: true,
            color: true,
          },
        },
      },
    });

    return NextResponse.json(appointment);
  } catch (error) {
    console.error('Error updating appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Check if appointment exists
    const existingAppointment = await prisma.appointment.findUnique({
      where: { id: params.id },
    });

    if (!existingAppointment) {
      return NextResponse.json(
        { error: 'Appointment not found' },
        { status: 404 }
      );
    }

    await prisma.appointment.delete({
      where: { id: params.id },
    });

    return NextResponse.json({ message: 'Appointment deleted successfully' });
  } catch (error) {
    console.error('Error deleting appointment:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
*/
