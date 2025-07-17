export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/db';
import { authOptions } from '@/lib/auth';
import { UserRole } from '@prisma/client'; // Add the enum import

// GET: List staff
export async function GET(request: Request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Optionally, limit visibility to admins/managers only.
    // if (session.user.role !== 'ADMIN' && session.user.role !== 'MANAGER') {
    //   return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
    // }

    const staff = await prisma.staff.findMany({
      where: {
        isActive: true,
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
      orderBy: {
        name: 'asc',
      },
    });

    return NextResponse.json(staff);
  } catch (error) {
    console.error('Error fetching staff:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

// POST: Create staff
export async function POST(request: Request) {
  try {
    const session = await getServerSession(authOptions);

    // Only admins can create new staff
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
      role, // Optional role, sent from frontend (ADMIN, STAFF, ATTORNEY)
    } = data;

    // Validate required fields
    if (!name || !email) {
      return NextResponse.json(
        { error: 'Name and email are required' },
        { status: 400 }
      );
    }

    // Check if staff with this email already exists
    const existingStaff = await prisma.staff.findUnique({
      where: { email },
    });

    if (existingStaff) {
      return NextResponse.json(
        { error: 'Staff member with this email already exists' },
        { status: 400 }
      );
    }

    // Ensure role is valid, fallback to STAFF if not provided or invalid
    let safeRole: UserRole = UserRole.STAFF;
    if (
      typeof role === 'string' &&
      Object.values(UserRole).includes(role as UserRole)
    ) {
      // Only allow ADMIN to create other ADMINs if you want (optional):
      // if (role === UserRole.ADMIN && session.user.role !== UserRole.ADMIN) {
      //   safeRole = UserRole.STAFF;
      // } else {
      //   safeRole = role as UserRole;
      // }
      safeRole = role as UserRole;
    }

    // Create user first (no password for now)
    const user = await prisma.user.create({
      data: {
        name,
        email,
        role: safeRole,
      },
    });

    // Create staff profile
    const staff = await prisma.staff.create({
      data: {
        userId: user.id,
        name,
        email,
        phone: phone || null,
        position: position || 'Staff Member',
        department: department || 'Roberson Law',
        color: color || '#3b82f6',
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

    return NextResponse.json(staff, { status: 201 });
  } catch (error) {
    console.error('Error creating staff:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
