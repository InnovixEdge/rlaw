import { fetchAvailability } from '@/backend/services/sync';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const body = await req.json();
  const { userIds, start, end } = body;

  if (!userIds || !start || !end) {
    return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
  }

  try {
    const slots = await fetchAvailability(userIds, start, end);
    return NextResponse.json({ slots });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
