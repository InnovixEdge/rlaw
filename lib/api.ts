export async function getAvailability(users: string[], start: string, end: string) {
  const params = new URLSearchParams({ users: users.join(','), start, end });
  const res = await fetch(`/api/calendar/availability?${params.toString()}`);
  return res.json();
}

export async function createEvent(event: any) {
  const res = await fetch('/api/calendar/events', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(event),
  });
  return res.json();
}
