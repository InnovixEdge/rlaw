import { Router } from 'express';
import { fetchAvailability, createEvent, updateEvent, deleteEvent } from '../services/sync';

const router = Router();

// Get merged availability for multiple users
router.get('/availability', async (req, res) => {
  try {
    const userIds = (req.query.users as string).split(',');
    const start = req.query.start as string;
    const end = req.query.end as string;
    const slots = await fetchAvailability(userIds, start, end);
    res.json(slots);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch availability' });
  }
});

// Create a new event on all linked calendars
router.post('/events', async (req, res) => {
  try {
    const event = await createEvent(req.body);
    res.json(event);
  } catch (e) {
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Update an event across calendars
router.put('/events/:id', async (req, res) => {
  try {
    const updated = await updateEvent(req.params.id, req.body);
    res.json(updated);
  } catch (e) {
    res.status(500).json({ error: 'Failed to update event' });
  }
});

// Delete an event across calendars
router.delete('/events/:id', async (req, res) => {
  try {
    await deleteEvent(req.params.id);
    res.sendStatus(204);
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Example webhook handler for push notifications from Google or Outlook.
router.post('/webhook', (req, res) => {
  // TODO: verify and process webhook payloads to keep calendars in sync
  console.log('Received webhook event', req.body);
  res.sendStatus(200);
});

export default router;
