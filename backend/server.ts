import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/auth';
import calendarRoutes from './routes/calendar';

// Load environment variables from .env
dotenv.config();

const app = express();
app.use(express.json());

// Authentication routes handle OAuth with Google and Outlook
app.use('/auth', authRoutes);
// Calendar routes manage syncing and event operations
app.use('/calendar', calendarRoutes);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});
