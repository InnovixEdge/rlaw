# Custom Calendar Scheduling Application

This project provides a starting point for building a calendar scheduling tool using Next.js for the frontend and Node.js with Express for the backend. It is intentionally lightweight and avoids external scheduling platforms such as Cal.com. The key logic for syncing with Google Calendar and Microsoft Outlook is implemented from scratch.

## Features

- Next.js frontend with Tailwind CSS styling
- Express backend with endpoints for authentication and calendar synchronization
- Skeleton code for integrating Google and Outlook OAuth2 flows
- Custom availability calculation to merge events from multiple calendars
- Example FullCalendar integration on the frontend
- Ready for deployment on platforms like Vercel

## Local Development

1. Copy `.env.example` to `.env` and fill in your OAuth credentials.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run both the Next.js and Express servers:
   ```bash
   npm run dev & npm run dev:server
   ```
4. Visit `http://localhost:3000` to view the calendar UI.

The Express server runs alongside Next.js under `backend/server.ts`.

## Deployment

See inline comments within the code for setup and configuration details. Provide environment variables for OAuth credentials, database connection, and other secrets in a `.env` file. Deploy the frontend to Vercel and the backend to your preferred Node.js host or serverless platform.

## Scheduling Logic Overview

- Each user connects their Outlook and Google calendars via OAuth.
- Events from both providers are fetched and merged chronologically.
- Free time slots are calculated by scanning gaps between events.
- New bookings are pushed to both calendars via their respective APIs.

Consult the `backend/services/sync.ts` file for detailed comments on the implementation.
