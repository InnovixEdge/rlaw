import { Router } from 'express';
import { googleAuthUrl, handleGoogleCallback /*outlookAuthUrl, handleOutlookCallback*/ } from '../services/oauth';

const router = Router();

// Redirect user to Google OAuth consent screen
router.get('/google', (req, res) => {
  res.redirect(googleAuthUrl());
});

// Redirect user to Outlook OAuth consent screen
/*
router.get('/outlook', (req, res) => {
  res.redirect(outlookAuthUrl());
});*/

// OAuth callback for Google
router.get('/google/callback', async (req, res) => {
  try {
    const tokens = await handleGoogleCallback(req.query.code as string);
    res.json(tokens);
  } catch (e) {
    res.status(500).json({ error: 'Google OAuth failed' });
  }
});

// OAuth callback for Outlook
/*
router.get('/outlook/callback', async (req, res) => {
  try {
    const tokens = await handleOutlookCallback(req.query.code as string);
    res.json(tokens);
  } catch (e) {
    res.status(500).json({ error: 'Outlook OAuth failed' });
  }
});*/

export default router;
