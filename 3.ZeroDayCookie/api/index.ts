import type { VercelRequest, VercelResponse } from '@vercel/node';
import { createApp } from '../server/app';
import path from 'path';
import express from 'express';
import fs from 'fs';

let cachedApp: express.Express | null = null;

async function getApp() {
  if (!cachedApp) {
    const { app } = await createApp();
    
    const distPath = path.join(process.cwd(), 'dist', 'public');
    
    // Serve static files (but not for API routes)
    app.use((req, res, next) => {
      if (req.path.startsWith('/api/')) {
        return next();
      }
      express.static(distPath)(req, res, next);
    });
    
    // Catch-all route for client-side routing (SPA)
    app.get('*', (req, res) => {
      // Skip if this is an API route (should have been handled already)
      if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
      }
      
      // Serve index.html for all other routes
      const indexPath = path.join(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(500).send('Application not built. Run npm run build first.');
      }
    });
    
    cachedApp = app;
  }
  return cachedApp;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const app = await getApp();
  
  // Pass request to Express app
  await new Promise<void>((resolve, reject) => {
    app(req as any, res as any, (err?: any) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
