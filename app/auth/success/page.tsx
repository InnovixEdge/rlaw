'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function AuthSuccessPage() {
  const searchParams = useSearchParams();
  const [tokens, setTokens] = useState({
    access_token: false,
    refresh_token: false
  });

  useEffect(() => {
    setTokens({
      access_token: searchParams.get('access_token') === 'received',
      refresh_token: searchParams.get('refresh_token') === 'received'
    });
  }, [searchParams]);

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6">
        <div className="text-center">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
            <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          
          <h1 className="text-2xl font-bold text-gray-900 mb-2">
            Authorization Successful!
          </h1>
          
          <p className="text-gray-600 mb-6">
            Your Google Calendar has been successfully connected to your legal calendar app.
          </p>
          
          <div className="bg-gray-50 rounded-lg p-4 mb-6">
            <h3 className="text-sm font-medium text-gray-700 mb-2">Tokens Received:</h3>
            <div className="space-y-1 text-sm">
              <div className="flex justify-between">
                <span>Access Token:</span>
                <span className={tokens.access_token ? 'text-green-600' : 'text-red-600'}>
                  {tokens.access_token ? '✓ Received' : '✗ Missing'}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Refresh Token:</span>
                <span className={tokens.refresh_token ? 'text-green-600' : 'text-red-600'}>
                  {tokens.refresh_token ? '✓ Received' : '✗ Missing'}
                </span>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => window.location.href = '/'}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
            >
              Go to Dashboard
            </button>
            
            <button
              onClick={() => window.location.href = '/api/calendar/google'}
              className="w-full bg-gray-200 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-300 transition-colors"
            >
              Test Calendar API
            </button>
          </div>

          <p className="text-xs text-gray-500 mt-4">
            You can now close this window and return to your application.
          </p>
        </div>
      </div>
    </div>
  );
}
