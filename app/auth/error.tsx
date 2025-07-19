'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function AuthErrorPage() {
  const searchParams = useSearchParams();
  const [error, setError] = useState('unknown_error');

  useEffect(() => {
    const errorParam = searchParams.get('error');
    setError(errorParam || 'unknown_error');
  }, [searchParams]);

  const getErrorMessage = (errorCode: string) => {
    switch (errorCode) {
      case 'access_denied':
        return 'You denied access to your Google Calendar. Please try again and grant permission.';
      case 'no_code':
        return 'No authorization code was received from Google.';
      case 'callback_failed':
        return 'Failed to process the authorization callback.';
      case 'invalid_request':
        return 'Invalid request parameters were sent to Google.';
      default:
        return 'An unknown error occurred during authorization.';
    }
  };

  const getErrorTitle = (errorCode: string) => {
    switch (errorCode) {
      case 'access_denied':
        return 'Access Denied';
      case 'no_code':
        return 'Authorization Failed';
      case 'callback_failed':
        return 'Callback Error';
      default:
        return 'Authorization Error';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-white rounded-lg shadow-lg p-6">
        <div className="text-center">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
            <svg className="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          
          <h1 className="text-2xl font-bold text-gray-900 mb-2">
            {getErrorTitle(error)}
          </h1>
          
          <p className="text-gray-600 mb-6">
            {getErrorMessage(error)}
          </p>
          
          <div className="bg-red-50 rounded-lg p-4 mb-6">
            <h3 className="text-sm font-medium text-red-700 mb-1">Error Code:</h3>
            <p className="text-sm text-red-600 font-mono">{error}</p>
          </div>

          <div className="space-y-3">
            <button
              onClick={() => window.location.href = '/auth'}
              className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
            >
              Try Again
            </button>
            
            <button
              onClick={() => window.location.href = '/'}
              className="w-full bg-gray-200 text-gray-700 py-2 px-4 rounded-md hover:bg-gray-300 transition-colors"
            >
              Go to Dashboard
            </button>
          </div>

          <div className="mt-6 text-left bg-gray-50 rounded-lg p-4">
            <h3 className="text-sm font-medium text-gray-700 mb-2">Troubleshooting:</h3>
            <ul className="text-xs text-gray-600 space-y-1">
              <li>• Make sure you're signed into Google</li>
              <li>• Check that cookies and JavaScript are enabled</li>
              <li>• Try using an incognito/private window</li>
              <li>• Contact support if the problem persists</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
