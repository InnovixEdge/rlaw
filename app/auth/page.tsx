'use client';

export default function AuthPage() {
  const handleGoogleAuth = () => {
    const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
    const redirectUri = `${window.location.origin}/api/auth/callback`;
    const scope = 'https://www.googleapis.com/auth/calendar.readonly';
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${clientId}&` +
      `redirect_uri=${redirectUri}&` +
      `scope=${scope}&` +
      `response_type=code&` +
      `access_type=offline&` +
      `prompt=consent`;
    
    window.location.href = authUrl;
  };

  return (
    <div className="p-8">
      <h1>Authorize Google Calendar</h1>
      <button 
        onClick={handleGoogleAuth}
        className="bg-blue-500 text-white px-4 py-2 rounded"
      >
        Connect Google Calendar
      </button>
    </div>
  );
}
