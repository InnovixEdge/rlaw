// app/api/auth/[...nextauth]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';

// Mock users database (same as other mock files)
const mockUsers = [
  {
    id: 'user-1',
    name: 'Office Manager',
    email: 'manager@lawfirm.com',
    password: '$2a$12$mock.hashed.password.for.demo123', // password: "password123"
    role: 'ADMIN',
    image: null,
  },
  {
    id: 'user-2',
    name: 'John Davis',
    email: 'john.davis@lawfirm.com', 
    password: '$2a$12$mock.hashed.password.for.attorney', // password: "attorney123"
    role: 'ATTORNEY',
    image: null,
  },
  {
    id: 'user-3',
    name: 'Lisa Chen',
    email: 'lisa.chen@lawfirm.com',
    password: '$2a$12$mock.hashed.password.for.staff', // password: "staff123"
    role: 'ATTORNEY', 
    image: null,
  }
];

// Simple session storage (in production, use proper session management)
const activeSessions = new Map<string, any>();

// Generate simple session token
function generateSessionToken(): string {
  return `mock-session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Handle different NextAuth endpoints
async function handleAuthRequest(request: NextRequest, path: string[]) {
  const endpoint = path[0];

  switch (endpoint) {
    case 'signin':
      return handleSignIn(request);
    case 'signout':
      return handleSignOut(request);
    case 'session':
      return handleSession(request);
    case 'csrf':
      return handleCSRF(request);
    case 'providers':
      return handleProviders(request);
    default:
      return NextResponse.json({ error: 'Unknown auth endpoint' }, { status: 404 });
  }
}

// Handle sign in
async function handleSignIn(request: NextRequest) {
  if (request.method === 'GET') {
    // Return sign-in page info
    return NextResponse.json({
      url: `${request.nextUrl.origin}/api/auth/signin`,
      providers: {
        credentials: {
          id: 'credentials',
          name: 'Credentials',
          type: 'credentials'
        }
      }
    });
  }

  if (request.method === 'POST') {
    try {
      const body = await request.json();
      const { email, password } = body;

      if (!email || !password) {
        return NextResponse.json(
          { error: 'Email and password are required' },
          { status: 400 }
        );
      }

      // Find user in mock database
      const user = mockUsers.find(u => u.email.toLowerCase() === email.toLowerCase());
      
      if (!user) {
        return NextResponse.json(
          { error: 'Invalid credentials' },
          { status: 401 }
        );
      }

      // For demo purposes, accept any password for mock users
      // In real app, you'd verify with bcrypt.compare(password, user.password)
      const validPassword = password === 'password123' || password === 'attorney123' || password === 'staff123';
      
      if (!validPassword) {
        return NextResponse.json(
          { error: 'Invalid credentials' },
          { status: 401 }
        );
      }

      // Create session
      const sessionToken = generateSessionToken();
      const session = {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          image: user.image
        },
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
        sessionToken
      };

      activeSessions.set(sessionToken, session);

      return NextResponse.json({
        url: `${request.nextUrl.origin}/dashboard`,
        user: session.user
      });
    } catch (error) {
      return NextResponse.json(
        { error: 'Sign in failed' },
        { status: 500 }
      );
    }
  }

  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
}

// Handle sign out
async function handleSignOut(request: NextRequest) {
  const sessionToken = request.cookies.get('next-auth.session-token')?.value;
  
  if (sessionToken) {
    activeSessions.delete(sessionToken);
  }

  return NextResponse.json({ url: `${request.nextUrl.origin}/` });
}

// Handle session check
async function handleSession(request: NextRequest) {
  const sessionToken = request.cookies.get('next-auth.session-token')?.value ||
                      request.headers.get('authorization')?.replace('Bearer ', '');

  if (!sessionToken) {
    return NextResponse.json(null);
  }

  const session = activeSessions.get(sessionToken);
  
  if (!session || new Date(session.expires) < new Date()) {
    activeSessions.delete(sessionToken);
    return NextResponse.json(null);
  }

  return NextResponse.json(session);
}

// Handle CSRF token
async function handleCSRF(request: NextRequest) {
  return NextResponse.json({
    csrfToken: `mock-csrf-${Date.now()}`
  });
}

// Handle providers
async function handleProviders(request: NextRequest) {
  return NextResponse.json({
    credentials: {
      id: 'credentials',
      name: 'Credentials',
      type: 'credentials',
      signinUrl: `${request.nextUrl.origin}/api/auth/signin/credentials`,
      callbackUrl: `${request.nextUrl.origin}/api/auth/callback/credentials`
    }
  });
}

// Main handler
export async function GET(
  request: NextRequest,
  { params }: { params: { nextauth: string[] } }
) {
  return handleAuthRequest(request, params.nextauth);
}

export async function POST(
  request: NextRequest,
  { params }: { params: { nextauth: string[] } }
) {
  return handleAuthRequest(request, params.nextauth);
}
