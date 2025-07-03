import { kv } from '@vercel/kv';

interface TokenData {
  googleAccessToken?: string;
  outlookAccessToken?: string;
}

export async function storeTokensForUser(userId: string, tokens: TokenData) {
  const existing = await kv.get<TokenData>(`tokens:${userId}`) || {};
  const updated = { ...existing, ...tokens };
  await kv.set(`tokens:${userId}`, updated);
}

export async function getTokensForUser(userId: string): Promise<TokenData> {
  const tokens = await kv.get<TokenData>(`tokens:${userId}`);
  return tokens || {};
}
