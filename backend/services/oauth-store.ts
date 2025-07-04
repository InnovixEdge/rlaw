import { kv } from '@vercel/kv'

interface TokenData {
  googleAccessToken?: string
  outlookAccessToken?: string
}

export async function storeTokensForUser(userId: string, tokens: TokenData) {
  await kv.hmset(`tokens:${userId}`, tokens as Record<string, unknown>)
}

export async function getTokensForUser(userId: string): Promise<TokenData> {
  const tokens = await kv.hgetall<TokenData>(`tokens:${userId}`)
  return tokens || {}
}
