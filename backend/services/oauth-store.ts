import { kv } from '@vercel/kv'

interface TokenData {
  googleAccessToken?: string
  outlookAccessToken?: string
}

export async function storeTokensForUser(userId: string, tokens: TokenData) {
  await kv.set(`tokens:${userId}`, tokens)
}

export async function getTokensForUser(userId: string): Promise<TokenData> {
  return (await kv.get(`tokens:${userId}`)) as TokenData || {}
}
