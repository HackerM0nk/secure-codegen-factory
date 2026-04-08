// Singleton token management for dev mode
let cachedToken: string | null = null;

export async function getAuthToken(): Promise<string> {
  if (cachedToken) return cachedToken;

  const res = await fetch("/api/auth/dev-login", { method: "POST" });
  if (!res.ok)
    throw new Error(
      "Failed to get dev token. Run: npx prisma db push && npx tsx prisma/seed.ts"
    );
  const data = await res.json();
  cachedToken = data.token;
  return cachedToken!;
}

export function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

export function clearToken(): void {
  cachedToken = null;
}
