import { request } from './client'

export interface UserInfo {
  username: string
  role: 'viewer' | 'trader' | 'admin'
}

export async function login(username: string, password: string) {
  return request<{ access_token: string; token_type: string; user: UserInfo }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  })
}

export async function me() {
  return request<UserInfo>('/api/auth/me')
}
