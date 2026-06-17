export interface ApiError {
  code: string
  message: string
  detail?: Record<string, unknown>
}

export interface ApiResponse<T> {
  ok: boolean
  data?: T
  error?: ApiError
}

export const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

export class ApiClientError extends Error {
  code: string
  detail?: Record<string, unknown>

  constructor(error: ApiError) {
    super(error.message)
    this.code = error.code
    this.detail = error.detail
  }
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('access_token')
  const headers = new Headers(options.headers)
  headers.set('Content-Type', 'application/json')
  if (token) headers.set('Authorization', `Bearer ${token}`)

  const response = await fetch(`${apiBaseUrl}${path}`, { ...options, headers })
  const body = (await response.json()) as ApiResponse<T>
  if (!body.ok || !response.ok) {
    throw new ApiClientError(body.error || { code: 'HTTP_ERROR', message: response.statusText })
  }
  return body.data as T
}
