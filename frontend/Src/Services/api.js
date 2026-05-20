export async function startScan(target) {
  const response = await fetch('http://127.0.0.1:8000/api/scans/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ target }),
  })

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    throw new Error(errorData.detail || 'Failed to start scan')
  }

  return response.json()
}

export async function getHistory() {
  const response = await fetch('http://127.0.0.1:8000/api/scans/history')

  if (!response.ok) {
    throw new Error('Failed to fetch history')
  }

  return response.json()
}