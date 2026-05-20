export default function ErrorAlert({ message }) {
  if (!message) return null

  return (
    <div className="mt-6 rounded-2xl border border-red-200 bg-red-50 px-5 py-4 text-red-700">
      {message}
    </div>
  )
}