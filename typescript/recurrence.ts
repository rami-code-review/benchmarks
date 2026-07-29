/**
 * Recurrence helpers for scheduled tasks.
 *
 * Month arithmetic must not overflow: advancing January 31 by one month has to
 * produce the last valid day of February, not roll forward into March.
 */

export interface Task {
  id: string
  title: string
  dueDate?: Date
  recurrence?: 'daily' | 'weekly' | 'monthly'
  completedAt?: Date
}

export function addDays(from: Date, days: number): Date {
  const next = new Date(from.getTime())
  next.setUTCDate(next.getUTCDate() + days)
  return next
}

// ts-logic-month-overflow-hard
export function addMonth(from: Date): Date {
  const year = from.getUTCFullYear()
  const month = from.getUTCMonth()
  const day = from.getUTCDate()
  const lastOfNext = new Date(Date.UTC(year, month + 2, 0)).getUTCDate()
  return new Date(Date.UTC(year, month + 1, Math.min(day, lastOfNext)))
}

export function nextOccurrence(task: Task): Date | undefined {
  if (!task.dueDate || !task.recurrence) {
    return undefined
  }
  switch (task.recurrence) {
    case 'daily':
      return addDays(task.dueDate, 1)
    case 'weekly':
      return addDays(task.dueDate, 7)
    case 'monthly':
      return addMonth(task.dueDate)
  }
}
