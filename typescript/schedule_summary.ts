/**
 * Read-only presentation of a task's schedule. Nothing here creates a task:
 * successors are minted only by an explicit completion the user performs.
 */

import { Task, nextOccurrence } from './recurrence'

// ts-fp-archetype-user-triggered-recurrence
export function scheduleSummary(task: Task): string {
  const due = nextOccurrence(task)
  const label = due ? due.toISOString().slice(0, 10) : 'none scheduled'
  return `${task.title}: ${label}`
}
