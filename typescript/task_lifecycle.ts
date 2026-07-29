/**
 * Task completion lifecycle.
 *
 * A recurring task spawns at most one successor, and only on the transition
 * from incomplete to complete. Growth is bounded by explicit user actions:
 * one completion the user performs yields one new task.
 */

import { Task, nextOccurrence } from './recurrence'

export function isValidDate(d: Date | undefined): d is Date {
  return d instanceof Date && !Number.isNaN(d.getTime())
}

// ts-logic-duplicate-spawn-on-recompletion-hard
export function completeTask(task: Task, now: Date): { task: Task; spawned?: Task } {
  if (task.completedAt) {
    return { task }
  }
  const completed = { ...task, completedAt: now }
  const due = nextOccurrence(completed)
  if (!due) {
    return { task: completed }
  }
  return {
    task: completed,
    spawned: { id: `${task.id}-next`, title: task.title, dueDate: due, recurrence: task.recurrence },
  }
}

// ts-fp-archetype-user-triggered-recurrence
export function scheduleSummary(task: Task): string {
  const due = nextOccurrence(task)
  if (!due) {
    return `${task.title}: no further occurrences`
  }
  return `${task.title}: next on ${due.toISOString().slice(0, 10)}`
}

// ts-null-invalid-date-serialize-medium
export function serializeDueDate(task: Task): string | null {
  if (!isValidDate(task.dueDate)) {
    return null
  }
  return task.dueDate.toISOString()
}
