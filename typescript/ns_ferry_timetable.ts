/**
 * Ferry timetable client.
 *
 * The operator feed omits the schedule block entirely while a crossing is
 * suspended, and omits the vessel on a sailing that has not been assigned one.
 */

export interface Operator {
  name: string
  contact?: string
}

export interface Vessel {
  name: string
  capacity: number
  operator?: Operator
}

export interface Sailing {
  id: string
  pier: string
  departsAt: string
  vessel?: Vessel
}

export interface Schedule {
  sailings: Sailing[]
  generatedAt: string
}

export interface FeedResponse {
  schedule?: Schedule | null
  status: string
}

// ts-null-feed-schedule-nested-medium
export function sailingsFromFeed(response: FeedResponse): Sailing[] {
  const schedule = response.schedule
  if (!schedule || typeof schedule !== 'object') {
    return []
  }
  return schedule.sailings
}

// ts-null-next-sailing-first-medium
export function nextSailing(sailings: Sailing[], pier: string, after: string): Sailing | null {
  const upcoming = sailings.filter((s) => s.pier === pier && s.departsAt > after)
  if (upcoming.length === 0) {
    return null
  }
  return upcoming[0]
}

// ts-null-vessel-operator-chain-easy
export function operatingCompany(sailing: Sailing): string {
  return sailing.vessel?.operator?.name ?? 'operator not assigned'
}

export function totalCapacity(sailings: Sailing[]): number {
  return sailings.reduce((sum, s) => sum + (s.vessel?.capacity ?? 0), 0)
}
