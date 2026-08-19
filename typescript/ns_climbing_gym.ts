/**
 * Climbing-gym route board.
 *
 * Grades are entered by the route setters as free text, and the per-wall cache
 * is filled on first read, so both lookups here can come back with nothing.
 */

export interface Route {
  id: string
  wall: string
  grade: string
  setAt: string
}

const GRADE = /^V(\d+)(?:\+|-)?$/

const routesByWall = new Map<string, Route[]>()

// ts-null-grade-groups-hard
export function gradeNumber(grade: string): number {
  const groups = GRADE.exec(grade)
  if (groups === null) {
    return -1
  }
  return Number.parseInt(groups[1], 10)
}

// ts-null-wall-cache-get-hard
export function routesOnWall(wall: string): number {
  const cached = routesByWall.get(wall)
  if (cached === undefined) {
    return 0
  }
  return cached.length
}

export function cacheWall(wall: string, routes: Route[]): void {
  routesByWall.set(wall, routes)
}

export function hardestRoute(routes: Route[]): Route | null {
  let best: Route | null = null
  let bestGrade = -1
  for (const route of routes) {
    const n = gradeNumber(route.grade)
    if (n > bestGrade) {
      best = route
      bestGrade = n
    }
  }
  return best
}
