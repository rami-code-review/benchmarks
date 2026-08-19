export interface ZoneReading {
  zoneId: string
  humidity: number
  takenAt: string
}

export interface ZoneApi {
  readingsForZone(zoneId: string): Promise<ZoneReading[]>
}

export interface ZoneLogger {
  error(message: string, cause: unknown): void
}

export async function loadZoneReadings(
  api: ZoneApi,
  logger: ZoneLogger,
  zoneId: string,
  onError: (message: string) => void,
): Promise<ZoneReading[]> {
  try {
    return await api.readingsForZone(zoneId)
  } catch (error) {
    logger.error('readings for zone ' + zoneId + ' failed', error)
    onError('Sensor readings are unavailable right now.')
    return []
  }
}

export function normalizeHumidity(raw: string): number {
  const value = Number(raw)
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw new RangeError('humidity ' + raw + ' is outside the 0-100 range')
  }
  return Math.round(value * 10) / 10
}

export function driestZone(readings: ZoneReading[]): ZoneReading | undefined {
  return readings.reduce<ZoneReading | undefined>((driest, reading) => {
    if (!driest || reading.humidity < driest.humidity) {
      return reading
    }
    return driest
  }, undefined)
}
