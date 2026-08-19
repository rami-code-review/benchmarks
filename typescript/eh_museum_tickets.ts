export interface Reservation {
  id: string
  visitorId: string
  slotId: string
}

export interface TicketApi {
  createReservation(visitorId: string, slotId: string): Promise<Reservation>
  sendConfirmation(reservationId: string): Promise<void>
}

export interface TicketLogger {
  warn(message: string, cause: unknown): void
}

export class TicketApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message)
    this.name = 'TicketApiError'
  }
}

export class SlotFullError extends Error {}

export class PaymentDeclinedError extends Error {}

export async function reserveTicket(
  api: TicketApi,
  logger: TicketLogger,
  visitorId: string,
  slotId: string,
): Promise<Reservation> {
  const reservation = await api.createReservation(visitorId, slotId)
  try {
    await api.sendConfirmation(reservation.id)
  } catch (error) {
    logger.warn('confirmation was not sent for ' + reservation.id, error)
  }
  return reservation
}

export function describeBookingFailure(error: unknown): string {
  if (error instanceof SlotFullError) {
    return 'That time slot is fully booked.'
  }
  if (error instanceof PaymentDeclinedError) {
    return 'Your card was declined.'
  }
  return 'Something went wrong booking your visit.'
}

export async function uploadFloorPlan(file: Blob, endpoint: string): Promise<void> {
  const response = await fetch(endpoint, { method: 'POST', body: file })
  if (!response.ok) {
    throw new TicketApiError(
      'floor plan was rejected with status ' + response.status,
      response.status,
      await response.text(),
    )
  }
}
