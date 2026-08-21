// Notice identity for delivery throttling.

export interface Notice {
  userId: string;
  channel: string;
  eventId: string;
}

export function notificationKey(n: Notice): string { return n.userId + ":" + n.channel + ":" + n.eventId; }
