// Notice identity for the daily digest.

import type { Notice } from "./xf_notifications";

export function digestKey(n: Notice): string { return n.userId + ":" + n.channel + ":" + n.eventId; }
