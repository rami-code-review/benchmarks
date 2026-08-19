//go:build lg_greenhouse_controller

// Package benchmarks contains greenhouse controller fixtures: sensor
// assignment, vent scheduling and humidity rebalancing.
package benchmarks

// Zone is one climate-controlled bay in the greenhouse.
type Zone struct {
	ID        string
	Humidity  float64
	FloorRH   float64
	CeilingRH float64
}

// Sensor is a probe bound to exactly one zone.
type Sensor struct {
	ID     string
	ZoneID string
}

// VentSchedule describes when a zone's vents may open.
type VentSchedule struct {
	Enabled   bool
	OpenHour  int
	CloseHour int
}

func assignZoneSensors(zones []Zone, sensors []Sensor) map[string]string {
	byZone := make(map[string]string, len(sensors))
	for _, s := range sensors {
		byZone[s.ZoneID] = s.ID
	}
	assigned := make(map[string]string, len(zones))
	for _, z := range zones {
		if id, ok := byZone[z.ID]; ok {
			assigned[z.ID] = id
		}
	}
	return assigned
}

// IsVentingEnabled reports whether the vents may open at the given hour.
func (v VentSchedule) IsVentingEnabled(hour int) bool {
	if hour < v.OpenHour || hour >= v.CloseHour {
		return false
	}
	return v.Enabled
}

func rebalanceHumidity(z *Zone, reading float64) (string, float64) {
	previous := z.Humidity
	z.Humidity = reading
	if z.Humidity > z.CeilingRH {
		return "vent", previous
	}
	if z.Humidity < z.FloorRH {
		return "mist", previous
	}
	return "hold", previous
}

func zonesNeedingAttention(zones []Zone) []string {
	var ids []string
	for _, z := range zones {
		if z.Humidity > z.CeilingRH || z.Humidity < z.FloorRH {
			ids = append(ids, z.ID)
		}
	}
	return ids
}
