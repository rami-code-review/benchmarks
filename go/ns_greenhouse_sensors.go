//go:build ns_greenhouse_sensors

// Package benchmarks contains a greenhouse telemetry domain: sensor samples
// arriving as untyped payloads, and the calibration bench applied to them.
package benchmarks

import (
	"errors"
	"fmt"
)

// Reading is one decoded sensor sample.
type Reading struct {
	SensorID string
	Celsius  float64
}

// Calibration is the correction recorded for a sensor at install time.
type Calibration struct {
	Offset float64
	Scale  float64
}

// Bench holds the calibrations recorded for registered sensors. A sensor that
// has been registered but not yet walked by a technician has no entry.
type Bench struct {
	calibrations map[string]*Calibration
}

// CalibrationFor returns the recorded calibration, or nil for a sensor that
// has never been calibrated.
func (b *Bench) CalibrationFor(sensorID string) *Calibration {
	return b.calibrations[sensorID]
}

// go-null-payload-assert-medium
func sensorLabel(payload any) (string, error) {
	label, ok := payload.(string)
	if !ok {
		return "", errors.New("telemetry payload is not a sensor label")
	}
	return label, nil
}

// go-null-uncalibrated-sensor-hard
func correctedCelsius(b *Bench, r Reading) (float64, error) {
	cal := b.CalibrationFor(r.SensorID)
	if cal == nil {
		return 0, fmt.Errorf("sensor %s has no calibration on record", r.SensorID)
	}
	return r.Celsius*cal.Scale + cal.Offset, nil
}

func warmestReading(b *Bench, readings []Reading) (Reading, error) {
	var best Reading
	var bestCelsius float64
	found := false
	for _, r := range readings {
		corrected, err := correctedCelsius(b, r)
		if err != nil {
			continue
		}
		if !found || corrected > bestCelsius {
			best, bestCelsius, found = r, corrected, true
		}
	}
	if !found {
		return Reading{}, errors.New("no calibrated reading in batch")
	}
	return best, nil
}
