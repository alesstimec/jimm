// Copyright 2026 Canonical.

package telemetry

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestParamsVerifyNormalizesDefaults(t *testing.T) {
	c := qt.New(t)

	ratio := 0.25
	params := Params{
		Endpoint:    " localhost:4317 ",
		SampleRatio: &ratio,
	}

	c.Assert(params.Verify(), qt.IsNil)
	c.Check(params.Endpoint, qt.Equals, "localhost:4317")
	c.Check(params.Protocol, qt.Equals, defaultTraceProtocol)
}

func TestParamsVerifyRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		params  Params
		wantErr string
	}{
		{
			name: "invalid protocol",
			params: Params{
				Endpoint: "localhost:4317",
				Protocol: "smtp",
			},
			wantErr: "unsupported OTLP trace protocol",
		},
		{
			name: "invalid sample ratio",
			params: Params{
				Endpoint:    "localhost:4317",
				SampleRatio: new(1.5),
			},
			wantErr: "OTLP trace sample ratio must be between 0 and 1",
		},
		{
			name: "invalid endpoint path without scheme",
			params: Params{
				Endpoint: "localhost:4317/v1/traces",
			},
			wantErr: "invalid OTLP trace endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := qt.New(t)
			err := tt.params.Verify()
			c.Assert(err, qt.ErrorMatches, ".*"+tt.wantErr+".*")
		})
	}
}
