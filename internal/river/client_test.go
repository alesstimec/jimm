// Copyright 2026 Canonical.

package river

import (
	"encoding/json"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverdatabasesql"
	"github.com/riverqueue/river/rivertype"
)

const metadataQueryTestJobKind = "metadata-query-test"

type metadataQueryTestArgs struct{}

func (metadataQueryTestArgs) Kind() string { return metadataQueryTestJobKind }

func TestInsert_MetadataQueryable_WithoutWorkers(t *testing.T) {
	c := qt.New(t)

	_, sqlDB := setupTestDB(c)
	riverClient, err := river.NewClient(riverdatabasesql.New(sqlDB), &river.Config{})
	c.Assert(err, qt.IsNil)

	controllerName := "controller-queryable"
	metadata := map[string]any{
		"controller-name": controllerName,
	}
	metadataBytes, err := json.Marshal(metadata)
	c.Assert(err, qt.IsNil)

	insRes, err := riverClient.Insert(c.Context(), metadataQueryTestArgs{}, &river.InsertOpts{Metadata: metadataBytes})
	c.Assert(err, qt.IsNil)

	jobs, err := riverClient.JobList(
		c.Context(),
		river.NewJobListParams().
			Kinds(metadataQueryTestJobKind).
			First(1).
			States(
				rivertype.JobStateAvailable,
			).
			Where(
				"metadata->>'controller-name' = @controller_name",
				river.NamedArgs{"controller_name": controllerName},
			),
	)
	c.Assert(err, qt.IsNil)
	c.Assert(jobs.Jobs, qt.HasLen, 1)
	c.Assert(jobs.Jobs[0].ID, qt.Equals, insRes.Job.ID)
	c.Assert(jobs.Jobs[0].State, qt.Equals, rivertype.JobStateAvailable)
	c.Assert(jobs.Jobs[0].FinalizedAt, qt.IsNil)

	var gotMetadata map[string]any
	err = json.Unmarshal(jobs.Jobs[0].Metadata, &gotMetadata)
	c.Assert(err, qt.IsNil)
	c.Assert(gotMetadata, qt.DeepEquals, metadata)
}
