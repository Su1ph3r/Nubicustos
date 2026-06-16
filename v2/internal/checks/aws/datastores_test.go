package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestDatastoreChecks(t *testing.T) {
	st := state.New()
	st.AddEFSFileSystem(state.EFSFileSystem{ID: "fs-open", Region: "us-east-1", Encrypted: false})
	st.AddEFSFileSystem(state.EFSFileSystem{ID: "fs-ok", Region: "us-east-1", Encrypted: true})
	st.AddElasticacheGroup(state.ElasticacheGroup{ID: "redis-open", Region: "us-east-1", AtRestEncrypted: false, InTransitEncrypted: false})
	st.AddElasticacheGroup(state.ElasticacheGroup{ID: "redis-ok", Region: "us-east-1", AtRestEncrypted: true, InTransitEncrypted: true})
	st.AddDynamoDBTable(state.DynamoDBTable{Name: "tbl-open", Region: "us-east-1", PITREnabled: false})
	st.AddDynamoDBTable(state.DynamoDBTable{Name: "tbl-ok", Region: "us-east-1", PITREnabled: true})

	if fs, _ := (efsUnencrypted{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "fs-open" {
		t.Fatalf("only the unencrypted EFS should be flagged, got %+v", fs)
	}
	if fs, _ := (elasticacheAtRest{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "redis-open" {
		t.Fatalf("only the at-rest-unencrypted group should be flagged, got %+v", fs)
	}
	if fs, _ := (elasticacheInTransit{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "redis-open" {
		t.Fatalf("only the in-transit-unencrypted group should be flagged, got %+v", fs)
	}
	if fs, _ := (dynamoDBNoPITR{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "tbl-open" {
		t.Fatalf("only the no-PITR table should be flagged, got %+v", fs)
	}
}

func TestDatastoreNilState(t *testing.T) {
	st := state.New()
	st.AWS = nil
	if fs, _ := (efsUnencrypted{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
}
