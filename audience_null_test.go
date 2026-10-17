package jwt

import (
	"encoding/json"
	"testing"
)

func TestAudienceNullClearsPreviousValue(t *testing.T) {
	a := Audience{"previous"}
	if err := json.Unmarshal([]byte("null"), &a); err != nil {
		t.Fatal(err)
	}
	if a != nil {
		t.Fatalf("got %#v, want nil", a)
	}
}
