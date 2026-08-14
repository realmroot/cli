package agent

import (
	"bytes"
	"testing"
)

func TestWriteApprovalURL(t *testing.T) {
	var output bytes.Buffer
	writeApprovalURL("https://auth.example.com/agent/enrollments/approve?code=ABC", &output)

	want := "Approval URL:\nhttps://auth.example.com/agent/enrollments/approve?code=ABC\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
