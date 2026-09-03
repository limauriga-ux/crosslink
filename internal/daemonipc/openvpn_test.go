package daemonipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOpenVPNStatusNeverCarriesSubmittedCredentials(t *testing.T) {
	command := Cmd{
		Action: ActionOpenVPNCompleteChallenge, ChallengeID: "challenge",
		Username: "employee", Password: "password-secret", Secret: "otp-secret",
	}
	encodedCommand, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"challenge_id":"challenge"`, `"username":"employee"`, `"password":"password-secret"`, `"secret":"otp-secret"`} {
		if !strings.Contains(string(encodedCommand), want) {
			t.Fatalf("command missing %s: %s", want, encodedCommand)
		}
	}
	status := OpenVPNStatusDTO{
		Configured: true, Active: true, State: "auth-pending",
		Challenge: &OpenVPNChallengeDTO{ID: "challenge", Kind: "secret", Username: "employee", Message: "OTP"},
	}
	encodedStatus, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedStatus), "password-secret") || strings.Contains(string(encodedStatus), "otp-secret") || strings.Contains(string(encodedStatus), `"password":`) || strings.Contains(string(encodedStatus), `"secret":`) {
		t.Fatalf("status leaked submitted credentials: %s", encodedStatus)
	}
}

func TestOpenVPNStatusUsesEmptyArraysOnlyWhenPresent(t *testing.T) {
	status := OpenVPNStatusDTO{Configured: true, State: "disconnected"}
	content, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), `"ipv4":null`) || strings.Contains(string(content), `"dns":null`) {
		t.Fatalf("status emitted null arrays: %s", content)
	}
}
