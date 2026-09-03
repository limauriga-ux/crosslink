package main

import (
	"reflect"
	"testing"
)

func TestQueueSplitRouteUpdateKeepsLatestSnapshot(t *testing.T) {
	ch := make(chan splitRouteUpdate, 1)
	firstRoutes := []string{"10.0.0.0/8"}
	firstSuffixes := []string{"old.example"}
	queueSplitRouteUpdate(ch, firstRoutes, firstSuffixes)

	latestRoutes := []string{"192.0.2.0/24"}
	latestSuffixes := []string{"new.example"}
	queueSplitRouteUpdate(ch, latestRoutes, latestSuffixes)
	latestRoutes[0] = "mutated"
	latestSuffixes[0] = "mutated"

	got := <-ch
	if want := []string{"192.0.2.0/24"}; !reflect.DeepEqual(got.routes, want) {
		t.Fatalf("queued routes = %v, want %v", got.routes, want)
	}
	if want := []string{"new.example"}; !reflect.DeepEqual(got.suffixes, want) {
		t.Fatalf("queued suffixes = %v, want %v", got.suffixes, want)
	}
}
