package lock

import (
	"errors"
	"testing"
)

func TestAcquireAll_RefusesWhileAnyScopeIsHeldAndHoldsEverything(t *testing.T) {
	base := testLockTarget(t)
	setLockTarget(base)

	releaseDev1, err := acquireTarget(scopedTarget(base, "dev1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireAll([]string{"dev1", "dev2"}); !errors.Is(err, ErrHeld) {
		t.Fatalf("AcquireAll while dev1's scan runs: err=%v, want ErrHeld", err)
	}
	// Nothing leaked from the failed attempt: the other targets are free.
	if release, err := acquireTarget(scopedTarget(base, "dev2")); err != nil {
		t.Fatalf("dev2 lock leaked by the failed AcquireAll: %v", err)
	} else {
		release()
	}
	releaseDev1()

	all, err := AcquireAll([]string{"dev1", "dev2", "dev1", ""})
	if err != nil {
		t.Fatalf("AcquireAll on an idle host: %v", err)
	}
	if _, err := Acquire(nil); !errors.Is(err, ErrHeld) {
		t.Errorf("machine-wide Acquire while AcquireAll holds: err=%v, want ErrHeld", err)
	}
	if _, err := acquireTarget(scopedTarget(base, "dev2")); !errors.Is(err, ErrHeld) {
		t.Errorf("dev2 scan lock while AcquireAll holds: err=%v, want ErrHeld", err)
	}
	all.Release()
	all.Release() // idempotent

	lk, err := Acquire(nil)
	if err != nil {
		t.Fatalf("Acquire after AcquireAll released: %v", err)
	}
	lk.Release()
}
