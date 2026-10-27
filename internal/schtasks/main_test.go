package schtasks

import (
	"os"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

func TestMain(m *testing.M) { os.Exit(proctest.Main(m)) }
