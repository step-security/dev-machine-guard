package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	goCredentialOwnershipKey = "credential"
	goEnvOwnershipKey        = "go-env"
)

// GoCoordinator fetches one Go policy and coordinates its shared credential
// and default Go environment file.
type GoCoordinator struct {
	Fetcher    Fetcher
	Reporter   Reporter
	Exec       executor.Executor
	CustomerID string
	DeviceID   string
	Platform   string
	Logf       func(format string, args ...any)
	Warnf      func(format string, args ...any)

	buildComponents func(executor.Executor, GoPolicy) (*goComponents, error)
	writeState      func(category, target string, state AppliedTargetState) error
	clearState      func(category, target string) error
}

type goComponents struct {
	credential           *goComponent
	env                  *goComponent
	hasPyPISibling       func() (bool, error)
	hasManagedCredential func() (bool, error)
	close                func() error
}

type goComponent struct {
	name                string
	ownershipTarget     string
	ownershipKey        string
	ownershipStateValue string
	writer              Writer
	initErr             error
	expected            string
	converged           func(string) (bool, error)
	staticConverged     func(string) (bool, error)
	restoreSnapshot     func() error
	hasMDMMarker        func() (bool, error)
	mdmOwned            func() (bool, error)
	completeState       func(AppliedTargetState, bool, *AppliedTargetState) error
	prepareWrite        func(AppliedTargetState, bool) error
	prepareClear        func(AppliedTargetState, bool) error
	preflight           func() error
	observe             func() (goComponentObservation, error)
}

type goComponentObservation struct {
	auth string
	env  *GoEnvObservation
}

type goComponentResult struct {
	name            string
	state           string
	err             error
	observation     goComponentObservation
	observationErr  error
	staticConverged bool
}

type goFixedFetcher struct{ policy EffectivePolicy }

func (f goFixedFetcher) Fetch(_ context.Context, _, _, category, target string) (EffectivePolicy, error) {
	if category != CategoryPackageConfig || target != TargetGo {
		return EffectivePolicy{}, errors.New("devicepolicy: fixed Go fetch identity mismatch")
	}
	return f.policy, nil
}

// Reconcile runs one fetch-once package_config/go cycle.
func (c *GoCoordinator) Reconcile(ctx context.Context) error {
	if c.Fetcher == nil {
		return errors.New("devicepolicy: nil Go fetcher")
	}
	effective, err := c.Fetcher.Fetch(ctx, c.CustomerID, c.DeviceID, CategoryPackageConfig, TargetGo)
	if err != nil {
		return fmt.Errorf("devicepolicy: fetch Go policy: %w", err)
	}
	if !effective.present() {
		c.logf("devicepolicy: run-config carried no package_config/go policy; leaving state untouched")
		return nil
	}
	if effective.Clear {
		host, hostErr := c.clearRegistryHost()
		if host == "" {
			host = "invalid.invalid"
		}
		return c.clear(ctx, effective, clearGoPolicy(host), hostErr)
	}
	policy, err := ParseGoPolicy(effective.Policy, c.DeviceID)
	if err != nil {
		return errors.Join(err, c.report(ctx, StatePolicyNotApplied, "", effective.Hash, canonicalEnforcement(effective.Enforcement), nil))
	}
	components, err := c.components(policy)
	if err != nil {
		state := StateWriteFailed
		if errors.Is(err, ErrNoTargetUser) || errors.Is(err, secureuserfile.ErrNoTargetUser) {
			state = StatePolicyNotApplied
		}
		return errors.Join(err, c.report(ctx, state, "", effective.Hash, canonicalEnforcement(effective.Enforcement), nil))
	}
	if components.close != nil {
		defer func() { _ = components.close() }()
	}
	effective.Enforcement = canonicalEnforcement(effective.Enforcement)
	if effective.Enforcement == enforcementMDM {
		return c.reconcileMDM(ctx, effective, policy, components)
	}
	return c.reconcileDMG(ctx, effective, policy, components)
}

func (c *GoCoordinator) clear(ctx context.Context, effective EffectivePolicy, policy GoPolicy, credentialInitErr error) error {
	components, err := c.components(policy)
	if err != nil {
		return fmt.Errorf("devicepolicy: Go clear requires an enforceable target user: %w", err)
	}
	if components.close != nil {
		defer func() { _ = components.close() }()
	}
	if credentialInitErr != nil {
		components.credential.initErr = errors.Join(components.credential.initErr, credentialInitErr)
	}
	effective.Enforcement = enforcementDMG
	envResult := c.runClear(ctx, effective, components.env)
	if envResult.err != nil {
		return envResult.err
	}
	sibling, err := components.hasPyPISibling()
	if err != nil {
		return fmt.Errorf("devicepolicy: inspect PyPI sibling marker: %w", err)
	}
	if sibling {
		if err := c.clearOwnershipState(CategoryPackageConfig, GoCredentialOwnershipTarget); err != nil {
			return fmt.Errorf("devicepolicy: release shared Go credential ownership: %w", err)
		}
		return nil
	}
	if credentialInitErr != nil && components.hasManagedCredential != nil {
		managed, err := components.hasManagedCredential()
		if err != nil {
			return fmt.Errorf("devicepolicy: inspect shared credential marker: %w", err)
		}
		if !managed {
			return c.clearOwnershipState(CategoryPackageConfig, GoCredentialOwnershipTarget)
		}
	}
	return c.runClear(ctx, effective, components.credential).err
}

func (c *GoCoordinator) reconcileMDM(ctx context.Context, effective EffectivePolicy, policy GoPolicy, components *goComponents) error {
	results := []goComponentResult{c.observeMDM(components.credential), c.observeMDM(components.env)}
	observed, observedErr := buildGoObserved(policy, results)
	state := StateMDMManaged
	for _, result := range results {
		if result.err != nil || result.observationErr != nil {
			state = StateVerificationFailed
			break
		}
		if result.state != StateMDMManaged {
			state = StatePolicyNotApplied
		}
	}
	if observedErr != nil {
		state = StateVerificationFailed
	}
	return errors.Join(goComponentErrors(results), observedErr, c.report(ctx, state, "", effective.Hash, enforcementMDM, observed))
}

func (c *GoCoordinator) observeMDM(component *goComponent) goComponentResult {
	result := c.observeOnly(component)
	if result.observationErr != nil || component == nil || component.mdmOwned == nil {
		result.state = StateVerificationFailed
		return result
	}
	owned, err := component.mdmOwned()
	if err != nil {
		result.state, result.err = StateVerificationFailed, err
	} else if owned {
		result.state = StateMDMManaged
	} else {
		result.state = StatePolicyNotApplied
	}
	return result
}

func (c *GoCoordinator) reconcileDMG(ctx context.Context, effective EffectivePolicy, policy GoPolicy, components *goComponents) error {
	managed := false
	var markerErrs []error
	for _, component := range []*goComponent{components.credential, components.env} {
		if component == nil || component.initErr != nil {
			if component != nil && component.initErr != nil {
				markerErrs = append(markerErrs, component.initErr)
			}
			continue
		}
		present, err := component.hasMDMMarker()
		if err != nil {
			markerErrs = append(markerErrs, fmt.Errorf("devicepolicy: inspect %s MDM marker: %w", component.name, err))
			continue
		}
		managed = managed || present
	}
	if managed {
		results := []goComponentResult{c.observeMDM(components.credential), c.observeMDM(components.env)}
		observed, observedErr := buildGoObserved(policy, results)
		state := StateMDMManaged
		if len(markerErrs) != 0 || observedErr != nil || goComponentErrors(results) != nil {
			state = StateVerificationFailed
		} else {
			for _, result := range results {
				if result.state != StateMDMManaged {
					state = StatePolicyNotApplied
					break
				}
			}
		}
		return errors.Join(errors.Join(markerErrs...), goComponentErrors(results), observedErr, c.report(ctx, state, "", effective.Hash, enforcementDMG, observed))
	}
	if len(markerErrs) != 0 {
		return errors.Join(errors.Join(markerErrs...), c.report(ctx, StateVerificationFailed, "", effective.Hash, enforcementDMG, nil))
	}
	for _, component := range []*goComponent{components.credential, components.env} {
		if component.initErr != nil {
			return errors.Join(component.initErr, c.report(ctx, StateVerificationFailed, "", effective.Hash, enforcementDMG, nil))
		}
		if component.preflight != nil {
			if err := component.preflight(); err != nil {
				return errors.Join(err, c.report(ctx, StateVerificationFailed, "", effective.Hash, enforcementDMG, nil))
			}
		}
	}

	previous, hadPrevious := ReadAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget)
	credentialConverged, convergeErr := components.credential.converged(components.credential.expected)
	if convergeErr != nil {
		return errors.Join(convergeErr, c.report(ctx, StateVerificationFailed, "", effective.Hash, enforcementDMG, nil))
	}
	credentialResult := c.runComponent(ctx, effective, components.credential)
	results := []goComponentResult{credentialResult}
	if !goComponentSucceeded(credentialResult.state) {
		envResult := c.observeOnly(components.env)
		envResult.state = StatePolicyNotApplied
		results = append(results, envResult)
		return c.finishDMG(ctx, effective, policy, results)
	}

	envResult := c.runComponent(ctx, effective, components.env)
	results = append(results, envResult)
	credentialChanged := !credentialConverged && goComponentSucceeded(credentialResult.state)
	if credentialChanged && !envResult.staticConverged {
		rollbackErr := components.credential.restoreSnapshot()
		rollbackState := StateWriteFailed
		if rollbackErr != nil {
			rollbackState = StateVerificationFailed
		} else if hadPrevious {
			rollbackErr = c.writeOwnershipState(CategoryPackageConfig, GoCredentialOwnershipTarget, previous)
		} else {
			rollbackErr = c.clearOwnershipState(CategoryPackageConfig, GoCredentialOwnershipTarget)
		}
		if rollbackErr != nil && rollbackState != StateVerificationFailed {
			rollbackState = StateWriteFailed
		}
		results = append(results, goComponentResult{name: "credential_rollback", state: rollbackState, err: rollbackErr})
		refreshed := c.observeOnly(components.credential)
		results[0].observation, results[0].observationErr = refreshed.observation, refreshed.observationErr
	}
	return c.finishDMG(ctx, effective, policy, results)
}

func (c *GoCoordinator) finishDMG(ctx context.Context, effective EffectivePolicy, policy GoPolicy, results []goComponentResult) error {
	observed, observedErr := buildGoObserved(policy, results)
	state := aggregateGoState(results)
	if observedErr != nil {
		state = StateVerificationFailed
	}
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = effective.Hash
	}
	return errors.Join(goComponentErrors(results), observedErr, c.report(ctx, state, appliedHash, effective.Hash, enforcementDMG, observed))
}

func (c *GoCoordinator) runComponent(ctx context.Context, effective EffectivePolicy, component *goComponent) goComponentResult {
	if component == nil {
		err := errors.New("devicepolicy: nil Go component")
		return goComponentResult{state: StateVerificationFailed, err: err, observationErr: err}
	}
	result := goComponentResult{name: component.name}
	if component.initErr != nil {
		result.state, result.err, result.observationErr = StateVerificationFailed, component.initErr, component.initErr
		return result
	}
	collector := &collectingReporter{}
	result.err = c.childReconciler(effective, component, collector).Reconcile(ctx)
	if len(collector.reports) == 1 {
		result.state = collector.reports[0].State
	} else {
		result.state = StateVerificationFailed
		result.err = errors.Join(result.err, fmt.Errorf("devicepolicy: %s child produced %d reports", component.name, len(collector.reports)))
	}
	result.observation, result.observationErr = component.observe()
	result.state = aggregateGoState([]goComponentResult{{state: result.state}, {state: goObservationState(result.observation, result.observationErr)}})
	if component.staticConverged != nil {
		var staticErr error
		result.staticConverged, staticErr = component.staticConverged(component.expected)
		result.observationErr = errors.Join(result.observationErr, staticErr)
		if staticErr != nil {
			result.state = StateVerificationFailed
		}
	}
	return result
}

func (c *GoCoordinator) runClear(ctx context.Context, effective EffectivePolicy, component *goComponent) goComponentResult {
	if component == nil || component.initErr != nil {
		err := errors.New("devicepolicy: unusable Go component")
		if component != nil {
			err = errors.Join(err, component.initErr)
		}
		return goComponentResult{state: StateWriteFailed, err: err}
	}
	result := goComponentResult{name: component.name, state: StateCompliant}
	result.err = c.childReconciler(effective, component, &collectingReporter{}).Reconcile(ctx)
	if result.err != nil {
		result.state = classifyWriteError(result.err)
	}
	return result
}

func (c *GoCoordinator) observeOnly(component *goComponent) goComponentResult {
	if component == nil || component.initErr != nil || component.observe == nil {
		err := errors.New("devicepolicy: Go component cannot be observed")
		if component != nil {
			err = errors.Join(err, component.initErr)
		}
		return goComponentResult{state: StateVerificationFailed, err: err, observationErr: err}
	}
	observation, err := component.observe()
	return goComponentResult{name: component.name, state: goObservationState(observation, err), observation: observation, observationErr: err}
}

func (c *GoCoordinator) childReconciler(effective EffectivePolicy, component *goComponent, reporter Reporter) *Reconciler {
	return &Reconciler{
		Fetcher:             goFixedFetcher{policy: effective},
		Reporter:            reporter,
		Writer:              component.writer,
		WriterInitErr:       component.initErr,
		CustomerID:          c.CustomerID,
		DeviceID:            c.DeviceID,
		Platform:            c.Platform,
		Category:            CategoryPackageConfig,
		Target:              TargetGo,
		OwnershipTarget:     component.ownershipTarget,
		OwnershipStateValue: component.ownershipStateValue,
		OwnershipKey:        component.ownershipKey,
		OwnsByMarker:        true,
		Converged:           component.converged,
		FullStateDrift:      true,
		RestoreSnapshot:     component.restoreSnapshot,
		CompleteState:       component.completeState,
		PrepareWrite:        component.prepareWrite,
		PrepareClear:        component.prepareClear,
		ProbeExpected:       func(string) (bool, string) { return false, "" },
		ProbeContent:        func(string) (bool, map[string]json.RawMessage, error) { return true, nil, nil },
		Render:              func(json.RawMessage) (string, error) { return component.expected, nil },
		Logf:                c.Logf,
		Warnf:               c.Warnf,
		writeState:          c.writeOwnershipState,
		clearState:          c.clearOwnershipState,
		probeState:          ProbeAppliedStateWritable,
	}
}

func (c *GoCoordinator) components(policy GoPolicy) (*goComponents, error) {
	if c.buildComponents != nil {
		return c.buildComponents(c.Exec, policy)
	}
	if c.Exec == nil {
		return nil, errors.New("devicepolicy: nil Go executor")
	}
	return buildGoComponents(c.Exec, policy)
}

func buildGoComponents(exec executor.Executor, policy GoPolicy) (*goComponents, error) {
	home, err := secureuserfile.OpenUserHome(exec)
	if err != nil {
		return nil, err
	}
	components := &goComponents{close: home.Close}
	components.hasManagedCredential = func() (bool, error) { return hasManagedNetrcMarker(home) }
	credentialExpected := renderNetrcEntry(policy.RegistryHost(), policy.DeviceToken())
	credential, credentialErr := newGoNetrcWriter(home, policy.RegistryHost(), policy.DeviceToken())
	components.credential = &goComponent{
		name: "credential", ownershipTarget: GoCredentialOwnershipTarget, ownershipKey: goCredentialOwnershipKey,
		ownershipStateValue: GoCredentialOwnershipValue, writer: credential, initErr: credentialErr, expected: credentialExpected,
	}
	credentialLocation := ""
	if credential != nil {
		credentialLocation = credential.Location()
		components.credential.preflight = credential.ValidateEffectivePath
		components.credential.converged = credential.Converged
		components.credential.restoreSnapshot = credential.RestoreSnapshot
		components.credential.hasMDMMarker = credential.HasMDMMarker
		components.credential.mdmOwned = func() (bool, error) {
			owned, err := credential.MDMOwned()
			if err != nil || !owned {
				return owned, err
			}
			secure, err := credential.file.MetadataSecure(secureuserfile.FileMode)
			if err != nil {
				return false, err
			}
			if !secure {
				return false, fmt.Errorf("netrc: insecure MDM metadata: %w", ErrTargetUnusable)
			}
			return true, nil
		}
		components.credential.completeState = func(_ AppliedTargetState, _ bool, state *AppliedTargetState) error {
			state.RegistryHost = policy.RegistryHost()
			return nil
		}
		components.credential.observe = func() (goComponentObservation, error) {
			status, err := credential.Observation(credentialExpected)
			return goComponentObservation{auth: status}, err
		}
	}

	envExpected, envRenderErr := renderGoEnvSettings(policy)
	envWriter, envErr := NewGoEnvWriter(exec, home, policy)
	components.env = &goComponent{
		name: "go-env", ownershipTarget: GoEnvOwnershipTarget, ownershipKey: goEnvOwnershipKey,
		ownershipStateValue: GoEnvOwnershipValue, writer: envWriter, initErr: errors.Join(envRenderErr, envErr), expected: envExpected,
	}
	if envWriter != nil {
		components.env.preflight = envWriter.ValidateTarget
		components.env.converged = envWriter.Converged
		components.env.staticConverged = envWriter.StaticConverged
		components.env.restoreSnapshot = envWriter.RestoreSnapshot
		components.env.hasMDMMarker = envWriter.HasMDMMarker
		components.env.mdmOwned = envWriter.MDMOwned
		components.env.completeState = envWriter.CompleteState
		components.env.prepareWrite = envWriter.PrepareWrite
		components.env.prepareClear = envWriter.PrepareClear
		components.env.observe = func() (goComponentObservation, error) {
			observation, err := envWriter.Observation(envExpected, credentialLocation)
			return goComponentObservation{env: &observation}, err
		}
	}
	components.hasPyPISibling = func() (bool, error) {
		sibling, err := hasPyPIDMGMarker(exec, home)
		if err != nil || !sibling {
			return sibling, err
		}
		return hasSingleManagedNetrc(home)
	}
	return components, nil
}

func hasPyPIDMGMarker(exec executor.Executor, home *secureuserfile.Home) (bool, error) {
	userExec := executor.NewUserAwareExecutor(exec, home.Username())
	if err := executor.UserEnvironmentError(userExec); err != nil {
		return false, fmt.Errorf("devicepolicy: inspect target-user environment: %w", err)
	}
	for _, path := range configaudit.TrustedPipUserPaths(userExec, home.Path()) {
		file, err := secureHomeFile(home, path, pipBackupPrefix)
		if err != nil {
			return false, err
		}
		present, err := file.ParentPresent()
		if err != nil || !present {
			if err != nil {
				return false, err
			}
			continue
		}
		data, existed, _, err := file.Read()
		if err != nil {
			return false, err
		}
		if existed {
			markers, err := scanPipMarkers(data)
			if err != nil {
				return false, err
			}
			if markers.dmg != nil {
				return true, nil
			}
		}
	}
	uvPath, err := uvUserConfigPath(userExec, home.Path())
	if err != nil {
		return false, err
	}
	uvFile, err := secureHomeFile(home, uvPath, uvBackupPrefix)
	if err != nil {
		return false, err
	}
	present, err := uvFile.ParentPresent()
	if err != nil || !present {
		return false, err
	}
	data, existed, _, err := uvFile.Read()
	if err != nil || !existed {
		return false, err
	}
	markers, err := scanUVMarkers(data)
	return markers.complete(), err
}

func secureHomeFile(home *secureuserfile.Home, path, backupPrefix string) (*secureuserfile.File, error) {
	relative, err := filepath.Rel(home.Path(), filepath.Clean(path))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, fmt.Errorf("devicepolicy: sibling path is outside resolved home: %w", ErrTargetUnusable)
	}
	return home.Open(relative, backupPrefix, secureuserfile.MaxBytes)
}

func hasGoDMGMarker(exec executor.Executor, home *secureuserfile.Home) (bool, error) {
	userExec := executor.NewUserAwareExecutor(exec, home.Username())
	path, err := goUserEnvPath(userExec, home.Path())
	if err != nil {
		return false, err
	}
	if err := executor.UserEnvironmentError(userExec); err != nil && userExec.GOOS() != model.PlatformDarwin {
		return false, fmt.Errorf("devicepolicy: inspect target-user environment: %w", err)
	}
	if _, err := userExec.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	file, err := secureHomeFile(home, path, goEnvBackupPrefix)
	if err != nil {
		return false, err
	}
	present, err := file.ParentPresent()
	if err != nil || !present {
		return false, err
	}
	data, existed, _, err := file.Read()
	if err != nil || !existed {
		return false, err
	}
	analysis, err := scanGoEnv(data)
	return analysis.owner == "dmg", err
}

func clearGoPolicy(host string) GoPolicy {
	policy := GoPolicy{Ecosystem: "go", RegistryURL: "https://" + host + "/go", deviceID: "clear"}
	policy.Auth.Scheme = goAuthScheme
	policy.Auth.APIKey = "clear"
	return policy
}

func (c *GoCoordinator) clearRegistryHost() (string, error) {
	if state, ok := ReadAppliedState(CategoryPackageConfig, GoCredentialOwnershipTarget); ok && isValidHost(state.RegistryHost) {
		return state.RegistryHost, nil
	}
	if c.Exec == nil {
		return "", errors.New("devicepolicy: nil Go executor")
	}
	home, err := secureuserfile.OpenUserHome(c.Exec)
	if err != nil {
		return "", err
	}
	defer func() { _ = home.Close() }()
	return discoverDMGNetrcHost(home)
}

func goObservationState(observation goComponentObservation, err error) string {
	if err != nil {
		return StateVerificationFailed
	}
	if observation.auth != "" {
		switch observation.auth {
		case authTokenMatch:
			return StateCompliant
		case authTokenUnreadable:
			return StateVerificationFailed
		default:
			return StatePolicyNotApplied
		}
	}
	if observation.env == nil {
		return StateVerificationFailed
	}
	if observation.env.ConfigStatus == "unreadable" {
		return StateVerificationFailed
	}
	if observation.env.ConfigStatus != "match" || observation.env.EffectiveStatus != "match" || observation.env.OverrideSource != "none" {
		return StatePolicyNotApplied
	}
	return StateCompliant
}

func aggregateGoState(results []goComponentResult) string {
	precedence := map[string]int{StateCompliant: 0, StateDriftDetected: 1, StatePolicyNotApplied: 2, StateWriteFailed: 3, StateVerificationFailed: 4}
	state, rank := StateCompliant, 0
	for _, result := range results {
		candidate, ok := precedence[result.state]
		if !ok {
			return StateVerificationFailed
		}
		if candidate > rank {
			state, rank = result.state, candidate
		}
	}
	return state
}

func goComponentSucceeded(state string) bool {
	return state == StateCompliant || state == StateDriftDetected
}

func goComponentErrors(results []goComponentResult) error {
	var errs []error
	for _, result := range results {
		errs = append(errs, result.err, result.observationErr)
	}
	return errors.Join(errs...)
}

func buildGoObserved(policy GoPolicy, results []goComponentResult) (json.RawMessage, error) {
	observed := GoObserved{
		Ecosystem:       "go",
		RegistryURL:     "",
		AuthTokenStatus: authTokenUnreadable,
		ConfigStatus:    "unreadable",
		EffectiveStatus: "unknown",
		OverrideSource:  "unknown",
	}
	for _, result := range results {
		if result.observation.auth != "" {
			observed.AuthTokenStatus = result.observation.auth
		}
		if result.observation.env != nil {
			observed.RegistryURL = safeObservedRegistryURL(result.observation.env.RegistryURL)
			observed.ConfigStatus = result.observation.env.ConfigStatus
			observed.EffectiveStatus = result.observation.env.EffectiveStatus
			observed.OverrideSource = result.observation.env.OverrideSource
		}
	}
	if observed.RegistryURL == "" && observed.ConfigStatus == "match" {
		observed.RegistryURL = policy.RegistryURL
	}
	return json.Marshal(observed)
}

func (c *GoCoordinator) writeOwnershipState(category, target string, state AppliedTargetState) error {
	if c.writeState != nil {
		return c.writeState(category, target, state)
	}
	return WriteAppliedState(category, target, state)
}

func (c *GoCoordinator) clearOwnershipState(category, target string) error {
	if c.clearState != nil {
		return c.clearState(category, target)
	}
	return ClearAppliedState(category, target)
}

func (c *GoCoordinator) report(ctx context.Context, state, appliedHash, evaluatedHash, enforcement string, observed json.RawMessage) error {
	report := ComplianceReport{
		Category: CategoryPackageConfig, Target: TargetGo, State: state, AppliedHash: appliedHash,
		EvaluatedHash: evaluatedHash, AgentVersion: AgentVersion(), Platform: c.Platform,
		Observed: observed, EvaluatedEnforcement: enforcement,
	}
	c.logf("devicepolicy: reporting aggregate state=%s category=%s target=%s", state, CategoryPackageConfig, TargetGo)
	if c.Reporter == nil {
		return nil
	}
	if err := c.Reporter.Report(ctx, c.CustomerID, c.DeviceID, report); err != nil {
		return fmt.Errorf("devicepolicy: report Go state %s: %w", state, err)
	}
	return nil
}

func (c *GoCoordinator) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}
