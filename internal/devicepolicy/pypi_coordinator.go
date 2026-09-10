package devicepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
)

const (
	pypiCredentialOwnershipKey = "credential"
	pypiPipOwnershipKey        = "pip"
	pypiUVOwnershipKey         = "uv"
)

// PyPICoordinator fetches one PyPI policy and coordinates its three local resources.
type PyPICoordinator struct {
	Fetcher    Fetcher
	Reporter   Reporter
	Exec       executor.Executor
	CustomerID string
	DeviceID   string
	Platform   string
	Logf       func(format string, args ...any)
	Warnf      func(format string, args ...any)

	buildComponents func(context.Context, executor.Executor, PyPIPolicy) (*pypiComponents, error)
	writeState      func(category, target string, state AppliedTargetState) error
	clearState      func(category, target string) error
}

type pypiComponents struct {
	credential   *pypiComponent
	pip          *pypiComponent
	uv           *pypiComponent
	hasGoSibling func() (bool, error)
	close        func() error
}

type pypiComponent struct {
	name                string
	ownershipTarget     string
	ownershipKey        string
	ownershipStateValue string
	writer              Writer
	initErr             error
	expected            string
	converged           func(string) (bool, error)
	fullStateDrift      bool
	restoreSnapshot     func() error
	hasMDMMarker        func() (bool, error)
	hasManagedMarker    func() (bool, error)
	mdmOwned            func() (bool, error)
	staticConverged     func(string) (bool, error)
	completeState       func(AppliedTargetState, bool, *AppliedTargetState) error
	prepareWrite        func(AppliedTargetState, bool) error
	prepareClear        func(AppliedTargetState, bool) error
	preflight           func() error
	observe             func(context.Context) (componentObservation, error)
}

type componentObservation struct {
	credential string
	client     *PyPIClientObservation
}

type componentResult struct {
	name              string
	state             string
	err               error
	observation       componentObservation
	observationErr    error
	staticConverged   bool
	staticConvergeErr error
}

type fixedFetcher struct{ policy EffectivePolicy }

func (f fixedFetcher) Fetch(_ context.Context, _, _, category, target string) (EffectivePolicy, error) {
	if category != CategoryPackageConfig || target != TargetPyPI {
		return EffectivePolicy{}, errors.New("devicepolicy: fixed PyPI fetch identity mismatch")
	}
	return f.policy, nil
}

type collectingReporter struct{ reports []ComplianceReport }

func (r *collectingReporter) Report(_ context.Context, _, _ string, report ComplianceReport) error {
	r.reports = append(r.reports, report)
	return nil
}

// Reconcile runs one fetch-once PyPI policy cycle.
func (c *PyPICoordinator) Reconcile(ctx context.Context) error {
	if c.Fetcher == nil {
		return errors.New("devicepolicy: nil PyPI fetcher")
	}
	effective, err := c.Fetcher.Fetch(ctx, c.CustomerID, c.DeviceID, CategoryPackageConfig, TargetPyPI)
	if err != nil {
		return fmt.Errorf("devicepolicy: fetch PyPI policy: %w", err)
	}
	if !effective.present() {
		c.logf("devicepolicy: run-config carried no package_config/pypi policy; leaving state untouched")
		return nil
	}

	enforcement := canonicalEnforcement(effective.Enforcement)
	if effective.Clear {
		host, hostErr := c.clearRegistryHost()
		if host == "" {
			host = "invalid.invalid"
		}
		return c.clear(ctx, effective, clearPyPIPolicy(host), hostErr)
	}

	policy, err := ParsePyPIPolicy(effective.Policy, c.DeviceID)
	if err != nil {
		reportErr := c.report(ctx, StatePolicyNotApplied, "", effective.Hash, enforcement, nil)
		return errors.Join(err, reportErr)
	}
	components, err := c.components(ctx, policy)
	if err != nil {
		state := StateWriteFailed
		if errors.Is(err, ErrNoTargetUser) || errors.Is(err, secureuserfile.ErrNoTargetUser) {
			state = StatePolicyNotApplied
		}
		reportErr := c.report(ctx, state, "", effective.Hash, enforcement, nil)
		return errors.Join(err, reportErr)
	}
	if components.close != nil {
		defer func() { _ = components.close() }()
	}

	effective.Enforcement = enforcement
	if enforcement == enforcementMDM {
		return c.reconcileMDM(ctx, effective, policy, components)
	}
	return c.reconcileDMG(ctx, effective, policy, components)
}

func (c *PyPICoordinator) clear(ctx context.Context, effective EffectivePolicy, policy PyPIPolicy, credentialInitErr error) error {
	components, err := c.components(ctx, policy)
	if err != nil {
		if errors.Is(err, ErrNoTargetUser) || errors.Is(err, secureuserfile.ErrNoTargetUser) {
			return fmt.Errorf("devicepolicy: PyPI clear requires an enforceable target user: %w", err)
		}
		return err
	}
	if components.close != nil {
		defer func() { _ = components.close() }()
	}
	if credentialInitErr != nil {
		if components.credential == nil {
			components.credential = &pypiComponent{name: "credential", ownershipTarget: PyPICredentialOwnershipTarget, initErr: credentialInitErr}
		} else {
			components.credential.initErr = errors.Join(components.credential.initErr, credentialInitErr)
		}
	}
	effective.Enforcement = enforcementDMG
	var errs []error
	for _, component := range []*pypiComponent{components.pip, components.uv} {
		result := c.runClear(ctx, effective, component)
		if result.err != nil {
			errs = append(errs, result.err)
		}
	}
	if components.hasGoSibling != nil {
		sibling, err := components.hasGoSibling()
		if err != nil {
			return errors.Join(errors.Join(errs...), fmt.Errorf("devicepolicy: inspect Go sibling marker: %w", err))
		}
		if sibling {
			return errors.Join(errors.Join(errs...), c.clearOwnershipState(CategoryPackageConfig, PyPICredentialOwnershipTarget))
		}
	}
	credentialResult := c.runClear(ctx, effective, components.credential)
	return errors.Join(errors.Join(errs...), credentialResult.err)
}

func (c *PyPICoordinator) reconcileMDM(ctx context.Context, effective EffectivePolicy, policy PyPIPolicy, components *pypiComponents) error {
	results := c.observeMDMSelected(ctx, policy, components)
	credential, pip, uv, observedErr := observations(policy, results)
	observed, marshalErr := buildPyPIObserved(policy, credential, pip, uv)
	state := aggregateMDMState(results, observedErr != nil || marshalErr != nil)
	reportErr := c.report(ctx, state, "", effective.Hash, enforcementMDM, observed)
	return errors.Join(componentErrors(results), observedErr, marshalErr, reportErr)
}

func (c *PyPICoordinator) observeMDMSelected(ctx context.Context, policy PyPIPolicy, components *pypiComponents) []componentResult {
	selected := []*pypiComponent{components.credential}
	if policy.Selects(PyPIClientPip) {
		selected = append(selected, components.pip)
	}
	if policy.Selects(PyPIClientUV) {
		selected = append(selected, components.uv)
	}
	results := make([]componentResult, 0, len(selected))
	for _, component := range selected {
		if component == nil {
			err := errors.New("devicepolicy: nil PyPI component")
			results = append(results, componentResult{state: StateVerificationFailed, observationErr: err})
			continue
		}
		result := c.observeOnly(ctx, component)
		if result.observationErr != nil {
			results = append(results, result)
			continue
		}
		if component.mdmOwned == nil {
			result.state = StateVerificationFailed
			result.observationErr = fmt.Errorf("devicepolicy: %s has no MDM ownership probe", component.name)
			results = append(results, result)
			continue
		}
		owned, err := component.mdmOwned()
		if err != nil {
			result.state, result.observationErr = StateVerificationFailed, err
		} else if owned {
			result.state = StateMDMManaged
		} else {
			result.state = StatePolicyNotApplied
			if result.observation.credential == authTokenMatch {
				result.observation.credential = authTokenMismatch
			}
			if result.observation.client != nil && result.observation.client.ConfigStatus == "match" {
				observed := *result.observation.client
				observed.ConfigStatus = "mismatch"
				result.observation.client = &observed
			}
		}
		results = append(results, result)
	}
	return results
}

func aggregateMDMState(results []componentResult, failed bool) string {
	if failed || anyComponentError(results) {
		return StateVerificationFailed
	}
	for _, result := range results {
		if result.state != StateMDMManaged {
			return StatePolicyNotApplied
		}
	}
	return StateMDMManaged
}

func (c *PyPICoordinator) reconcileDMG(ctx context.Context, effective EffectivePolicy, policy PyPIPolicy, components *pypiComponents) error {
	all := []*pypiComponent{components.credential, components.pip, components.uv}
	managed := false
	var markerErrs []error
	for _, component := range all {
		if component == nil || component.initErr != nil {
			if component != nil && component.initErr != nil {
				markerErrs = append(markerErrs, component.initErr)
			}
			continue
		}
		present, err := component.hasMDMMarker()
		if err != nil {
			err = fmt.Errorf("devicepolicy: inspect %s MDM marker: %w", component.name, err)
			component.initErr = errors.Join(component.initErr, err)
			markerErrs = append(markerErrs, err)
			continue
		}
		managed = managed || present
	}
	if managed {
		results := c.observeMDMSelected(ctx, policy, components)
		credential, pip, uv, observedErr := observations(policy, results)
		observed, marshalErr := buildPyPIObserved(policy, credential, pip, uv)
		state := aggregateMDMState(results, len(markerErrs) != 0 || observedErr != nil || marshalErr != nil)
		reportErr := c.report(ctx, state, "", effective.Hash, enforcementDMG, observed)
		return errors.Join(errors.Join(markerErrs...), observedErr, marshalErr, reportErr)
	}

	credentialPriorState, credentialHadPriorState := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget)
	if components.credential.preflight != nil {
		if err := components.credential.preflight(); err != nil {
			reportErr := c.report(ctx, StatePolicyNotApplied, "", effective.Hash, enforcementDMG, nil)
			return errors.Join(err, reportErr)
		}
	}
	credentialWasConverged := false
	if components.credential.initErr == nil {
		var convergeErr error
		credentialWasConverged, convergeErr = components.credential.converged(components.credential.expected)
		if convergeErr != nil {
			c.logf("devicepolicy: credential pre-cycle convergence check failed: %v", convergeErr)
		}
	}
	credentialResult := c.runComponent(ctx, effective, components.credential)
	results := []componentResult{credentialResult}
	if !componentSucceeded(credentialResult.state) {
		skipped := c.observeSelected(ctx, policy, components)
		for i := range skipped {
			if skipped[i].name != "credential" {
				skipped[i].state = StatePolicyNotApplied
				results = append(results, skipped[i])
			}
		}
		return c.finishDMG(ctx, effective, policy, results)
	}

	for _, component := range []*pypiComponent{components.pip, components.uv} {
		selected := component.name == "pip" && policy.Selects(PyPIClientPip) || component.name == "uv" && policy.Selects(PyPIClientUV)
		if !selected {
			results = append(results, c.runClear(ctx, EffectivePolicy{Category: CategoryPackageConfig, Target: TargetPyPI, Clear: true, Enforcement: enforcementDMG}, component))
		}
	}
	for _, component := range []*pypiComponent{components.pip, components.uv} {
		selected := component.name == "pip" && policy.Selects(PyPIClientPip) || component.name == "uv" && policy.Selects(PyPIClientUV)
		if selected {
			results = append(results, c.runComponent(ctx, effective, component))
		}
	}

	anyStatic := false
	for _, result := range results {
		if (result.name == "pip" || result.name == "uv") && result.staticConverged {
			anyStatic = true
		}
	}
	credentialChanged := !credentialWasConverged && componentSucceeded(credentialResult.state)
	if credentialChanged && !anyStatic {
		rollbackState := StatePolicyNotApplied
		rollbackErr := components.credential.restoreSnapshot()
		if rollbackErr != nil {
			rollbackState = StateVerificationFailed
		} else {
			var stateErr error
			if credentialHadPriorState {
				stateErr = c.writeOwnershipState(CategoryPackageConfig, PyPICredentialOwnershipTarget, credentialPriorState)
			} else {
				stateErr = c.clearOwnershipState(CategoryPackageConfig, PyPICredentialOwnershipTarget)
			}
			if stateErr != nil {
				rollbackErr = stateErr
				rollbackState = StateWriteFailed
			}
		}
		results = append(results, componentResult{name: "credential_rollback", state: rollbackState, err: rollbackErr})
		refreshed := c.observeOnly(ctx, components.credential)
		for i := range results {
			if results[i].name == "credential" {
				results[i].observation = refreshed.observation
				results[i].observationErr = refreshed.observationErr
				break
			}
		}
	}

	return c.finishDMG(ctx, effective, policy, results)
}

func (c *PyPICoordinator) finishDMG(ctx context.Context, effective EffectivePolicy, policy PyPIPolicy, results []componentResult) error {
	credential, pip, uv, observedErr := observations(policy, results)
	observed, marshalErr := buildPyPIObserved(policy, credential, pip, uv)
	state := aggregatePyPIState(results)
	appliedHash := ""
	if state == StateCompliant || state == StateDriftDetected {
		appliedHash = effective.Hash
	}
	reportErr := c.report(ctx, state, appliedHash, effective.Hash, enforcementDMG, observed)
	return errors.Join(componentErrors(results), observedErr, marshalErr, reportErr)
}

func (c *PyPICoordinator) runComponent(ctx context.Context, effective EffectivePolicy, component *pypiComponent) componentResult {
	if component == nil {
		err := errors.New("devicepolicy: nil PyPI component")
		return componentResult{state: StateVerificationFailed, err: err, observationErr: err}
	}
	result := componentResult{name: component.name}
	if component.initErr != nil {
		result.state, result.err, result.observationErr = StateVerificationFailed, component.initErr, component.initErr
		return result
	}
	collector := &collectingReporter{}
	reconciler := c.childReconciler(effective, component, collector)
	result.err = reconciler.Reconcile(ctx)
	if len(collector.reports) == 1 {
		result.state = collector.reports[0].State
		if errors.Is(result.err, errUVUnsupportedVersion) {
			result.state = StatePolicyNotApplied
			result.err = nil
		}
	} else {
		result.state = StateVerificationFailed
		result.err = errors.Join(result.err, fmt.Errorf("devicepolicy: %s child produced %d reports", component.name, len(collector.reports)))
	}
	result.observation, result.observationErr = component.observe(ctx)
	if effective.Enforcement != enforcementMDM {
		result.state = aggregatePyPIState([]componentResult{{state: result.state}, {state: observationState(result.observation, result.observationErr)}})
		if component.staticConverged != nil {
			result.staticConverged, result.staticConvergeErr = component.staticConverged(component.expected)
			if result.staticConvergeErr != nil {
				result.state = StateVerificationFailed
			}
		}
	}
	return result
}

func (c *PyPICoordinator) runClear(ctx context.Context, effective EffectivePolicy, component *pypiComponent) componentResult {
	if component == nil {
		return componentResult{state: StateWriteFailed, err: errors.New("devicepolicy: nil PyPI component")}
	}
	result := componentResult{name: component.name, state: StateCompliant}
	if component.initErr != nil {
		state, ok := ReadAppliedState(CategoryPackageConfig, component.ownershipTarget)
		if ok && emptyOwnershipState(state) && component.hasManagedMarker != nil {
			managed, err := component.hasManagedMarker()
			if err == nil && !managed {
				if err := c.clearOwnershipState(CategoryPackageConfig, component.ownershipTarget); err == nil {
					return result
				}
			}
		}
		result.state = StateWriteFailed
		result.err = component.initErr
		return result
	}
	collector := &collectingReporter{}
	result.err = c.childReconciler(effective, component, collector).Reconcile(ctx)
	if result.err != nil {
		result.state = classifyWriteError(result.err)
	}
	return result
}

func (c *PyPICoordinator) childReconciler(effective EffectivePolicy, component *pypiComponent, reporter Reporter) *Reconciler {
	reconciler := &Reconciler{
		Fetcher:             fixedFetcher{policy: effective},
		Reporter:            reporter,
		Writer:              component.writer,
		WriterInitErr:       component.initErr,
		CustomerID:          c.CustomerID,
		DeviceID:            c.DeviceID,
		Platform:            c.Platform,
		Category:            CategoryPackageConfig,
		Target:              TargetPyPI,
		OwnershipTarget:     component.ownershipTarget,
		OwnershipStateValue: component.ownershipStateValue,
		OwnershipKey:        component.ownershipKey,
		OwnsByMarker:        true,
		Converged:           component.converged,
		FullStateDrift:      component.fullStateDrift,
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
	return reconciler
}

func (c *PyPICoordinator) components(ctx context.Context, policy PyPIPolicy) (*pypiComponents, error) {
	if c.buildComponents != nil {
		return c.buildComponents(ctx, c.Exec, policy)
	}
	if c.Exec == nil {
		return nil, errors.New("devicepolicy: nil PyPI executor")
	}
	return buildPyPIComponents(ctx, c.Exec, policy)
}

func buildPyPIComponents(ctx context.Context, exec executor.Executor, policy PyPIPolicy) (*pypiComponents, error) {
	home, err := secureuserfile.OpenUserHome(exec)
	if err != nil {
		return nil, err
	}
	components := &pypiComponents{close: home.Close}
	userExec := executor.NewUserAwareExecutor(exec, home.Username())
	components.hasGoSibling = func() (bool, error) {
		sibling, err := hasGoDMGMarker(exec, home)
		if err != nil || !sibling {
			return sibling, err
		}
		return hasSingleManagedNetrc(home)
	}

	credentialExpected := renderNetrcEntry(policy.RegistryHost(), policy.DeviceToken())
	credential, credentialErr := NewNetrcWriter(home, policy)
	components.credential = &pypiComponent{
		name: "credential", ownershipTarget: PyPICredentialOwnershipTarget, ownershipKey: pypiCredentialOwnershipKey,
		ownershipStateValue: PyPICredentialOwnershipValue, writer: credential, initErr: credentialErr, expected: credentialExpected,
		hasManagedMarker: func() (bool, error) { return hasManagedNetrcMarker(home) },
	}
	if credential != nil {
		components.credential.preflight = credential.ValidateEffectivePath
		components.credential.converged = credential.Converged
		components.credential.restoreSnapshot = credential.RestoreSnapshot
		components.credential.hasMDMMarker = credential.HasMDMMarker
		components.credential.mdmOwned = credential.MDMOwned
		components.credential.completeState = func(_ AppliedTargetState, _ bool, state *AppliedTargetState) error {
			state.RegistryHost = policy.RegistryHost()
			return nil
		}
		components.credential.observe = func(context.Context) (componentObservation, error) {
			status, err := credential.Observation(credentialExpected)
			return componentObservation{credential: status}, err
		}
	}

	pipExpected, pipRenderErr := renderPipSettings(policy)
	pip, pipErr := NewPipWriter(ctx, userExec, home, policy)
	components.pip = &pypiComponent{name: "pip", ownershipTarget: PyPIPipOwnershipTarget, ownershipKey: pypiPipOwnershipKey, writer: pip, initErr: errors.Join(pipRenderErr, pipErr), expected: pipExpected}
	if pip != nil {
		components.pip.converged = pip.Converged
		components.pip.fullStateDrift = true
		components.pip.restoreSnapshot = pip.RestoreSnapshot
		components.pip.hasMDMMarker = pip.HasMDMMarker
		components.pip.hasManagedMarker = pip.HasManagedMarker
		components.pip.mdmOwned = pip.MDMOwned
		components.pip.staticConverged = pip.StaticConverged
		components.pip.completeState = pip.CompleteState
		components.pip.prepareWrite = pip.PrepareWrite
		components.pip.prepareClear = pip.PrepareClear
		components.pip.observe = func(ctx context.Context) (componentObservation, error) {
			observation, err := pip.Observation(ctx, pipExpected)
			client := PyPIClientObservation(observation)
			return componentObservation{client: &client}, err
		}
	}

	uvExpected, uvRenderErr := renderUVSettings(policy)
	uv, uvErr := NewUVWriter(ctx, userExec, home, policy)
	components.uv = &pypiComponent{name: "uv", ownershipTarget: PyPIUVOwnershipTarget, ownershipKey: pypiUVOwnershipKey, writer: uv, initErr: errors.Join(uvRenderErr, uvErr), expected: uvExpected}
	if uv != nil {
		components.uv.converged = uv.Converged
		components.uv.restoreSnapshot = uv.RestoreSnapshot
		components.uv.hasMDMMarker = uv.HasMDMMarker
		components.uv.hasManagedMarker = uv.HasManagedMarker
		components.uv.mdmOwned = uv.MDMOwned
		components.uv.staticConverged = uv.StaticConverged
		components.uv.observe = func(ctx context.Context) (componentObservation, error) {
			observation, err := uv.Observation(ctx, uvExpected)
			client := PyPIClientObservation(observation)
			return componentObservation{client: &client}, err
		}
	}
	return components, nil
}

func emptyOwnershipState(state AppliedTargetState) bool {
	return state.AppliedHash == "" && len(state.WrittenSettings) == 0 && !state.FileCreated &&
		state.ResolvedPath == "" && len(state.ResolvedPaths) == 0 && state.RegistryHost == ""
}

func clearPyPIPolicy(host string) PyPIPolicy {
	policy := PyPIPolicy{Ecosystem: "pypi", Clients: []PyPIClient{PyPIClientPip, PyPIClientUV}, RegistryURL: "https://" + host + "/python/simple", deviceID: "clear"}
	policy.Auth.Scheme = pypiAuthScheme
	policy.Auth.APIKey = "clear"
	return policy
}

func (c *PyPICoordinator) clearRegistryHost() (string, error) {
	state, ok := ReadAppliedState(CategoryPackageConfig, PyPICredentialOwnershipTarget)
	if ok && state.RegistryHost != "" {
		if !isValidHost(state.RegistryHost) {
			return "", fmt.Errorf("devicepolicy: invalid registry host in credential ownership state: %w", ErrTargetUnusable)
		}
		return state.RegistryHost, nil
	}
	if c.Exec == nil {
		return "", fmt.Errorf("devicepolicy: cannot derive registry host without an executor: %w", ErrTargetUnusable)
	}
	home, err := secureuserfile.OpenUserHome(c.Exec)
	if err != nil {
		return "", err
	}
	defer func() { _ = home.Close() }()
	host, err := discoverDMGNetrcHost(home)
	if err != nil {
		return "", fmt.Errorf("devicepolicy: derive clear registry host: %w", err)
	}
	return host, nil
}

func (c *PyPICoordinator) writeOwnershipState(category, target string, state AppliedTargetState) error {
	if c.writeState != nil {
		return c.writeState(category, target, state)
	}
	return WriteAppliedState(category, target, state)
}

func (c *PyPICoordinator) clearOwnershipState(category, target string) error {
	if c.clearState != nil {
		return c.clearState(category, target)
	}
	return ClearAppliedState(category, target)
}

func (c *PyPICoordinator) observeOnly(ctx context.Context, component *pypiComponent) componentResult {
	result := componentResult{name: component.name, state: StateCompliant}
	if component.initErr != nil {
		result.state, result.observationErr = StateWriteFailed, component.initErr
		return result
	}
	result.observation, result.observationErr = component.observe(ctx)
	if result.observationErr != nil {
		result.state = StateVerificationFailed
	}
	return result
}

func (c *PyPICoordinator) observeSelected(ctx context.Context, policy PyPIPolicy, components *pypiComponents) []componentResult {
	results := []componentResult{c.observeOnly(ctx, components.credential)}
	if policy.Selects(PyPIClientPip) {
		results = append(results, c.observeOnly(ctx, components.pip))
	}
	if policy.Selects(PyPIClientUV) {
		results = append(results, c.observeOnly(ctx, components.uv))
	}
	return results
}

func observations(policy PyPIPolicy, results []componentResult) (string, *PipObservation, *UVObservation, error) {
	credential := authTokenUnreadable
	var pip *PipObservation
	var uv *UVObservation
	var errs []error
	for _, result := range results {
		if result.observationErr != nil {
			errs = append(errs, result.observationErr)
		}
		switch result.name {
		case "credential":
			if result.observation.credential != "" {
				credential = result.observation.credential
			}
		case "pip":
			if result.observation.client != nil {
				observation := PipObservation(*result.observation.client)
				pip = &observation
			}
		case "uv":
			if result.observation.client != nil {
				observation := UVObservation(*result.observation.client)
				uv = &observation
			}
		}
	}
	if policy.Selects(PyPIClientPip) && pip == nil {
		pip = &PipObservation{ConfigStatus: "unreadable", EffectiveStatus: "unknown", OverrideSource: "unknown"}
	}
	if policy.Selects(PyPIClientUV) && uv == nil {
		uv = &UVObservation{ConfigStatus: "unreadable", EffectiveStatus: "unknown", OverrideSource: "unknown"}
	}
	return credential, pip, uv, errors.Join(errs...)
}

func observationState(observation componentObservation, err error) string {
	if err != nil {
		return StateVerificationFailed
	}
	if observation.credential != "" {
		switch observation.credential {
		case authTokenMatch:
			return StateCompliant
		case authTokenUnreadable:
			return StateVerificationFailed
		default:
			return StatePolicyNotApplied
		}
	}
	if observation.client == nil {
		return StateVerificationFailed
	}
	if observation.client.ConfigStatus == "unreadable" {
		return StateVerificationFailed
	}
	if observation.client.ConfigStatus != "match" {
		return StatePolicyNotApplied
	}
	switch observation.client.EffectiveStatus {
	case "match", "not_installed":
		return StateCompliant
	default:
		return StatePolicyNotApplied
	}
}

func componentSucceeded(state string) bool {
	return state == StateCompliant || state == StateDriftDetected
}

func anyComponentError(results []componentResult) bool {
	for _, result := range results {
		if result.err != nil || result.observationErr != nil || result.staticConvergeErr != nil {
			return true
		}
	}
	return false
}

func componentErrors(results []componentResult) error {
	var errs []error
	for _, result := range results {
		errs = append(errs, result.err, result.observationErr, result.staticConvergeErr)
	}
	return errors.Join(errs...)
}

// aggregatePyPIState applies the coordinator's deterministic failure precedence.
func aggregatePyPIState(results []componentResult) string {
	precedence := map[string]int{
		StateCompliant:          0,
		StateDriftDetected:      1,
		StatePolicyNotApplied:   2,
		StateWriteFailed:        3,
		StateVerificationFailed: 4,
	}
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

// buildPyPIObserved returns only selected-client, credential-free evidence.
func buildPyPIObserved(policy PyPIPolicy, credential string, pip *PipObservation, uv *UVObservation) (json.RawMessage, error) {
	observed := PyPIObserved{Ecosystem: "pypi", AuthTokenStatus: credential, Clients: map[string]PyPIClientObservation{}}
	if policy.Selects(PyPIClientPip) {
		if pip == nil {
			return nil, errors.New("devicepolicy: missing selected pip observation")
		}
		client := PyPIClientObservation(*pip)
		client.RegistryURL = safeObservedRegistryURL(client.RegistryURL)
		observed.Clients[string(PyPIClientPip)] = client
	}
	if policy.Selects(PyPIClientUV) {
		if uv == nil {
			return nil, errors.New("devicepolicy: missing selected uv observation")
		}
		client := PyPIClientObservation(*uv)
		client.RegistryURL = safeObservedRegistryURL(client.RegistryURL)
		observed.Clients[string(PyPIClientUV)] = client
	}
	return json.Marshal(observed)
}

func canonicalEnforcement(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), enforcementMDM) {
		return enforcementMDM
	}
	return enforcementDMG
}

func (c *PyPICoordinator) report(ctx context.Context, state, appliedHash, evaluatedHash, enforcement string, observed json.RawMessage) error {
	report := ComplianceReport{
		Category:             CategoryPackageConfig,
		Target:               TargetPyPI,
		State:                state,
		AppliedHash:          appliedHash,
		EvaluatedHash:        evaluatedHash,
		AgentVersion:         AgentVersion(),
		Platform:             c.Platform,
		Observed:             observed,
		EvaluatedEnforcement: enforcement,
	}
	c.logf("devicepolicy: reporting aggregate state=%s category=%s target=%s", state, CategoryPackageConfig, TargetPyPI)
	if c.Reporter == nil {
		return nil
	}
	if err := c.Reporter.Report(ctx, c.CustomerID, c.DeviceID, report); err != nil {
		return fmt.Errorf("devicepolicy: report PyPI state %s: %w", state, err)
	}
	return nil
}

func (c *PyPICoordinator) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}
