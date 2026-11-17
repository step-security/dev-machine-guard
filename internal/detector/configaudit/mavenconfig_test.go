package configaudit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func mavenConfigTest(t *testing.T) (*composerConfigMock, MavenConfigScope) {
	t.Helper()
	m, scope := composerConfigTest(t)
	return m, MavenConfigScope{Username: scope.Username, Home: scope.Home, ProcessVerified: true}
}

func mavenFindingKeys(audit model.RubyConfigAudit) []string {
	keys := []string{}
	for _, f := range audit.Findings {
		keys = append(keys, f.Code+" "+f.Key)
	}
	slices.Sort(keys)
	return keys
}

func TestParseJavaProperties(t *testing.T) {
	for _, tc := range []struct {
		name, in   string
		key, value string
		complete   bool
	}{
		{"equals", "a=b", "a", "b", true},
		{"colon", "a:b", "a", "b", true},
		{"whitespace separator", "a   b", "a", "b", true},
		{"separator spacing", "a = b ", "a", "b ", true},
		{"escaped separator in key", `a\:b=c`, "a:b", "c", true},
		{"escaped url colon", `distributionUrl=https\://example.invalid/x.zip`, "distributionUrl", "https://example.invalid/x.zip", true},
		{"continuation", "a=b\\\n    c", "a", "bc", true},
		{"escaped backslash is not continuation", `a=b\\`, "a", `b\`, true},
		{"unicode escape", `a=\u0041`, "a", "A", true},
		{"comment then entry", "# c\n! c\na=b", "a", "b", true},
		{"malformed unicode escape", `a=\u00G1`, "a", "", false},
		{"key only", "a", "a", "", true},
	} {
		props, complete := ParseJavaProperties([]byte(tc.in))
		if len(props) != 1 || props[0].Key != tc.key || props[0].Value != tc.value || complete != tc.complete {
			t.Errorf("%s: %+v complete=%v", tc.name, props, complete)
		}
	}
	props, _ := ParseJavaProperties([]byte{'a', '=', 'c', 'a', 'f', 0xE9})
	if len(props) != 1 || props[0].Value != "café" {
		t.Errorf("ISO-8859-1 value %+v", props)
	}
	many := strings.Repeat("k=v\n", mavenPropertyLimit+1)
	if props, complete := ParseJavaProperties([]byte(many)); complete || len(props) != mavenPropertyLimit {
		t.Errorf("entry cap: %d complete=%v", len(props), complete)
	}
}

func TestMavenConfigSettingsAllowlistAndFindings(t *testing.T) {
	m, scope := mavenConfigTest(t)
	home := scope.Home
	m.SetEnv("MAVEN_ARGS", "-s /opt/team/settings.xml -Daether.transport.https.securityMode=insecure -Dmaven.repo.local=/opt/repo -Daether.lrm.enhanced.split=false")
	// JVM options cannot name settings files, and a relative lead is not guessed.
	m.SetEnv("MAVEN_OPTS", "-gs /opt/ignored.xml -Dmaven.wagon.http.ssl.insecure=true -Dmaven.repo.local=relative/repo -Dcanary=CANARY_OPTS")
	m.SetEnv("MAVEN_HOME", "/opt/maven")
	m.SetFile(filepath.Join(home, ".m2", "settings.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>${user.home}/custom-repo</localRepository>
  <mirrors>
    <mirror><id>open</id><url>http://mirror.example.invalid/maven</url><mirrorOf>*,!internal</mirrorOf></mirror>
    <mirror><id>blocked</id><url>http://blocked.example.invalid/maven</url><mirrorOf>external:http:*</mirrorOf><blocked>true</blocked></mirror>
  </mirrors>
  <proxies><proxy><active>true</active><protocol>HTTPS</protocol><host>proxy.example.invalid</host><port>8443</port><username>CANARY_USER</username><password>CANARY_PROXY_PASS</password></proxy></proxies>
  <servers>
    <server><id>enc</id><username>CANARY_USER</username><password>{CANARY_ENCRYPTED}</password></server>
    <server><id>ref</id><password>${env.CANARY_REF}</password></server>
    <server><id>key</id><privateKey>/home/dev/.ssh/CANARY_KEY</privateKey></server>
  </servers>
  <profiles><profile><id>corp</id><repositories>
    <repository><id>corp</id><url>https://CANARY_U:CANARY_P@repo.example.invalid/maven?token=CANARY_Q</url>
      <releases><checksumPolicy>warn</checksumPolicy><updatePolicy>interval:60</updatePolicy></releases>
      <snapshots><enabled>false</enabled></snapshots>
    </repository>
  </repositories></profile></profiles>
</settings>`))
	m.SetFile("/opt/team/settings.xml", []byte(`<settings><repositories><repository><id>legacy</id><url>http://legacy.example.invalid/m2</url></repository></repositories></settings>`))
	m.SetFile("/opt/maven/conf/settings.xml", []byte(`<settings><mirrors><mirror><id>bad id!</id></mirror></mirrors></settings>`))
	m.SetFile(filepath.Join(home, ".m2", "settings-security.xml"), []byte("CANARY_MASTER"))

	snap := NewMavenConfigDetector(m).Detect(context.Background(), scope)
	if want := []string{"/opt/repo", filepath.Join(home, "custom-repo")}; !slices.Equal(snap.RepositoryLeads, want) {
		t.Errorf("leads = %v, want %v", snap.RepositoryLeads, want)
	}
	if snap.Split {
		t.Error("split=false requested a split repository")
	}
	if reason := snap.ContentGuard(filepath.Join(home, ".m2", "settings-security.xml")); reason != "skipped_protected" {
		t.Errorf("security settings guard = %q", reason)
	}
	maven, gradle := snap.Finish()

	user := rubySettings(rubyFile(t, maven, "maven", "user", filepath.Join(home, ".m2", "settings.xml")))
	for key, want := range map[string]string{
		"local_repository":                      filepath.Join(home, "custom-repo"),
		"mirrors.0.url":                         "http://mirror.example.invalid/maven",
		"mirrors.0.mirror_of":                   "*,!internal",
		"mirrors.0.blocked":                     "false",
		"mirrors.1.blocked":                     "true",
		"proxies.0.protocol":                    "https",
		"proxies.0.port":                        "8443",
		"proxies.0.credential_form":             "literal",
		"servers.0.credential_form":             "encrypted",
		"servers.1.credential_form":             "reference",
		"servers.2.credential_form":             "unknown",
		"repositories.0.url":                    "https://repo.example.invalid/maven",
		"repositories.0.profile_id":             "corp",
		"repositories.0.profile_activation":     "unknown",
		"repositories.0.releases_update_policy": "interval:60",
		"repositories.0.snapshots_enabled":      "false",
	} {
		if user[key] != want {
			t.Errorf("user %s = %q, want %q", key, user[key], want)
		}
	}
	if _, ok := user["proxies.0.username"]; ok {
		t.Error("proxy username kept")
	}
	if got := rubySettings(rubyFile(t, maven, "maven", "process", "")); got["aether.transport.https.securityMode"] != "insecure" || got["maven.wagon.http.ssl.insecure"] != "true" || len(got) != 2 {
		t.Errorf("process settings %v", got)
	}
	rubyFile(t, maven, "maven", "user", "/opt/team/settings.xml")
	if f := rubyFile(t, maven, "maven", "system", "/opt/maven/conf/settings.xml"); f.Status != "present" || !slices.Contains(f.Reasons, "unsupported_format") {
		t.Errorf("unsafe mirror id %+v", f)
	}
	for _, f := range maven.Files {
		if f.Path == "/opt/ignored.xml" {
			t.Error("MAVEN_OPTS named a global settings file")
		}
	}
	if !slices.Contains(maven.Reasons, "path_unresolved") {
		t.Errorf("relative lead not reported: %v", maven.Reasons)
	}
	want := []string{
		"maven-001 mirrors.0.url",
		"maven-001 repositories.0.url",
		"maven-002 repositories.0.releases_checksum_policy",
		"maven-003 aether.transport.https.securityMode",
		"maven-003 maven.wagon.http.ssl.insecure",
	}
	if got := mavenFindingKeys(maven); !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
	if len(maven.CredentialFiles) != 2 || maven.CredentialFiles[0].Presence != "present" || maven.CredentialFiles[1].Presence != "absent" {
		t.Errorf("credential files %+v", maven.CredentialFiles)
	}
	if c := maven.Contexts; len(c) != 1 || c[0].ProjectPath != "" || len(c[0].ConfigSourceIDs) != 4 || c[0].ConfigSourceIDs[0] != rubyFile(t, maven, "maven", "process", "").SourceID {
		t.Errorf("ambient context %+v", c)
	}
	data, _ := json.Marshal([]any{maven, gradle})
	if strings.Contains(string(data), "CANARY") {
		t.Errorf("credential survived: %s", data)
	}
}

func TestMavenConfigProjectFiles(t *testing.T) {
	m, scope := mavenConfigTest(t)
	dir := filepath.Join(scope.Home, "app")
	files := map[string]string{
		".mvn/maven.config": "-Dmaven.repo.local=/opt/project-repo\n-s\n/opt/project-settings.xml\n-Dspaced value\n",
		".mvn/jvm.config":   "-Daether.enhancedLocalRepository.split=true -Dmaven.repo.local=/opt/jvm-repo",
		".mvn/wrapper/maven-wrapper.properties": "distributionType=only-script\n" +
			"distributionUrl=http\\://repo.example.invalid/apache-maven-3.9.9-bin.zip\n",
		"gradle.properties": "org.gradle.dependency.verification=Lenient\n" +
			"systemProp.https.proxyHost=proxy.example.invalid\nsystemProp.https.proxyPassword=CANARY_GRADLE_PASS\n",
		"gradle/wrapper/gradle-wrapper.properties": "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10-bin.zip\n" +
			"distributionSha256Sum=" + strings.Repeat("ab", 32) + "\n",
	}
	paths := []string{}
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		m.SetFile(p, []byte(body))
		paths = append(paths, p)
	}
	slices.Sort(paths)
	m.SetFile("/opt/project-settings.xml", []byte(`<settings/>`))

	snap := NewMavenConfigDetector(m).Detect(context.Background(), scope)
	leads := snap.Project(dir, "unknown", paths)
	if !leads.Split || !slices.Equal(leads.Repositories, []string{"/opt/jvm-repo", "/opt/project-repo"}) && !slices.Equal(leads.Repositories, []string{"/opt/project-repo", "/opt/jvm-repo"}) {
		t.Errorf("project leads %+v", leads)
	}
	if snap.Split || len(snap.RepositoryLeads) != 0 {
		t.Errorf("project leads leaked into process leads: split=%v %v", snap.Split, snap.RepositoryLeads)
	}
	url := "http://repo.example.invalid/maven"
	pom := filepath.Join(dir, "pom.xml")
	snap.Manifest(dir, pom, []MavenRepository{{ID: new("plain"), URL: &url, Kind: "dependency"}}, "present", nil)
	verification := filepath.Join(dir, "gradle", "verification-metadata.xml")
	snap.Verification(dir, verification, GradleVerification{VerifyMetadata: new(false), VerifySignatures: new(false), TrustedKeys: true}, "present", nil)
	maven, gradle := snap.Finish()

	if f := rubyFile(t, maven, "maven", "project", filepath.Join(dir, ".mvn", "maven.config")); !slices.Contains(f.Reasons, "unsupported_format") {
		t.Errorf("whitespace line accepted: %+v", f)
	}
	rubyFile(t, maven, "maven", "user", "/opt/project-settings.xml")
	wrapper := rubySettings(rubyFile(t, maven, "maven", "project", filepath.Join(dir, ".mvn", "wrapper", "maven-wrapper.properties")))
	if wrapper["wrapper.type"] != "only-script" || wrapper["wrapper.distribution_checksum_configured"] != "false" || wrapper["wrapper.wrapper_checksum_configured"] != "false" {
		t.Errorf("maven wrapper %v", wrapper)
	}
	gw := rubySettings(rubyFile(t, gradle, "gradle", "project", filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties")))
	if gw["wrapper.distribution_checksum_configured"] != "true" {
		t.Errorf("gradle wrapper %v", gw)
	}
	if got, want := mavenFindingKeys(maven), []string{
		"maven-001 repositories.0.url",
		"maven-004 wrapper.distribution_url",
		"maven-005 wrapper.distribution_checksum_configured",
	}; !slices.Equal(got, want) {
		t.Errorf("maven findings:\n got %v\nwant %v", got, want)
	}
	// verify-signatures=false alone is not a finding; only metadata checking is.
	if got, want := mavenFindingKeys(gradle), []string{
		"gradle-002 org.gradle.dependency.verification",
		"gradle-005 verification.verify_metadata",
	}; !slices.Equal(got, want) {
		t.Errorf("gradle findings:\n got %v\nwant %v", got, want)
	}
	// A project's own limitation and named settings stay in its own chain.
	projectSettings := rubyFile(t, maven, "maven", "user", "/opt/project-settings.xml").SourceID
	for _, tc := range []struct {
		audit                   model.RubyConfigAudit
		ambient, project        string
		projectHasNamedSettings bool
	}{{maven, "observed", "partial", true}, {gradle, "observed", "observed", false}} {
		for _, c := range tc.audit.Contexts {
			want, named := tc.ambient, false
			if c.ProjectPath == dir {
				want, named = tc.project, tc.projectHasNamedSettings
			}
			if c.SelectionStatus != want || slices.Contains(c.ConfigSourceIDs, projectSettings) != named {
				t.Errorf("%s context %+v", c.Manager, c)
			}
		}
	}
	if data, _ := json.Marshal([]any{maven, gradle}); strings.Contains(string(data), "CANARY") {
		t.Errorf("credential survived: %s", data)
	}
}

func TestMavenConfigWrapperIncompleteParse(t *testing.T) {
	m, scope := mavenConfigTest(t)
	dir := filepath.Join(scope.Home, "app")
	p := filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties")
	m.SetFile(p, []byte("distributionUrl=https\\://services.gradle.org/x.zip\nbroken=\\u00G1\n"))
	snap := NewMavenConfigDetector(m).Detect(context.Background(), scope)
	snap.Project(dir, "gradle", []string{p})
	_, gradle := snap.Finish()
	f := rubyFile(t, gradle, "gradle", "project", p)
	if _, ok := rubySettings(f)["wrapper.distribution_checksum_configured"]; ok || len(gradle.Findings) != 0 || !slices.Contains(f.Reasons, "parse_error") {
		t.Errorf("an incomplete parse claimed a missing checksum: %+v %+v", f, gradle.Findings)
	}
}

func TestMavenConfigUnverifiedProcess(t *testing.T) {
	m, scope := mavenConfigTest(t)
	scope.ProcessVerified = false
	m.SetEnv("MAVEN_ARGS", "-Dmaven.repo.local=/opt/repo")
	m.SetEnv("GRADLE_USER_HOME", "/opt/gradle-home")
	snap := NewMavenConfigDetector(m).Detect(context.Background(), scope)
	if len(snap.RepositoryLeads) != 0 || len(snap.GradleHomes) != 0 {
		t.Errorf("unverified process leads %v %v", snap.RepositoryLeads, snap.GradleHomes)
	}
	maven, gradle := snap.Finish()
	for _, a := range []model.RubyConfigAudit{maven, gradle} {
		f := rubyFile(t, a, a.Files[0].Manager, "process", "")
		if f.Status != "unsupported" || !slices.Equal(f.Reasons, []string{"user_unresolved"}) || a.Status != "partial" {
			t.Errorf("unverified process %+v %s", f, a.Status)
		}
	}
}

// A later -D definition replaces an earlier one within one argument list.
func TestMavenConfigLastDefinitionWins(t *testing.T) {
	m, scope := mavenConfigTest(t)
	m.SetEnv("MAVEN_ARGS", "-Dmaven.wagon.http.ssl.insecure=true -Daether.lrm.enhanced.split=true "+
		"-Dmaven.wagon.http.ssl.insecure=false -Daether.lrm.enhanced.split=false")
	snap := NewMavenConfigDetector(m).Detect(context.Background(), scope)
	if snap.Split {
		t.Error("superseded split definition applied")
	}
	maven, _ := snap.Finish()
	if got := rubySettings(rubyFile(t, maven, "maven", "process", ""))["maven.wagon.http.ssl.insecure"]; got != "false" {
		t.Errorf("insecure = %q, want false", got)
	}
	if got := mavenFindingKeys(maven); slices.ContainsFunc(got, func(k string) bool { return strings.HasPrefix(k, "maven-003") }) {
		t.Errorf("superseded TLS flag raised a finding: %v", got)
	}
}

func TestMavenConfigSeparateBudgets(t *testing.T) {
	old := maxMavenAuditBytes
	t.Cleanup(func() { maxMavenAuditBytes = old })
	maxMavenAuditBytes = 4096
	m, scope := mavenConfigTest(t)
	var servers strings.Builder
	for i := range 60 {
		servers.WriteString("<server><id>server" + strconv.Itoa(i) + "</id><password>x</password></server>")
	}
	m.SetFile(filepath.Join(scope.Home, ".m2", "settings.xml"), []byte("<settings><servers>"+servers.String()+"</servers></settings>"))
	m.SetFile(filepath.Join(scope.Home, ".gradle", "gradle.properties"), []byte("org.gradle.dependency.verification=off\n"))
	maven, gradle := NewMavenConfigDetector(m).Detect(context.Background(), scope).Finish()
	if !slices.Contains(maven.Reasons, "output_size_limit") {
		t.Errorf("maven budget not reached: %v", maven.Reasons)
	}
	if gradle.Status != "complete" || len(gradle.Findings) != 1 {
		t.Errorf("maven overflow affected gradle: %s %v %+v", gradle.Status, gradle.Reasons, gradle.Findings)
	}
	for name, a := range map[string]model.RubyConfigAudit{"maven": maven, "gradle": gradle} {
		if data, _ := json.Marshal(a); len(data) > maxMavenAuditBytes {
			t.Errorf("%s audit %d bytes exceeds cap", name, len(data))
		}
	}
}

func TestMavenConfigBudgetRetainsObservations(t *testing.T) {
	for _, tc := range []string{"project findings", "settings", "blocked mirrors"} {
		t.Run(tc, func(t *testing.T) {
			m, scope := mavenConfigTest(t)
			if tc != "project findings" {
				var text strings.Builder
				text.WriteString("<settings><mirrors>")
				for i := range 120 {
					blocked := tc == "blocked mirrors" && i > 0
					text.WriteString("<mirror><id>repo" + strconv.Itoa(i) + "</id><url>http://example.invalid/" + strings.Repeat("a", 3000) + "</url><blocked>" + strconv.FormatBool(blocked) + "</blocked></mirror>")
				}
				text.WriteString("</mirrors></settings>")
				m.SetFile(filepath.Join(scope.Home, ".m2", "settings.xml"), []byte(text.String()))
			}
			snap := NewMavenConfigDetector(m).Detect(t.Context(), scope)
			if tc == "project findings" {
				for i := range 120 {
					dir := filepath.Join(scope.Home, "projects", "app"+strconv.Itoa(i))
					repos := []MavenRepository{}
					for j := range 5 {
						repos = append(repos, MavenRepository{ID: new("repo" + strconv.Itoa(j)), URL: new("http://example.invalid/releases"), Kind: "dependency"})
					}
					snap.Manifest(dir, filepath.Join(dir, "pom.xml"), repos, "present", nil)
				}
			}
			audit, _ := snap.Finish()
			data, _ := json.Marshal(audit)
			if len(data) > maxMavenAuditBytes || !slices.Contains(audit.Reasons, "output_size_limit") || len(audit.Files) == 0 || len(audit.Findings) == 0 {
				t.Fatalf("bytes=%d status=%s reasons=%v files=%d findings=%d", len(data), audit.Status, audit.Reasons, len(audit.Files), len(audit.Findings))
			}
			if tc == "blocked mirrors" && len(audit.Findings) != 1 {
				t.Errorf("blocked mirrors raised findings: %v", mavenFindingKeys(audit))
			}
			ids := map[string]bool{}
			for _, f := range audit.Files {
				ids[f.SourceID] = true
				if slices.Contains(f.Reasons, "output_size_limit") && (f.Status != "present" || len(f.Settings) == 0) {
					t.Errorf("lost admitted settings: %+v", f)
				}
			}
			for _, f := range audit.Findings {
				if !ids[f.SourceID] {
					t.Errorf("finding source missing: %s", f.SourceID)
				}
			}
			for _, c := range audit.Contexts {
				for _, id := range c.ConfigSourceIDs {
					if !ids[id] {
						t.Errorf("context source missing: %s", id)
					}
				}
			}
		})
	}
}

// Maven rejects a settings file with anything but comments and whitespace
// after its root, so such a file contributes no settings.
func TestMavenConfigSettingsDocumentEnd(t *testing.T) {
	doc := `<settings><mirrors><mirror><id>m</id><url>http://mirror.example.invalid/maven</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>`
	for _, tc := range []struct {
		name, tail string
		valid      bool
	}{
		{"trailing whitespace", "\n\n", true},
		{"trailing comment", "\n<!-- done -->\n", true},
		{"second root", "<settings/>", false},
		{"unfinished comment", "\n<!-- unfinished", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, scope := mavenConfigTest(t)
			path := filepath.Join(scope.Home, ".m2", "settings.xml")
			m.SetFile(path, []byte(doc+tc.tail))
			maven, _ := NewMavenConfigDetector(m).Detect(context.Background(), scope).Finish()
			f := rubyFile(t, maven, "maven", "user", path)
			if tc.valid {
				if f.Status != "present" || len(f.Settings) == 0 || !slices.Contains(mavenFindingKeys(maven), "maven-001 mirrors.0.url") {
					t.Errorf("file = %+v, findings = %v", f, mavenFindingKeys(maven))
				}
				return
			}
			if f.Status != "invalid" || !slices.Contains(f.Reasons, "parse_error") || len(f.Settings) != 0 || maven.Status != "partial" {
				t.Errorf("file = %+v, audit = %s", f, maven.Status)
			}
		})
	}
}
