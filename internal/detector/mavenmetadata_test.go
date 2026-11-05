package detector

import (
	"slices"
	"strings"
	"testing"
)

func TestMavenCoordinateAndVersion(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"org.example", ""},
		{"Foo_2.13", ""},
		{"", "unresolved_coordinate"},
		{"${project.groupId}", "unresolved_coordinate"},
		{"a:b", "parse_error"},
		{"a/b", "parse_error"},
		{`a\b`, "parse_error"},
		{"a b", "parse_error"},
		{"..", "parse_error"},
		{strings.Repeat("a", 257), "parse_error"},
	} {
		if got := mavenCoordinate(tc.in); got != tc.want {
			t.Errorf("mavenCoordinate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"1.0", true}, {"1.0-SNAPSHOT", true}, {"2.0.0-M1+build.5", true}, {"[1.0,2.0)", true},
		{"", false}, {"..", false}, {"1.0/2", false}, {"1:0", false}, {"1@0", false}, {"1?0", false}, {"1#0", false}, {"1 0", false},
	} {
		if got := mavenVersion(tc.in); got != tc.want {
			t.Errorf("mavenVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestMavenRequirement(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		redacted bool
	}{
		{"1.2.3", "1.2.3", false},
		{" [1.0,2.0) ", "[1.0,2.0)", false},
		{"[1.0, 2.0)", "[1.0, 2.0)", false},
		{"${junit.version}", "${junit.version}", false},
		{"https://CANARY@repo.example.invalid/x", condaRedacted, true},
		{"1.0@CANARY", condaRedacted, true},
		{"1.0?x", condaRedacted, true},
		{"1.0#x", condaRedacted, true},
		{"../1.0", condaRedacted, true},
		{"1.0\t2.0", condaRedacted, true},
		{"1.0\x00", condaRedacted, true},
		{strings.Repeat("1", 1025), condaRedacted, true},
	} {
		got, redacted := mavenRequirement(tc.in)
		if got != tc.want || redacted != tc.redacted {
			t.Errorf("mavenRequirement(%q) = %q %v", tc.in, got, redacted)
		}
	}
}

func TestMavenFilename(t *testing.T) {
	for _, tc := range []struct {
		name, file, artifact, version string
		ok                            bool
		ext, classifier, fileVersion  string
	}{
		{"jar", "widgets-1.0.jar", "widgets", "1.0", true, "jar", "", ""},
		{"pom", "widgets-1.0.pom", "widgets", "1.0", true, "pom", "", ""},
		{"gradle module", "widgets-1.0.module", "widgets", "1.0", true, "module", "", ""},
		{"aar", "android-1.0.aar", "android", "1.0", true, "aar", "", ""},
		{"classifier", "widgets-1.0-sources.jar", "widgets", "1.0", true, "jar", "sources", ""},
		{"hyphenated classifier", "widgets-1.0-test-fixtures.jar", "widgets", "1.0", true, "jar", "test-fixtures", ""},
		{"hyphenated artifact", "foo-bar-1.0.jar", "foo-bar", "1.0", true, "jar", "", ""},
		{"hyphenated version", "foo-1.0-rc-1.jar", "foo", "1.0-rc-1", true, "jar", "", ""},
		{"normalized snapshot", "snap-1.0-SNAPSHOT.jar", "snap", "1.0-SNAPSHOT", true, "jar", "", ""},
		{"timestamped snapshot", "snap-1.0-20240101.120000-1.jar", "snap", "1.0-SNAPSHOT", true, "jar", "", "1.0-20240101.120000-1"},
		{"timestamped snapshot classifier", "snap-1.0-20240101.120000-12-sources.jar", "snap", "1.0-SNAPSHOT", true, "jar", "sources", "1.0-20240101.120000-12"},
		{"bare SNAPSHOT version", "snap-20240101.120000-1.pom", "snap", "SNAPSHOT", true, "pom", "", "20240101.120000-1"},
		{"bad timestamp", "snap-1.0-2024.jar", "snap", "1.0-SNAPSHOT", false, "", "", ""},
		{"other artifact", "other-1.0.jar", "widgets", "1.0", false, "", "", ""},
		{"other version", "widgets-1.1.jar", "widgets", "1.0", false, "", "", ""},
		{"sha1 sidecar", "widgets-1.0.jar.sha1", "widgets", "1.0", false, "", "", ""},
		{"lastUpdated marker", "widgets-1.0.jar.lastUpdated", "widgets", "1.0", false, "", "", ""},
		{"signature", "widgets-1.0.jar.asc", "widgets", "1.0", false, "", "", ""},
		{"metadata", "maven-metadata-central.xml", "widgets", "1.0", false, "", "", ""},
		{"war out of scope", "widgets-1.0.war", "widgets", "1.0", false, "", "", ""},
		{"temporary", "widgets-1.0.jar.part", "widgets", "1.0", false, "", "", ""},
	} {
		f, ok := mavenFilename(tc.file, tc.artifact, tc.version)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", tc.name, ok)
			continue
		}
		if !ok {
			continue
		}
		if f.extension != tc.ext || f.classifier == nil || *f.classifier != tc.classifier || f.fileVersion != tc.fileVersion {
			t.Errorf("%s: %+v classifier=%v", tc.name, f, f.classifier)
		}
	}
}

func mavenDeclKeys(ds []mavenDeclaration) []string {
	keys := []string{}
	for _, d := range ds {
		keys = append(keys, d.role+"|"+d.profile+"|"+d.context+"|"+d.group+":"+d.artifact+"|"+strings.Join(d.specs, ","))
	}
	slices.Sort(keys)
	return keys
}

func TestParseMavenPOM(t *testing.T) {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version></parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.0,5.0)</version><scope>test</scope><type>jar</type><classifier></classifier><optional>true</optional></dependency>
    <dependency><groupId>${unknown.group}</groupId><artifactId>x</artifactId></dependency>
    <dependency><groupId>bad group</groupId><artifactId>x</artifactId></dependency>
  </dependencies>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>2</version><scope>import</scope><type>pom</type></dependency>
    <dependency><groupId>org.example</groupId><artifactId>managed</artifactId><version>3</version></dependency>
  </dependencies></dependencyManagement>
  <build>
    <extensions><extension><groupId>org.example</groupId><artifactId>ext</artifactId><version>4</version></extension></extensions>
    <plugins>
      <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>
        <dependencies><dependency><groupId>org.ow2.asm</groupId><artifactId>asm</artifactId><version>9.7</version></dependency></dependencies>
      </plugin>
      <plugin><groupId>${plugin.group}</groupId><artifactId>p</artifactId>
        <dependencies><dependency><groupId>org.example</groupId><artifactId>orphan</artifactId></dependency></dependencies>
      </plugin>
    </plugins>
    <pluginManagement><plugins><plugin><groupId>org.example</groupId><artifactId>managed-plugin</artifactId><version>5</version></plugin></plugins></pluginManagement>
  </build>
  <repositories><repository><id>central</id><url>https://repo.example.invalid/maven2</url></repository></repositories>
  <profiles>
    <profile><id>ci</id>
      <dependencies><dependency><groupId>org.example</groupId><artifactId>ci-only</artifactId><version>6</version></dependency></dependencies>
      <pluginRepositories><pluginRepository><id>plugins</id><url>https://plugins.example.invalid</url></pluginRepository></pluginRepositories>
    </profile>
    <profile><id>bad id</id>
      <dependencies><dependency><groupId>org.example</groupId><artifactId>skipped</artifactId></dependency></dependencies>
    </profile>
  </profiles>
</project>`
	m, err := parseMavenPOM([]byte(pom))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"bom_import|||org.example:bom|2",
		"direct|ci||org.example:ci-only|6",
		"direct|||junit:junit|[4.0,5.0)",
		"extension|||org.example:ext|4",
		"managed_plugin|||org.example:managed-plugin|5",
		"managed|||org.example:managed|3",
		"parent|||org.example:parent|1",
		"plugin_dependency||plugin:org.apache.maven.plugins:maven-compiler-plugin|org.ow2.asm:asm|9.7",
		"plugin|||org.apache.maven.plugins:maven-compiler-plugin|3.13.0",
	}
	if got := mavenDeclKeys(m.declarations); !slices.Equal(got, want) {
		t.Errorf("declarations:\n got %q\nwant %q", got, want)
	}
	slices.Sort(m.reasons)
	if !slices.Equal(m.reasons, []string{"parse_error", "unresolved_coordinate"}) {
		t.Errorf("reasons = %v", m.reasons)
	}
	for _, d := range m.declarations {
		if d.artifact != "junit" {
			continue
		}
		if d.scope != "test" || d.declaredType != "jar" || d.classifier == nil || *d.classifier != "" || d.optional == nil || !*d.optional {
			t.Errorf("junit labels %+v", d)
		}
	}
	if len(m.repositories) != 2 || m.repositories[0].Kind != "dependency" || m.repositories[0].ProfileID != nil ||
		m.repositories[1].Kind != "plugin" || m.repositories[1].ProfileID == nil || *m.repositories[1].ProfileID != "ci" {
		t.Errorf("repositories %+v", m.repositories)
	}
	if g, a, v, err := mavenPOMIdentity([]byte(pom)); err != nil || g != "org.example" || a != "app" || v != "1" {
		t.Errorf("identity = %q %q %q %v", g, a, v, err)
	}

	latin := append([]byte(`<?xml version="1.0" encoding="ISO-8859-1"?><project><artifactId>caf`), 0xE9)
	latin = append(latin, []byte(`</artifactId></project>`)...)
	if _, a, _, err := mavenPOMIdentity(latin); err != nil || a != "café" {
		t.Errorf("ISO-8859-1 identity = %q %v", a, err)
	}
	for _, bad := range []string{
		`<!DOCTYPE project [<!ENTITY x "CANARY">]><project><artifactId>&x;</artifactId></project>`,
		`<project><artifactId>a</artifactId>`,
		`<settings/>`,
	} {
		if _, err := parseMavenPOM([]byte(bad)); err == nil {
			t.Errorf("parseMavenPOM(%q) accepted", bad)
		}
	}
}

func TestMavenIvyMatches(t *testing.T) {
	ivy := `<ivy-module version="2.0"><info organisation="com.ivy" module="thing" revision="2.0"/></ivy-module>`
	for _, tc := range []struct {
		name, data, version string
		want                bool
	}{
		{"match", ivy, "2.0", true},
		{"other revision", ivy, "2.1", false},
		{"old schema", strings.Replace(ivy, `version="2.0"`, `version="1.0"`, 1), "2.0", false},
		{"not ivy", `<project/>`, "2.0", false},
		{"malformed", `<ivy-module`, "2.0", false},
	} {
		if got := mavenIvyMatches([]byte(tc.data), "com.ivy", "thing", tc.version); got != tc.want {
			t.Errorf("%s: mavenIvyMatches = %v", tc.name, got)
		}
	}
}

func TestParseGradleLock(t *testing.T) {
	modern := "# comment\n" +
		"org.example:a:1.0=compileClasspath,runtimeClasspath\n" +
		"org.example:a:1.0=testRuntimeClasspath\n" +
		"org.example:b:2.0=runtimeClasspath\n" +
		"bad line\n" +
		"bad:coords=runtimeClasspath\n" +
		"empty=annotationProcessor\n"
	l, err := parseGradleLock([]byte(modern), "")
	if err != nil {
		t.Fatal(err)
	}
	if !l.invalid || len(l.entries) != 2 {
		t.Fatalf("lock %+v", l)
	}
	if got := l.entries[0].configurations; !slices.Equal(got, []string{"compileClasspath", "runtimeClasspath", "testRuntimeClasspath"}) {
		t.Errorf("aggregated configurations = %v", got)
	}
	if !slices.Contains(l.named, "annotationProcessor") {
		t.Errorf("empty= configuration not named: %v", l.named)
	}

	legacy, err := parseGradleLock([]byte("# header only\n"), "compileClasspath")
	if err != nil || len(legacy.entries) != 0 || !slices.Equal(legacy.named, []string{"compileClasspath"}) || legacy.invalid {
		t.Errorf("header-only legacy lock %+v %v", legacy, err)
	}
	legacy, err = parseGradleLock([]byte("org.example:a:1.0\n"), "compileClasspath")
	if err != nil || len(legacy.entries) != 1 || !slices.Equal(legacy.entries[0].configurations, []string{"compileClasspath"}) {
		t.Errorf("legacy lock %+v %v", legacy, err)
	}
	if _, err := parseGradleLock([]byte{0xff}, ""); err == nil {
		t.Error("invalid UTF-8 accepted")
	}

	for _, tc := range []struct{ in, modern, conf string }{
		{"compileClasspath.lockfile", "gradle.lockfile", "compileClasspath"},
		{"buildscript-classpath.lockfile", "buildscript-gradle.lockfile", "classpath"},
		{"settings-incomingCatalogForLibs0.lockfile", "settings-gradle.lockfile", "incomingCatalogForLibs0"},
	} {
		if modern, conf := mavenLockPair(tc.in); modern != tc.modern || conf != tc.conf {
			t.Errorf("mavenLockPair(%q) = %q %q", tc.in, modern, conf)
		}
	}
}

func TestParseGradleCatalog(t *testing.T) {
	catalog := `
[versions]
guava = "33.0.0-jre"
rich = { strictly = "[1.0,2.0)", prefer = "1.5" }

[libraries]
a-string = "org.example:a:1.0"
b-noversion = "org.example:b"
c-module = { module = "org.example:c", version = "2.0" }
d-group = { group = "org.example", name = "d", version.ref = "guava" }
e-ref = { module = "org.example:e", version = { ref = "rich" } }
f-rich = { module = "org.example:f", version = { require = "1.0", reject = ["1.1", "1.2"], rejectAll = true } }
g-missing = { module = "org.example:g", version.ref = "nope" }
h-unresolved = { module = "${group}:h", version = "1.0" }
i-bad = "only-one-part"

[bundles]
all = ["a-string"]

[plugins]
kotlin = { id = "org.jetbrains.kotlin.jvm", version = "2.0.0" }
`
	c, err := parseGradleCatalog([]byte(catalog))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"catalog_entry||catalog:a-string|org.example:a|1.0",
		"catalog_entry||catalog:b-noversion|org.example:b|",
		"catalog_entry||catalog:c-module|org.example:c|2.0",
		"catalog_entry||catalog:d-group|org.example:d|33.0.0-jre",
		"catalog_entry||catalog:e-ref|org.example:e|strictly=[1.0,2.0),prefer=1.5",
		"catalog_entry||catalog:f-rich|org.example:f|require=1.0,reject=1.1,reject=1.2,reject_all=true",
		"catalog_entry||catalog:g-missing|org.example:g|",
	}
	if got := mavenDeclKeys(c.declarations); !slices.Equal(got, want) {
		t.Errorf("declarations:\n got %q\nwant %q", got, want)
	}
	slices.Sort(c.reasons)
	if !slices.Equal(c.reasons, []string{"parse_error", "unresolved_coordinate"}) {
		t.Errorf("reasons = %v", c.reasons)
	}
	if _, err := parseGradleCatalog([]byte("[libraries\n")); err == nil {
		t.Error("malformed TOML accepted")
	}
}

func TestParseGradleVerification(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
  <configuration>
    <verify-metadata>false</verify-metadata>
    <verify-signatures>true</verify-signatures>
    <trusted-artifacts><trust group="org.example" reason="CANARY"/></trusted-artifacts>
    <trusted-keys><trusted-key id="CANARYKEY" group="org.example"/></trusted-keys>
  </configuration>
  <components>
    <component group="org.example" name="widgets" version="1.0">
      <artifact name="widgets-1.0.jar">
        <sha256 value="` + mavenSHA256A + `" origin="CANARY"><also-trust value="` + mavenSHA256B + `"/></sha256>
        <sha1 value="NOT-HEX"/>
      </artifact>
      <artifact name="widgets-1.0.pom"><md5 value="` + strings.Repeat("a", 32) + `"/></artifact>
    </component>
    <component group="${g}" name="x" version="1"><artifact name="x-1.jar"/></component>
    <component group="org.example" name="widgets" version="1.0">
      <artifact name="widgets-1.0.jar"><sha256 value="` + strings.Repeat("3", 64) + `"/></artifact>
    </component>
  </components>
</verification-metadata>`
	refs, policy, reasons, err := parseGradleVerification([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if policy.VerifyMetadata == nil || *policy.VerifyMetadata || policy.VerifySignatures == nil || !*policy.VerifySignatures || !policy.TrustedArtifacts || !policy.TrustedKeys {
		t.Errorf("policy %+v", policy)
	}
	if !slices.Equal(reasons, []string{"unresolved_coordinate"}) {
		t.Errorf("reasons = %v", reasons)
	}
	if len(refs) != 2 {
		t.Fatalf("refs %+v", refs)
	}
	jar := refs[0]
	if jar.filename != "widgets-1.0.jar" || !jar.invalid || jar.limited ||
		!slices.Equal(jar.checksums, []mavenChecksum{{"sha256", mavenSHA256A}, {"sha256", mavenSHA256B}, {"sha256", strings.Repeat("3", 64)}}) {
		t.Errorf("jar ref %+v", jar)
	}
	if pom := refs[1]; pom.invalid || !slices.Equal(pom.checksums, []mavenChecksum{{"md5", strings.Repeat("a", 32)}}) {
		t.Errorf("pom ref %+v", pom)
	}

	for _, tc := range []struct {
		name, tail string
		valid      bool
	}{
		{"trailing comment", "\n<!-- done -->\n", true},
		{"unfinished comment", "\n<!-- unfinished", false},
		{"second root", "<verification-metadata/>", false},
		{"trailing text", "text", false},
	} {
		if _, _, _, err := parseGradleVerification([]byte(doc + tc.tail)); (err == nil) != tc.valid {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}

	r := mavenReference{}
	for i := range maxMavenChecksums + 1 {
		r.checksum("md5", strings.Repeat("0", 30)+string("0123456789abcdef"[i/16])+string("0123456789abcdef"[i%16]))
	}
	if !r.limited || len(r.checksums) != maxMavenChecksums {
		t.Errorf("checksum cap: limited=%v count=%d", r.limited, len(r.checksums))
	}
	r = mavenReference{}
	r.checksum("sha256", strings.Repeat("AB", 32))
	if !r.invalid || len(r.checksums) != 0 {
		t.Errorf("uppercase hex kept: %+v", r)
	}
	if _, _, _, err := parseGradleVerification([]byte(`<verification-metadata>`)); err == nil {
		t.Error("malformed verification metadata accepted")
	}
}
