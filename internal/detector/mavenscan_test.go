package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// mavenTrap adds the Java never-read files: security settings, build and
// init scripts, archives, checksums and version-list metadata.
type mavenTrap struct{ *rubyTrap }

func (x *mavenTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &mavenTrap{x.rubyTrap.GuardedFiles(roots, guard, max).(*rubyTrap)}
}
func (x *mavenTrap) ReadFile(path string) ([]byte, error) {
	name := filepath.Base(path)
	if strings.HasPrefix(name, "settings-security") || strings.HasPrefix(name, "maven-metadata") || strings.HasSuffix(name, ".gradle") || strings.HasSuffix(name, ".gradle.kts") ||
		slices.Contains([]string{".jar", ".aar", ".module", ".sha1", ".lastUpdated"}, filepath.Ext(name)) {
		x.t.Fatalf("read forbidden file %s", path)
	}
	return x.rubyTrap.ReadFile(path)
}

func mavenTestScanner(t *testing.T, home string) (*MavenScanner, *mavenTrap) {
	t.Helper()
	_, inner := rubyTestScanner(t, home)
	x := &mavenTrap{inner}
	s := NewMavenScanner(x, progress.NewNoop())
	s.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(string) string { return "" }, func(string) bool { return false }
	}
	return s, x
}

const (
	mavenSHA256A = "1111111111111111111111111111111111111111111111111111111111111111"
	mavenSHA256B = "2222222222222222222222222222222222222222222222222222222222222222"
	mavenKey40   = "0123456789abcdef0123456789abcdef01234567"
	mavenKey39   = "123456789abcdef0123456789abcdef01234567"
	mavenKey38   = "23456789abcdef0123456789abcdef01234567"
)

func mavenTestPOM(group, artifact, version string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>` +
		`<groupId>` + group + `</groupId><artifactId>` + artifact + `</artifactId><version>` + version + `</version>` +
		`<dependencies><dependency><groupId>org.example</groupId><artifactId>never-a-declaration</artifactId><version>1</version></dependency></dependencies></project>`
}

// mavenWriteFixture lays out a developer home with a Maven local repository,
// a Gradle module cache, settings, and one Maven and one Gradle project.
func mavenWriteFixture(t *testing.T, home, root string) {
	t.Helper()
	m2 := filepath.Join(home, ".m2")
	goWrite(t, filepath.Join(m2, "settings.xml"), `<?xml version="1.0" encoding="ISO-8859-1"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <localRepository>${user.home}/.m2/repository</localRepository>
  <mirrors>
    <mirror><id>corp</id><url>http://CANARY_MUSER:CANARY_MPASS@mirror.example.invalid/maven2?token=CANARY_QUERY</url><mirrorOf>*,!local</mirrorOf></mirror>
    <mirror><id>blocked</id><url>http://blocked.example.invalid/</url><mirrorOf>external:http:*</mirrorOf><blocked>true</blocked></mirror>
  </mirrors>
  <proxies><proxy><active>true</active><protocol>https</protocol><host>proxy.example.invalid</host><port>8443</port><username>CANARY_PUSER</username><password>{CANARY_ENCRYPTED}</password></proxy></proxies>
  <servers>
    <server><id>corp</id><username>CANARY_SUSER</username><password>CANARY_LITERAL</password><configuration><httpHeaders><property><name>X-Token</name><value>CANARY_HEADER</value></property></httpHeaders></configuration></server>
    <server><id>env</id><password>${env.CANARY_REFERENCE}</password></server>
  </servers>
  <profiles><profile><id>corp</id><repositories><repository><id>corp-releases</id><url>https://repo.example.invalid/releases</url>
    <releases><checksumPolicy>warn</checksumPolicy><updatePolicy>interval:60</updatePolicy></releases><snapshots><enabled>false</enabled></snapshots></repository></repositories></profile></profiles>
  <!-- caf`+"\xe9"+` CANARY_COMMENT -->
</settings>
`, 0o600)
	goWrite(t, filepath.Join(m2, "settings-security.xml"), "<settingsSecurity><master>CANARY_MASTER</master></settingsSecurity>", 0o600)
	goWrite(t, filepath.Join(m2, "wrapper", "dists", "apache-maven-3.9.9", "abc", "pom.xml"), mavenTestPOM("org.apache.maven", "dist", "3.9.9"), 0o600)

	repo := filepath.Join(m2, "repository")
	widgets := filepath.Join(repo, "org", "example", "widgets", "1.0")
	goWrite(t, filepath.Join(widgets, "widgets-1.0.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(widgets, "widgets-1.0-sources.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(widgets, "widgets-1.0.pom"), mavenTestPOM("org.example", "widgets", "1.0"), 0o600)
	goWrite(t, filepath.Join(widgets, "widgets-1.0.jar.sha1"), "CANARY_SHA1", 0o600)
	goWrite(t, filepath.Join(widgets, "widgets-1.0-javadoc.jar.lastUpdated"), "CANARY_LAST", 0o600)
	goWrite(t, filepath.Join(widgets, "_remote.repositories"), "#NOTE: This is a Maven Resolver internal implementation file\nwidgets-1.0.jar>central=\nwidgets-1.0.pom>=\n", 0o600)
	goWrite(t, filepath.Join(repo, "org", "example", "widgets", "maven-metadata-central.xml"), "<metadata>CANARY_METADATA</metadata>", 0o600)
	goWrite(t, filepath.Join(repo, "com", "Example", "Foo_2.13", "2.0", "Foo_2.13-2.0.pom"), mavenTestPOM("com.Example", "Foo_2.13", "2.0"), 0o600)
	snap := filepath.Join(repo, "org", "example", "snap", "1.0-SNAPSHOT")
	goWrite(t, filepath.Join(snap, "snap-1.0-20240101.120000-1.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(snap, "snap-1.0-SNAPSHOT.pom"), mavenTestPOM("org.example", "snap", "1.0-SNAPSHOT"), 0o600)
	goWrite(t, filepath.Join(snap, "maven-metadata-local.xml"), "<metadata/>", 0o600)
	goWrite(t, filepath.Join(repo, "org", "example", "android", "1.0", "android-1.0.aar"), "CANARY_AAR", 0o600)
	goWrite(t, filepath.Join(repo, "org", "example", "empty", "1.0", "empty-1.0.jar"), "", 0o600)
	// A default split prefix without identifying metadata stays unread.
	goWrite(t, filepath.Join(repo, "installed", "org", "example", "lib", "1.0", "lib-1.0.jar"), "CANARY_JAR", 0o600)

	files := filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")
	gw := filepath.Join(files, "org.example", "widgets", "1.0")
	goWrite(t, filepath.Join(gw, mavenKey40, "widgets-1.0.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(gw, mavenKey38, "widgets-1.0.pom"), mavenTestPOM("org.example", "widgets", "1.0"), 0o600)
	goWrite(t, filepath.Join(gw, mavenKey39, "widgets-1.0-test-fixtures.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(gw, mavenKey39, "widgets-1.0.module"), `{"CANARY_MODULE":1}`, 0o600)
	goWrite(t, filepath.Join(gw, mavenKey39, "renamed.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(gw, mavenKey39, "widgets-1.0.jar.part"), "CANARY_PART", 0o600)
	goWrite(t, filepath.Join(gw, "not-a-key", "widgets-1.0.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(files, "org.example", "relocated", "1.0", mavenKey40, "relocated-1.0.pom"), mavenTestPOM("org.other", "relocated", "1.0"), 0o600)
	goWrite(t, filepath.Join(files, "com.ivy", "thing", "2.0", mavenKey40, "ivy-2.0.xml"), `<?xml version="1.0"?><ivy-module version="2.0"><info organisation="com.ivy" module="thing" revision="2.0"/><dependencies><dependency org="CANARY" name="x" rev="1"/></dependencies></ivy-module>`, 0o600)
	goWrite(t, filepath.Join(files, "com.ivy", "thing", "2.0", mavenKey39, "thing-2.0.jar"), "CANARY_JAR", 0o600)
	goWrite(t, filepath.Join(files, "com.ivy", "bad", "1.0", mavenKey40, "ivy-1.0.xml"), `<ivy-module version="2.0"><info organisation="com.ivy" module="other" revision="1.0"/></ivy-module>`, 0o600)
	goWrite(t, filepath.Join(home, ".gradle", "gradle.properties"), "systemProp.https.proxyHost=proxy.example.invalid\nsystemProp.https.proxyPort=3128\nsystemProp.https.proxyPassword=CANARY_GPASS\norg.gradle.jvmargs=-Dtoken\\=CANARY_JVM\n", 0o600)
	goWrite(t, filepath.Join(home, ".gradle", "init.d", "corp.gradle"), "CANARY_INIT", 0o600)

	custom := filepath.Join(home, "custom-repo", "org", "example", "custom", "1.0")
	goWrite(t, filepath.Join(custom, "custom-1.0.jar"), "CANARY_JAR", 0o600)

	app := filepath.Join(root, "mvnapp")
	goWrite(t, filepath.Join(app, "pom.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <artifactId>mvnapp</artifactId>
  <repositories><repository><id>insecure</id><url>http://repo.example.invalid/maven</url></repository></repositories>
  <dependencyManagement><dependencies>
    <dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>2.0</version><type>pom</type><scope>import</scope></dependency>
    <dependency><groupId>org.example</groupId><artifactId>widgets</artifactId><version>[1.0, 2.0)</version></dependency>
  </dependencies></dependencyManagement>
  <dependencies>
    <dependency><groupId>org.example</groupId><artifactId>widgets</artifactId><version>${widgets.version}</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>widgets</artifactId><version>1.0</version></dependency>
    <dependency><groupId>org.example</groupId><artifactId>widgets</artifactId><version>1.0</version><classifier>sources</classifier><scope>test</scope><optional>true</optional></dependency>
    <dependency><groupId>org.example</groupId><artifactId>widgets</artifactId><classifier></classifier></dependency>
    <dependency><groupId>${unresolved.group}</groupId><artifactId>x</artifactId></dependency>
    <dependency><groupId>org.example</groupId><artifactId>leaky</artifactId><version>https://CANARY_REQUIREMENT@evil.example.invalid/x</version></dependency>
    <dependency><groupId>org.scala-lang</groupId><artifactId>scala-library_2.13</artifactId></dependency>
  </dependencies>
  <build>
    <plugins><plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version>
      <dependencies><dependency><groupId>org.example</groupId><artifactId>plugin-helper</artifactId><version>1.0</version></dependency></dependencies></plugin></plugins>
    <pluginManagement><plugins><plugin><groupId>org.example</groupId><artifactId>managed-plugin</artifactId><version>1.0</version></plugin></plugins></pluginManagement>
    <extensions><extension><groupId>org.example</groupId><artifactId>ext</artifactId><version>1.0</version></extension></extensions>
  </build>
  <profiles><profile><id>ci</id><dependencies><dependency><groupId>org.example</groupId><artifactId>ci-only</artifactId><version>1.0</version></dependency></dependencies></profile></profiles>
</project>
`, 0o600)
	goWrite(t, filepath.Join(app, ".mvn", "maven.config"), "-Dmaven.repo.local="+filepath.Join(home, "custom-repo")+"\n-Daether.transport.https.securityMode=insecure\n-Dsecret=CANARY_OPTION\n", 0o600)
	goWrite(t, filepath.Join(app, ".mvn", "wrapper", "maven-wrapper.properties"), "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\ndistributionType=bin\n", 0o600)
	goWrite(t, filepath.Join(app, "target", "classes", "pom.xml"), mavenTestPOM("org.example", "built", "1.0"), 0o600)

	gapp := filepath.Join(root, "gradleapp")
	goWrite(t, filepath.Join(gapp, "settings.gradle.kts"), "CANARY_SCRIPT", 0o600)
	goWrite(t, filepath.Join(gapp, "build.gradle.kts"), "CANARY_SCRIPT", 0o600)
	goWrite(t, filepath.Join(gapp, "gradle.lockfile"), "# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\n# This file is expected to be part of source control.\n"+
		"com.squareup.okhttp3:okhttp:4.12.0=runtimeClasspath\norg.example:widgets:1.0=compileClasspath,runtimeClasspath\norg.example:widgets:1.0=testCompileClasspath\nempty=annotationProcessor,runtimeOnlyLegacy\n", 0o600)
	goWrite(t, filepath.Join(gapp, "gradle", "dependency-locks", "runtimeOnlyLegacy.lockfile"), "# legacy\norg.example:superseded:0.9\n", 0o600)
	goWrite(t, filepath.Join(gapp, "gradle", "dependency-locks", "legacyOnly.lockfile"), "# legacy\norg.example:legacy:0.1\n", 0o600)
	goWrite(t, filepath.Join(gapp, "gradle", "libs.versions.toml"), `[versions]
okhttp = "4.12.0"
guava = { strictly = "[32.0, 33.0)", prefer = "32.1.3-jre", reject = ["32.0.0"] }

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
guava = { group = "com.google.guava", name = "guava", version.ref = "guava" }
junit = "junit:junit:4.13.2"
nover = { module = "org.example:nover" }
missing = { module = "org.example:missing", version.ref = "nope" }

[bundles]
net = ["okhttp"]

[plugins]
kotlin = { id = "org.jetbrains.kotlin.jvm", version = "2.0.0" }
`, 0o600)
	goWrite(t, filepath.Join(gapp, "gradle", "verification-metadata.xml"), `<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
  <configuration>
    <verify-metadata>false</verify-metadata>
    <verify-signatures>false</verify-signatures>
    <trusted-artifacts><trust group="org.example" reason="CANARY_REASON"/></trusted-artifacts>
  </configuration>
  <components>
    <component group="org.example" name="widgets" version="1.0">
      <artifact name="widgets-1.0.jar"><sha256 value="`+mavenSHA256A+`" origin="Generated by Gradle"><also-trust value="`+mavenSHA256B+`"/></sha256></artifact>
      <artifact name="widgets-1.0.pom"><sha512 value="CANARYBAD" origin="Generated by Gradle"/></artifact>
    </component>
  </components>
</verification-metadata>
`, 0o600)
	goWrite(t, filepath.Join(gapp, "gradle.properties"), "org.gradle.dependency.verification=off\norg.gradle.mirror.maven.settings=true\n", 0o600)
	goWrite(t, filepath.Join(gapp, "gradle", "wrapper", "gradle-wrapper.properties"), "distributionUrl=http\\://services.gradle.org/distributions/gradle-8.10-bin.zip\n", 0o600)
	goWrite(t, filepath.Join(gapp, "build", "generated", "pom.xml"), mavenTestPOM("org.example", "generated", "1.0"), 0o600)
	goWrite(t, filepath.Join(gapp, ".gradle", "8.10", "pom.xml"), mavenTestPOM("org.example", "state", "1.0"), 0o600)

	// Both build systems in one directory keep an unknown tool attribution.
	mixed := filepath.Join(root, "mixedapp")
	goWrite(t, filepath.Join(mixed, "pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>mixed</artifactId><version>1.0</version></project>", 0o600)
	goWrite(t, filepath.Join(mixed, "build.gradle"), "CANARY_SCRIPT", 0o600)
}

func mavenJSON(t *testing.T, v ...any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func mavenSource(t *testing.T, inv *model.MavenInventory, kind, path string) model.MavenSource {
	t.Helper()
	for _, s := range inv.Sources {
		if s.Kind == kind && s.Path == path {
			return s
		}
	}
	t.Fatalf("no %s source at %s", kind, path)
	return model.MavenSource{}
}

func mavenPackages(inv *model.MavenInventory, evidence, name string) []model.MavenPackage {
	out := []model.MavenPackage{}
	for _, p := range inv.Packages {
		if p.Evidence == evidence && p.PackageName == name {
			out = append(out, p)
		}
	}
	return out
}

// mavenAssertRefs checks the graph the backend validates: unique source IDs,
// parents and children that exist, evidence on its owning kind, and present owners.
func mavenAssertRefs(t *testing.T, inv *model.MavenInventory) {
	t.Helper()
	byID := map[string]model.MavenSource{}
	for _, s := range inv.Sources {
		if _, dup := byID[s.SourceID]; dup {
			t.Errorf("duplicate source %s", s.Path)
		}
		byID[s.SourceID] = s
	}
	for _, s := range inv.Sources {
		if _, ok := byID[s.ParentSourceID]; s.ParentSourceID != "" && !ok {
			t.Errorf("source %s has missing parent", s.Path)
		}
		for _, child := range s.DiscoveredSources {
			if byID[child].ParentSourceID != s.SourceID {
				t.Errorf("source %s lists a child it does not own", s.Path)
			}
		}
		if s.Status == "complete" && s.Presence == "unknown" {
			t.Errorf("complete source %s has unknown presence", s.Path)
		}
	}
	owners := map[string][]string{"declared_dependency": {"manifest", "version_catalog"}, "locked_package": {"lockfile"}, "cached_artifact": {"cached_artifact"}, "verification_reference": {"verification_metadata"}}
	for _, p := range inv.Packages {
		src, ok := byID[p.SourceID]
		if !ok || src.Path != p.SourcePath || !slices.Contains(owners[p.Evidence], src.Kind) || src.Presence != "present" {
			t.Errorf("package %s %s has a wrong owner %+v", p.PackageName, p.Evidence, src)
		}
		if (p.Version != "") != (p.VersionStatus == "known") || p.Evidence == "declared_dependency" && p.Version != "" {
			t.Errorf("package %s %s version %q status %s", p.PackageName, p.Evidence, p.Version, p.VersionStatus)
		}
	}
	for _, p := range inv.Projects {
		if byID[p.SourceID].Kind != "project" || byID[p.SourceID].Path != p.ProjectPath {
			t.Errorf("project %s has a wrong source", p.ProjectPath)
		}
	}
}

func TestMavenScanFixture(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	mavenWriteFixture(t, home, root)
	scanner, _ := mavenTestScanner(t, home)
	inv, maven, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	mavenAssertRefs(t, inv)
	if out := mavenJSON(t, inv, maven, gradle); strings.Contains(out, "CANARY") || strings.Contains(out, "never-a-declaration") {
		t.Fatalf("secret, content or cached POM dependency leaked: %s", out)
	}
	repo := filepath.Join(home, ".m2", "repository")
	if src := mavenSource(t, inv, "maven_repository", repo); src.Status != "partial" || !slices.Equal(src.Reasons, []string{"unsupported_layout"}) || src.ParentSourceID != "" {
		t.Errorf("repository = %+v, want an unparented root partial only for its split prefix", src)
	}
	widgets := filepath.Join(repo, "org", "example", "widgets", "1.0")
	cached := map[string]model.MavenArtifact{}
	for _, p := range mavenPackages(inv, "cached_artifact", "org.example:widgets") {
		if p.Tool == "maven" {
			if p.RepositoryFormat != "maven" || p.Version != "1.0" || p.Scope != "user" {
				t.Errorf("maven cached package = %+v", p)
			}
			cached[p.Artifact.Filename] = *p.Artifact
		}
	}
	if len(cached) != 3 || *cached["widgets-1.0.jar"].Classifier != "" || *cached["widgets-1.0-sources.jar"].Classifier != "sources" || cached["widgets-1.0.jar"].ArtifactRole != "payload" ||
		cached["widgets-1.0.pom"].ArtifactRole != "metadata" || !cached["widgets-1.0.pom"].LocalInstallMarkerPresent || cached["widgets-1.0.jar"].LocalInstallMarkerPresent ||
		cached["widgets-1.0.jar"].Path != filepath.Join(widgets, "widgets-1.0.jar") || cached["widgets-1.0.jar"].SizeBytes != int64(len("CANARY_JAR")) {
		t.Errorf("maven widgets files = %+v", cached)
	}
	snaps := mavenPackages(inv, "cached_artifact", "org.example:snap")
	slices.SortFunc(snaps, func(a, b model.MavenPackage) int { return strings.Compare(a.Artifact.Filename, b.Artifact.Filename) })
	if len(snaps) != 2 || snaps[0].Version != "1.0-SNAPSHOT" || snaps[0].Artifact.FileVersion != "1.0-20240101.120000-1" || snaps[0].Artifact.BaseVersion != "1.0-SNAPSHOT" ||
		snaps[1].Artifact.FileVersion != "" || snaps[1].Artifact.BaseVersion != "1.0-SNAPSHOT" {
		t.Errorf("snapshots = %+v", snaps)
	}
	for _, name := range []string{"com.Example:Foo_2.13", "org.example:android", "org.example:custom"} {
		if len(mavenPackages(inv, "cached_artifact", name)) != 1 {
			t.Errorf("missing cached %s", name)
		}
	}
	for _, name := range []string{"org.example:empty", "installed.org.example:lib", "org.example:lib", "org.apache.maven:dist", "org.example:built", "org.example:generated", "org.example:state"} {
		for _, p := range inv.Packages {
			if p.PackageName == name {
				t.Errorf("unexpected package %+v", p)
			}
		}
	}
	if src := mavenSource(t, inv, "maven_repository", filepath.Join(home, "custom-repo")); src.ParentSourceID != "" || src.Status != "complete" {
		t.Errorf("lead repository = %+v, want an unparented complete root", src)
	}

	gradleFiles := map[string]model.MavenPackage{}
	for _, p := range inv.Packages {
		if p.Evidence == "cached_artifact" && p.Tool == "gradle" {
			gradleFiles[p.Artifact.ContentKey+"/"+p.Artifact.Filename] = p
		}
	}
	for key, want := range map[string]struct{ format, role, classifier string }{
		mavenKey40 + "/widgets-1.0.jar":               {"unknown", "payload", ""},
		mavenKey38 + "/widgets-1.0.pom":               {"maven", "metadata", ""},
		mavenKey39 + "/widgets-1.0-test-fixtures.jar": {"unknown", "payload", "test-fixtures"},
		mavenKey39 + "/widgets-1.0.module":            {"unknown", "metadata", ""},
		mavenKey39 + "/renamed.jar":                   {"unknown", "payload", "<nil>"},
		mavenKey40 + "/relocated-1.0.pom":             {"unknown", "metadata", ""},
		mavenKey40 + "/ivy-2.0.xml":                   {"ivy", "metadata", "<nil>"},
		mavenKey39 + "/thing-2.0.jar":                 {"unknown", "payload", ""},
	} {
		p, ok := gradleFiles[key]
		classifier := "<nil>"
		if ok && p.Artifact.Classifier != nil {
			classifier = *p.Artifact.Classifier
		}
		if !ok || p.RepositoryFormat != want.format || p.Artifact.ArtifactRole != want.role || classifier != want.classifier {
			t.Errorf("gradle %s = %+v, want %+v", key, p, want)
		}
	}
	if len(gradleFiles) != 8 {
		t.Errorf("gradle files = %d, want 8", len(gradleFiles))
	}

	declared := map[string]model.MavenPackage{}
	for _, p := range inv.Packages {
		if p.Evidence == "declared_dependency" && p.Tool == "maven" {
			classifier := ""
			if p.DeclaredClassifier != nil {
				classifier = "|=" + *p.DeclaredClassifier
			}
			declared[p.PackageName+"|"+p.DeclarationRole+"|"+p.DeclarationContext+"|"+p.ProfileID+"|"+p.MavenScope+classifier] = p
		}
	}
	for key, specs := range map[string][]string{
		"org.example:parent|parent|||":                             {"1.0"},
		"org.example:bom|bom_import|||import":                      {"2.0"},
		"org.example:widgets|managed|||":                           {"[1.0, 2.0)"},
		"org.example:widgets|direct|||":                            {"${widgets.version}", "1.0"},
		"org.example:widgets|direct|||test|=sources":               {"1.0"},
		"org.example:widgets|direct||||=":                          {},
		"org.example:leaky|direct|||":                              {"[redacted]"},
		"org.scala-lang:scala-library_2.13|direct|||":              {},
		"org.apache.maven.plugins:maven-compiler-plugin|plugin|||": {"3.13.0"},
		"org.example:plugin-helper|plugin_dependency|plugin:org.apache.maven.plugins:maven-compiler-plugin||": {"1.0"},
		"org.example:managed-plugin|managed_plugin|||":                                                        {"1.0"},
		"org.example:ext|extension|||":                                                                        {"1.0"},
		"org.example:ci-only|direct||ci|":                                                                     {"1.0"},
	} {
		if p, ok := declared[key]; !ok || !slices.Equal(p.RequestedSpecs, specs) {
			t.Errorf("declaration %s = %+v, want specs %q", key, p, specs)
		}
	}
	if p := declared["org.example:widgets|direct|||test|=sources"]; !*p.Optional {
		t.Errorf("classified declaration = %+v", p)
	}
	if n := len(mavenPackages(inv, "declared_dependency", "org.example:widgets")); n != 4 {
		t.Errorf("widgets declarations = %d, want managed, consolidated direct, classified and empty-classifier rows", n)
	}
	manifest := mavenSource(t, inv, "manifest", filepath.Join(root, "mvnapp", "pom.xml"))
	if manifest.Status != "partial" || !slices.Equal(manifest.Reasons, []string{"redacted_requirement", "unresolved_coordinate"}) {
		t.Errorf("manifest = %+v", manifest)
	}

	gapp := filepath.Join(root, "gradleapp")
	locked := map[string][]string{}
	for _, p := range inv.Packages {
		if p.Evidence == "locked_package" {
			locked[p.PackageName+":"+p.Version] = p.Configurations
		}
	}
	if !slices.Equal(locked["org.example:widgets:1.0"], []string{"compileClasspath", "runtimeClasspath", "testCompileClasspath"}) || len(locked["org.example:legacy:0.1"]) != 1 ||
		locked["org.example:superseded:0.9"] != nil || len(locked) != 3 {
		t.Errorf("locked = %v", locked)
	}
	catalog := map[string][]string{}
	for _, p := range inv.Packages {
		if p.Evidence == "declared_dependency" && p.Tool == "gradle" {
			catalog[p.DeclarationContext] = p.RequestedSpecs
		}
	}
	if !slices.Equal(catalog["catalog:okhttp"], []string{"4.12.0"}) || !slices.Equal(catalog["catalog:guava"], []string{"prefer=32.1.3-jre", "reject=32.0.0", "strictly=[32.0, 33.0)"}) ||
		!slices.Equal(catalog["catalog:junit"], []string{"4.13.2"}) || len(catalog["catalog:nover"]) != 0 || len(catalog["catalog:missing"]) != 0 || len(catalog) != 5 {
		t.Errorf("catalog = %v", catalog)
	}
	if src := mavenSource(t, inv, "version_catalog", filepath.Join(gapp, "gradle", "libs.versions.toml")); !slices.Equal(src.Reasons, []string{"parse_error"}) {
		t.Errorf("catalog source = %+v", src)
	}
	refs := mavenPackages(inv, "verification_reference", "org.example:widgets")
	slices.SortFunc(refs, func(a, b model.MavenPackage) int { return strings.Compare(a.Artifact.Filename, b.Artifact.Filename) })
	if len(refs) != 2 || len(refs[0].RecordedChecksums) != 2 || refs[0].Artifact.Path != "" || refs[0].RecordedChecksums[0].SourceKind != "verification_metadata" ||
		!slices.Equal(refs[1].Reasons, []string{"checksum_invalid"}) || len(refs[1].RecordedChecksums) != 0 {
		t.Errorf("verification references = %+v", refs)
	}
	projects := map[string]string{}
	for _, p := range inv.Projects {
		projects[p.ProjectPath] = p.Tool
	}
	if len(projects) != 3 || projects[filepath.Join(root, "mvnapp")] != "maven" || projects[gapp] != "gradle" || projects[filepath.Join(root, "mixedapp")] != "unknown" {
		t.Errorf("projects = %v", projects)
	}

	findings := map[string]bool{}
	for _, a := range []*model.MavenConfigAudit{maven, gradle} {
		for _, f := range a.Findings {
			findings[f.Code] = true
		}
	}
	for _, code := range []string{"maven-001", "maven-002", "maven-003", "maven-005", "gradle-001", "gradle-003", "gradle-004", "gradle-005"} {
		if !findings[code] {
			t.Errorf("missing finding %s", code)
		}
	}
	if findings["maven-004"] || findings["gradle-002"] || len(findings) != 8 {
		t.Errorf("findings = %v", findings)
	}
	if len(maven.CredentialFiles) != 2 || maven.CredentialFiles[0].Presence != "present" || maven.CredentialFiles[1].Presence != "absent" {
		t.Errorf("credential files = %+v", maven.CredentialFiles)
	}
}

func TestMavenScanEmptyHome(t *testing.T) {
	home := goTestHome(t)
	scanner, _ := mavenTestScanner(t, home)
	inv, maven, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{filepath.Join(home, "missing")}, nil)
	mavenAssertRefs(t, inv)
	if inv.Status != "complete" || len(inv.Packages) != 0 || maven.Status != "complete" || gradle.Status != "complete" {
		t.Fatalf("inventory = %+v, maven = %s, gradle = %s", inv, maven.Status, gradle.Status)
	}
	// Missing default roots are observed absent so earlier facts can retire.
	for _, kind := range []string{"maven_repository", "gradle_cache"} {
		path := filepath.Join(home, ".m2", "repository")
		if kind == "gradle_cache" {
			path = filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")
		}
		if src := mavenSource(t, inv, kind, path); src.Presence != "absent" || src.Status != "complete" {
			t.Errorf("%s = %+v", kind, src)
		}
	}
}

func TestMavenScanDeclines(t *testing.T) {
	home := goTestHome(t)
	mavenWriteFixture(t, home, filepath.Join(home, "projects"))
	service := goTestTarget(home)
	service.Username, service.Uid = "root", "0"
	if runtime.GOOS == model.PlatformWindows {
		service.Username, service.Uid = `NT AUTHORITY\SYSTEM`, "S-1-5-18"
	}
	for _, tc := range []struct {
		name   string
		target *user.User
	}{{"nil", nil}, {"service", service}, {"relative home", &user.User{Username: "dev", Uid: "1000", HomeDir: "home"}}} {
		t.Run(tc.name, func(t *testing.T) {
			scanner, x := mavenTestScanner(t, home)
			inv, maven, gradle := scanner.Scan(context.Background(), tc.target, []string{home}, nil)
			if inv.Status != "partial" || !slices.Equal(inv.Reasons, []string{"user_unresolved"}) || len(inv.Sources) != 0 || maven.Status != "partial" || gradle.Status != "partial" || *x.calls != 0 {
				t.Fatalf("inventory = %+v maven = %+v calls = %d", inv, maven, *x.calls)
			}
		})
	}
}

// An agent running as another account must not read its own environment
// as the developer's; the process scope is reported unsupported.
func TestMavenScanUnverifiedProcess(t *testing.T) {
	home := goTestHome(t)
	scanner, x := mavenTestScanner(t, home)
	x.current = &user.User{Username: "agent", Uid: "1001"}
	x.env["MAVEN_ARGS"] = "-Daether.lrm.enhanced.split=true"
	_, maven, gradle := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
	for _, a := range []*model.MavenConfigAudit{maven, gradle} {
		for _, f := range a.Files {
			if f.Scope == "process" && (f.Status != "unsupported" || !slices.Equal(f.Reasons, []string{"user_unresolved"})) {
				t.Errorf("process file = %+v", f)
			}
		}
		if a.Status != "partial" {
			t.Errorf("audit status = %s", a.Status)
		}
	}
}

func TestMavenScanCanceled(t *testing.T) {
	home := goTestHome(t)
	mavenWriteFixture(t, home, filepath.Join(home, "projects"))
	scanner, x := mavenTestScanner(t, home)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv, maven, gradle := scanner.Scan(ctx, goTestTarget(home), []string{filepath.Join(home, "projects")}, nil)
	if *x.calls != 0 || len(x.reads) != 0 || len(inv.Packages) != 0 || !slices.Contains(inv.Reasons, "deadline_exceeded") || maven.Status != "partial" || gradle.Status != "partial" {
		t.Fatalf("filesystem calls = %d reads = %v inventory = %+v", *x.calls, x.reads, inv)
	}
}

func TestMavenScanLimits(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	mavenWriteFixture(t, home, root)
	scanner, _ := mavenTestScanner(t, home)
	full, _, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	for _, tc := range []struct {
		name   string
		set    func()
		reason string
	}{
		{"records", func() { maxMavenRecords = len(full.Sources) + len(full.Projects) + len(full.Packages) - 5 }, "record_limit"},
		{"output", func() { maxMavenOutputBytes = goJSONSize(full) + (512 << 10) - 4096 }, "output_size_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, output := maxMavenRecords, maxMavenOutputBytes
			defer func() { maxMavenRecords, maxMavenOutputBytes = records, output }()
			tc.set()
			scanner, _ := mavenTestScanner(t, home)
			inv, _, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			mavenAssertRefs(t, inv)
			if !slices.Contains(inv.Reasons, tc.reason) || len(inv.Packages) == 0 || len(inv.Packages) >= len(full.Packages) {
				t.Fatalf("packages = %d of %d, reasons = %v", len(inv.Packages), len(full.Packages), inv.Reasons)
			}
		})
	}
}

func TestMavenScanRepositoryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pom     string
		env     map[string]string
		want    []string
		reasons []string
	}{
		{"default prefix proven by POM", mavenTestPOM("installed.org", "lib", "1.0"), nil, []string{"installed.org:lib"}, []string{}},
		{"default prefix contradicted by POM", mavenTestPOM("org", "lib", "1.0"), nil, nil, []string{"identity_mismatch"}},
		{"oversized POM", mavenTestPOM("installed.org", "lib", "1.0") + strings.Repeat(" ", int(maxMavenMetadataBytes)), nil, nil, []string{"size_limit"}},
		{"expression group is inconclusive", mavenTestPOM("${g}", "lib", "1.0"), nil, nil, []string{"unsupported_layout"}},
		{"observed split flag", mavenTestPOM("installed.org", "lib", "1.0"), map[string]string{"MAVEN_ARGS": "-Daether.lrm.enhanced.split=true"}, nil, []string{"unsupported_layout"}},
		{"explicitly unsplit", mavenTestPOM("installed.org", "lib", "1.0"), map[string]string{"MAVEN_OPTS": "-Daether.enhancedLocalRepository.split=false"}, []string{"installed.org:lib"}, []string{}},
		{"bare Maven define is true", mavenTestPOM("installed.org", "lib", "1.0"), map[string]string{"MAVEN_ARGS": "-Daether.lrm.enhanced.split"}, nil, []string{"unsupported_layout"}},
		{"bare JVM define is empty", mavenTestPOM("installed.org", "lib", "1.0"), map[string]string{"MAVEN_OPTS": "-Daether.lrm.enhanced.split"}, []string{"installed.org:lib"}, []string{}},
		{"refinement without split", mavenTestPOM("installed.org", "lib", "1.0"), map[string]string{"MAVEN_ARGS": "-Daether.lrm.enhanced.splitLocal=true"}, []string{"installed.org:lib"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			dir := filepath.Join(home, ".m2", "repository", "installed", "org", "lib", "1.0")
			goWrite(t, filepath.Join(dir, "lib-1.0.jar"), "JAR", 0o600)
			goWrite(t, filepath.Join(dir, "lib-1.0.pom"), tc.pom, 0o600)
			scanner, x := mavenTestScanner(t, home)
			for k, v := range tc.env {
				x.env[k] = v
			}
			inv, _, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
			names := []string{}
			for _, p := range inv.Packages {
				if !slices.Contains(names, p.PackageName) {
					names = append(names, p.PackageName)
				}
			}
			src := mavenSource(t, inv, "maven_repository", filepath.Join(home, ".m2", "repository"))
			if !slices.Equal(names, tc.want) && len(names)+len(tc.want) > 0 || !slices.Equal(src.Reasons, tc.reasons) {
				t.Fatalf("packages = %v, repository = %+v", names, src)
			}
		})
	}
}

// Outside a default split prefix, a readable literal POM still has to agree
// with the repository path.
func TestMavenScanRepositoryPOMIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pom     string
		want    []string
		reasons []string
	}{
		{"matching POM", mavenTestPOM("org.example", "app", "1"), []string{"org.example:app"}, []string{}},
		{"contradicting POM", mavenTestPOM("org.other", "different", "9"), nil, []string{"identity_mismatch"}},
		{"expression POM keeps the path", mavenTestPOM("${g}", "app", "1"), []string{"org.example:app"}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			dir := filepath.Join(home, ".m2", "repository", "org", "example", "app", "1")
			goWrite(t, filepath.Join(dir, "app-1.jar"), "JAR", 0o600)
			goWrite(t, filepath.Join(dir, "app-1.pom"), tc.pom, 0o600)
			scanner, _ := mavenTestScanner(t, home)
			inv, _, _ := scanner.Scan(context.Background(), goTestTarget(home), nil, nil)
			names := []string{}
			for _, p := range inv.Packages {
				if !slices.Contains(names, p.PackageName) {
					names = append(names, p.PackageName)
				}
			}
			src := mavenSource(t, inv, "maven_repository", filepath.Join(home, ".m2", "repository"))
			if !slices.Equal(names, tc.want) && len(names)+len(tc.want) > 0 || !slices.Equal(src.Reasons, tc.reasons) {
				t.Fatalf("packages = %v, repository = %+v", names, src)
			}
		})
	}
}

// A configuration folder the scan cannot list leaves that manager's project
// context and audit partial instead of reporting its files absent.
func TestMavenScanUnlistedConfigFolder(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	dir := filepath.Join(root, "app")
	wrapper := filepath.Join(dir, ".mvn", "wrapper")
	goWrite(t, filepath.Join(dir, "pom.xml"), mavenTestPOM("org.example", "app", "1"), 0o600)
	goWrite(t, filepath.Join(wrapper, "maven-wrapper.properties"), "distributionUrl=https\\://repo.example.invalid/maven.zip\n", 0o600)
	scanner, _ := mavenTestScanner(t, home)
	scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
		return func(p string) string {
			if p == wrapper || strings.HasPrefix(p, wrapper+string(filepath.Separator)) {
				return "skipped_protected"
			}
			return ""
		}, func(string) bool { return false }
	}
	_, maven, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	if maven.Status != "partial" || !slices.Contains(maven.Reasons, "skipped_protected") || slices.Contains(gradle.Reasons, "skipped_protected") {
		t.Fatalf("maven = %s %v, gradle = %s %v", maven.Status, maven.Reasons, gradle.Status, gradle.Reasons)
	}
	found := false
	for _, c := range maven.Contexts {
		if c.ProjectPath == dir {
			found = true
			if c.SelectionStatus != "partial" {
				t.Errorf("project context = %+v", c)
			}
		}
	}
	if !found {
		t.Errorf("no Maven context for %s in %+v", dir, maven.Contexts)
	}
}

// A walk that reaches a lead root adopts it; one it never reaches leaves it
// unparented, so deleting a project never retires cache facts.
func TestMavenScanRootOwnership(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	inside := filepath.Join(root, "shared-repo")
	goWrite(t, filepath.Join(inside, "org", "example", "a", "1.0", "a-1.0.pom"), mavenTestPOM("org.example", "a", "1.0"), 0o600)
	goWrite(t, filepath.Join(home, ".m2", "settings.xml"), "<settings><localRepository>"+inside+"</localRepository></settings>", 0o600)
	real := filepath.Join(home, "gradle-home")
	goWrite(t, filepath.Join(real, "caches", "modules-2", "files-2.1", "org.example", "b", "1.0", mavenKey40, "b-1.0.jar"), "JAR", 0o600)
	if err := os.Symlink(real, filepath.Join(home, ".gradle")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	scanner, x := mavenTestScanner(t, home)
	x.env["GRADLE_USER_HOME"] = real
	inv, _, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{root, home}, nil)
	mavenAssertRefs(t, inv)
	walk := mavenSource(t, inv, "project_search_root", home)
	if src := mavenSource(t, inv, "maven_repository", inside); src.ParentSourceID != walk.SourceID {
		t.Errorf("walked lead root = %+v, want parent %s", src, walk.SourceID)
	}
	caches, packages := 0, len(mavenPackages(inv, "cached_artifact", "org.example:b"))
	for _, s := range inv.Sources {
		if s.Kind == "gradle_cache" {
			caches++
		}
	}
	if caches != 1 || packages != 1 {
		t.Errorf("gradle caches = %d, packages = %d; an alias must not duplicate evidence", caches, packages)
	}
	if !bytes.Contains([]byte(mavenJSON(t, gradle)), []byte("gradle_user_home")) {
		t.Errorf("gradle audit lacks the verified user home: %s", mavenJSON(t, gradle))
	}
}

func TestMavenScanVerificationPolicyCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, value, component, status string
	}{
		{"invalid policy", "invalid", "", "partial"},
		{"invalid component only", "false", `<component group="${group}" name="lib" version="1"/>`, "complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "projects")
			dir := filepath.Join(root, "app")
			goWrite(t, filepath.Join(dir, "build.gradle"), "", 0o600)
			goWrite(t, filepath.Join(dir, "gradle", "verification-metadata.xml"), `<verification-metadata><configuration><verify-metadata>`+tc.value+`</verify-metadata></configuration><components>`+tc.component+`</components></verification-metadata>`, 0o600)
			scanner, _ := mavenTestScanner(t, home)
			inv, _, audit := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			if inv.Status != "partial" || audit.Status != tc.status {
				t.Fatalf("inventory=%s audit=%s reasons=%v", inv.Status, audit.Status, audit.Reasons)
			}
			for _, c := range audit.Contexts {
				if c.ProjectPath == dir && (c.SelectionStatus == "partial") != (tc.status == "partial") {
					t.Errorf("project coverage=%s", c.SelectionStatus)
				}
			}
		})
	}
}

func TestMavenScanKnownRootsAtLimit(t *testing.T) {
	old := maxMavenRecords
	t.Cleanup(func() { maxMavenRecords = old })
	maxMavenRecords = 3
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	goWrite(t, filepath.Join(root, "app", "pom.xml"), mavenTestPOM("org.example", "app", "1"), 0o600)
	scanner, _ := mavenTestScanner(t, home)
	inv, _, _ := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
	for _, r := range []struct{ kind, path string }{
		{"maven_repository", filepath.Join(home, ".m2", "repository")},
		{"gradle_cache", filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1")},
	} {
		src := mavenSource(t, inv, r.kind, r.path)
		if src.Presence != "unknown" || src.Status != "partial" || !slices.Contains(src.Reasons, "record_limit") {
			t.Errorf("unscanned root=%+v", src)
		}
	}
	for _, manager := range []string{"maven", "gradle"} {
		t.Run(manager+" project source", func(t *testing.T) {
			maxMavenRecords = 4
			home := goTestHome(t)
			root := filepath.Join(home, "projects")
			dir := filepath.Join(root, "app")
			if manager == "maven" {
				goWrite(t, filepath.Join(dir, "pom.xml"), mavenTestPOM("org.example", "app", "1"), 0o600)
			} else {
				goWrite(t, filepath.Join(dir, "build.gradle"), "", 0o600)
				goWrite(t, filepath.Join(dir, "gradle", "verification-metadata.xml"), `<verification-metadata/>`, 0o600)
			}
			scanner, _ := mavenTestScanner(t, home)
			_, maven, gradle := scanner.Scan(t.Context(), goTestTarget(home), []string{root}, nil)
			audit, other := maven, gradle
			if manager == "gradle" {
				audit, other = gradle, maven
			}
			if audit.Status != "partial" || !slices.Contains(audit.Reasons, "record_limit") || slices.Contains(other.Reasons, "record_limit") {
				t.Fatalf("audit = %s %v, other = %s %v", audit.Status, audit.Reasons, other.Status, other.Reasons)
			}
			found := false
			for _, c := range audit.Contexts {
				if c.ProjectPath == dir {
					found = true
					if c.SelectionStatus != "partial" {
						t.Errorf("project context = %+v", c)
					}
				}
			}
			if !found {
				t.Fatal("project context missing")
			}
		})
	}

}

type mavenInfoTrap struct {
	os.DirEntry
	t *testing.T
}

func (e mavenInfoTrap) Info() (os.FileInfo, error) {
	e.t.Fatal("unguarded file metadata read")
	return nil, os.ErrNotExist
}

func TestMavenScanQueuedMetadataCanceled(t *testing.T) {
	dir := t.TempDir()
	goWrite(t, filepath.Join(dir, "lib-1.jar"), "fixture", 0o600)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	repo := &model.MavenSource{SourceID: "repo"}
	c := &mavenScan{ctx: ctx, inv: emptyMavenInventory(), byID: map[string]*model.MavenSource{"repo": repo}}
	c.versionDir(repo, nil, mavenRoot{}, dir, []string{"org", "example", "lib", "1"}, []os.DirEntry{mavenInfoTrap{entries[0], t}})
	if !slices.Contains(repo.Reasons, "deadline_exceeded") {
		t.Errorf("stop reason missing: %v", repo.Reasons)
	}
	t.Run("protected queued artifact", func(t *testing.T) {
		repo := &model.MavenSource{SourceID: "repo"}
		guard := func(path string) string {
			if path == filepath.Join(dir, "lib-1.jar") {
				return "skipped_protected"
			}
			return ""
		}
		files := executor.NewReal().GuardedFiles([]string{dir}, guard, 0)
		c := &mavenScan{ctx: t.Context(), remaining: 10, guard: guard, inv: emptyMavenInventory(), byID: map[string]*model.MavenSource{"repo": repo}}
		c.versionDir(repo, files, mavenRoot{}, dir, []string{"org", "example", "lib", "1"}, []os.DirEntry{mavenInfoTrap{entries[0], t}})
		if !slices.Contains(repo.Reasons, "skipped_protected") || len(c.inv.Packages) != 0 {
			t.Errorf("protected artifact = %v, packages = %d", repo.Reasons, len(c.inv.Packages))
		}
	})

}

// A configuration folder that cannot be listed may hide project files, so the
// project itself is partial, not only its walk and audit context.
func TestMavenScanUnlistedProjectFolder(t *testing.T) {
	for _, tc := range []struct{ name, blocked string }{
		{"control", ""},
		{"gradle folder", "gradle"},
		{"legacy locks", filepath.Join("gradle", "dependency-locks")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := goTestHome(t)
			root := filepath.Join(home, "projects")
			dir := filepath.Join(root, "app")
			goWrite(t, filepath.Join(dir, "build.gradle"), "", 0o600)
			goWrite(t, filepath.Join(dir, "gradle", "libs.versions.toml"), "[libraries]\na = \"org.example:a:1.0\"\n", 0o600)
			goWrite(t, filepath.Join(dir, "gradle", "dependency-locks", "compileClasspath.lockfile"), "org.example:a:1.0\n", 0o600)
			scanner, _ := mavenTestScanner(t, home)
			blocked := filepath.Join(dir, tc.blocked)
			scanner.protection = func(string, *bool) (func(string) string, func(string) bool) {
				return func(p string) string {
					if tc.blocked != "" && (p == blocked || strings.HasPrefix(p, blocked+string(filepath.Separator))) {
						return "skipped_protected"
					}
					return ""
				}, func(string) bool { return false }
			}
			inv, _, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
			src := mavenSource(t, inv, "project", dir)
			if tc.blocked == "" {
				if src.Status != "complete" || gradle.Status != "complete" {
					t.Errorf("project = %+v, gradle = %s %v", src, gradle.Status, gradle.Reasons)
				}
				return
			}
			if src.Status != "partial" || !slices.Contains(src.Reasons, "skipped_protected") {
				t.Errorf("project = %+v", src)
			}
		})
	}
}

// A profile ID Maven accepts but the audit cannot report still declares its
// repositories, so their findings are kept and coverage is partial.
func TestMavenScanUnsupportedProfileRepositories(t *testing.T) {
	home := goTestHome(t)
	root := filepath.Join(home, "projects")
	dir := filepath.Join(root, "app")
	goWrite(t, filepath.Join(dir, "pom.xml"), `<project><groupId>org.example</groupId><artifactId>app</artifactId><version>1</version>
<profiles><profile><id>team ci</id><repositories><repository><id>team</id><url>http://team.example.invalid/maven</url>
<releases><checksumPolicy>warn</checksumPolicy></releases></repository></repositories></profile></profiles></project>`, 0o600)
	scanner, _ := mavenTestScanner(t, home)
	_, maven, _ := scanner.Scan(context.Background(), goTestTarget(home), []string{root}, nil)
	keys := []string{}
	for _, f := range maven.Findings {
		keys = append(keys, f.Code+" "+f.Key)
	}
	for _, want := range []string{"maven-001 repositories.0.url", "maven-002 repositories.0.releases_checksum_policy"} {
		if !slices.Contains(keys, want) {
			t.Errorf("findings %v lack %s", keys, want)
		}
	}
	if maven.Status != "partial" {
		t.Errorf("audit = %s %v", maven.Status, maven.Reasons)
	}
}

// mavenListTrap records every directory the scan lists.
type mavenListTrap struct {
	*mavenTrap
	listed *[]string
}

func (x *mavenListTrap) GuardedFiles(roots []string, guard func(string) string, max int64) executor.Executor {
	return &mavenListTrap{x.mavenTrap.GuardedFiles(roots, guard, max).(*mavenTrap), x.listed}
}
func (x *mavenListTrap) ReadDirLimit(path string, max int) ([]os.DirEntry, bool, error) {
	*x.listed = append(*x.listed, path)
	return x.mavenTrap.ReadDirLimit(path, max)
}

// Symlinked default tool homes are pruned at their physical path, so a home
// search never walks them as ordinary directories.
func TestMavenScanSymlinkedToolHomes(t *testing.T) {
	home := goTestHome(t)
	m2, gradleHome := filepath.Join(home, "tools", "m2"), filepath.Join(home, "tools", "gradle-home")
	goWrite(t, filepath.Join(m2, "settings.xml"), "<settings/>", 0o600)
	goWrite(t, filepath.Join(m2, "repository", "org", "example", "a", "1.0", "a-1.0.pom"), mavenTestPOM("org.example", "a", "1.0"), 0o600)
	goWrite(t, filepath.Join(m2, "wrapper", "dists", "apache-maven-3.9.9-bin", "conf", "settings.xml"), "<settings/>", 0o600)
	goWrite(t, filepath.Join(gradleHome, "gradle.properties"), "org.gradle.caching=true\n", 0o600)
	goWrite(t, filepath.Join(gradleHome, "caches", "modules-2", "files-2.1", "org.example", "b", "1.0", mavenKey40, "b-1.0.jar"), "JAR", 0o600)
	for target, link := range map[string]string{m2: ".m2", gradleHome: ".gradle"} {
		if err := os.Symlink(target, filepath.Join(home, link)); err != nil {
			t.Skip("symlinks unavailable:", err)
		}
	}
	project := filepath.Join(home, "projects", "app")
	goWrite(t, filepath.Join(project, "pom.xml"), mavenTestPOM("org.example", "app", "1"), 0o600)
	scanner, x := mavenTestScanner(t, home)
	listed := []string{}
	trapped := &mavenListTrap{x, &listed}
	protection := scanner.protection
	scanner = NewMavenScanner(trapped, progress.NewNoop())
	scanner.protection = protection
	inv, maven, gradle := scanner.Scan(context.Background(), goTestTarget(home), []string{home}, nil)
	mavenAssertRefs(t, inv)
	for _, p := range listed {
		if p == m2 || p == gradleHome || goPathWithin(p, filepath.Join(m2, "wrapper")) {
			t.Errorf("walk listed tool home %s", p)
		}
	}
	projects := []string{}
	for _, p := range inv.Projects {
		projects = append(projects, p.ProjectPath)
	}
	if !slices.Equal(projects, []string{project}) {
		t.Errorf("projects = %v, want only %s", projects, project)
	}
	for _, a := range []*model.RubyConfigAudit{maven, gradle} {
		for _, f := range a.Files {
			if f.Scope == "project" && f.Path != filepath.Join(project, "pom.xml") {
				t.Errorf("tool-home file audited as project configuration: %+v", f)
			}
		}
	}
	if len(mavenPackages(inv, "cached_artifact", "org.example:a")) != 1 || len(mavenPackages(inv, "cached_artifact", "org.example:b")) != 1 {
		t.Errorf("cached evidence lost: %s", mavenJSON(t, inv.Packages))
	}
}
