package plugin

import (
	"path/filepath"
	"testing"
	"time"

	model "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// pyNodeIn builds one Python dependency node whose declaration site is the
// requirements file of projectRoot.
func pyNodeIn(t *testing.T, name, version, projectRoot string) *model.DependencyNode {
	t.Helper()
	dep := testkit.MustDependencyCoords(t, model.Coordinates{
		Name: name, Version: version, Ecosystem: model.EcosystemPython, PackageManager: "pip",
	})
	if projectRoot != "" {
		dep.Locations = []model.PackageLocation{{RealPath: filepath.Join(projectRoot, "requirements.txt")}}
	}
	dep.PackageRef = dep.NodeID()
	return dep
}

func pyGraph(t *testing.T, nodes []*model.DependencyNode, ids []string) (*model.Graph, *model.PackageRegistry) {
	t.Helper()
	g := model.New()
	registry := model.NewPackageRegistry()
	for i, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
		registry.Ensure(node.PackageRef).Vulnerabilities = append(
			registry.Ensure(node.PackageRef).Vulnerabilities,
			model.Vulnerability{ID: ids[i], Source: "osv"},
		)
	}
	return g, registry
}

func pyReachability(t *testing.T, registry *model.PackageRegistry, purl string) *model.Reachability {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no vulnerability for %q", purl)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func pyRoots(r *model.Reachability) []string {
	if r == nil {
		return nil
	}
	roots := make([]string, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		roots = append(roots, e.ModuleRoot)
	}
	return roots
}

// TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt is the core of row 2.8.
//
// A distribution declared by apps/api must not collect apps/web's finding.
// Before attribution was real, packageBelongsToProjectRoot ended in an
// unconditional `return true`, so every Python package took every root's
// answer — including an "unreachable" from a project it was never part of.
func TestEvidenceIsKeyedByTheProjectRootThatEstablishedIt(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "apps", "api")
	webRoot := filepath.Join(workspace, "apps", "web")

	apiDep := pyNodeIn(t, "requests", "2.31.0", apiRoot)
	webDep := pyNodeIn(t, "django", "4.2.0", webRoot)
	g, registry := pyGraph(t, []*model.DependencyNode{apiDep, webDep}, []string{"PYSEC-1", "PYSEC-2"})
	req := model.AnalyzeRequest{Graph: g, Registry: registry}

	attributor := newRootAttributor(g, []string{apiRoot, webRoot})
	for _, root := range []string{apiRoot, webRoot} {
		applyRunnerResult(req, attributor, root, RunnerResult{}, time.Time{})
	}

	for _, tc := range []struct {
		dep  *model.DependencyNode
		want string
	}{{apiDep, apiRoot}, {webDep, webRoot}} {
		roots := pyRoots(pyReachability(t, registry, tc.dep.PackageRef))
		if len(roots) != 1 || roots[0] != tc.want {
			t.Errorf("%s evidence roots = %v, want exactly [%s]", tc.dep.Name, roots, tc.want)
		}
	}
}

// TestEvidenceNeverNamesAnOccurrenceNode records the judgement row 2.8 asks
// for: pyreach speaks at module-root granularity and no lower.
//
// Its seed set is keyed by canonical distribution name (isPackageImported), so
// two graph nodes for one distribution at two versions are seeded identically
// and the analysis never separates them — a pip environment installs one copy
// per distribution, which is why the name key was enough. Naming the node this
// loop happens to be visiting would publish an occurrence the analysis did not
// establish. Empty refs mean "not stated", never "no occurrence".
func TestEvidenceNeverNamesAnOccurrenceNode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	// Two occurrences of one distribution. The import scanner sees the name
	// "requests" and nothing that could tell the two apart.
	first := pyNodeIn(t, "requests", "2.31.0", root)
	second := pyNodeIn(t, "requests", "2.25.1", root)
	g, registry := pyGraph(t, []*model.DependencyNode{first, second}, []string{"PYSEC-1", "PYSEC-1"})

	applyRunnerResult(model.AnalyzeRequest{Graph: g, Registry: registry},
		newRootAttributor(g, []string{root}), root,
		RunnerResult{ImportedDistributions: map[string]struct{}{"requests": {}}}, time.Time{})

	for _, dep := range []*model.DependencyNode{first, second} {
		evidence := pyReachability(t, registry, dep.PackageRef).Evidence
		if len(evidence) != 1 {
			t.Fatalf("%s evidence = %d entries, want 1", dep.Version, len(evidence))
		}
		if evidence[0].ModuleRoot != root {
			t.Errorf("%s module root = %q, want %q: the floor is mandatory", dep.Version, evidence[0].ModuleRoot, root)
		}
		if got := evidence[0].DependencyRefs; len(got) != 0 {
			t.Errorf("%s refs = %v; the name-keyed seed set cannot separate two copies of one distribution", dep.Version, got)
		}
	}
}

// TestFailedProjectRootStillContributesUnknownEvidence pins the safety half in
// the failure path: one root finding nothing must not speak for a workspace
// whose other root was never analyzed.
func TestFailedProjectRootStillContributesUnknownEvidence(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := filepath.Join(workspace, "apps", "api")
	webRoot := filepath.Join(workspace, "apps", "web")

	dep := pyNodeIn(t, "requests", "2.31.0", apiRoot)
	dep.Locations = append(dep.Locations, model.PackageLocation{
		RealPath: filepath.Join(webRoot, "requirements.txt"),
	})
	g, registry := pyGraph(t, []*model.DependencyNode{dep}, []string{"PYSEC-1"})
	req := model.AnalyzeRequest{Graph: g, Registry: registry}

	attributor := newRootAttributor(g, []string{apiRoot, webRoot})
	applyRunnerResult(req, attributor, apiRoot, RunnerResult{}, time.Time{})
	annotateProjectUnknown(req, attributor, webRoot, "missing-toolchain", time.Time{})

	r := pyReachability(t, registry, dep.PackageRef)
	if len(r.Evidence) != 2 {
		t.Fatalf("evidence = %d entries (%v), want one per project root", len(r.Evidence), pyRoots(r))
	}
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown: one root was never analyzed", r.Status)
	}
	if r.Reason == "" {
		t.Error("an unknown summary must still explain itself")
	}
}

// TestSiteOutsideEveryAnalyzedRootIsNotAbsence separates the two ways a path
// can fail to match. A site under another analyzed root is evidence the
// package belongs elsewhere; a site under no analyzed root at all — a shared
// virtualenv, a system site-packages — says nothing, and reading it as absence
// would silently drop the finding.
func TestSiteOutsideEveryAnalyzedRootIsNotAbsence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	venv := filepath.Join(t.TempDir(), "shared-venv")

	dep := pyNodeIn(t, "requests", "2.31.0", venv)
	g, registry := pyGraph(t, []*model.DependencyNode{dep}, []string{"PYSEC-1"})

	applyRunnerResult(model.AnalyzeRequest{Graph: g, Registry: registry},
		newRootAttributor(g, []string{root}), root, RunnerResult{}, time.Time{})

	r := pyReachability(t, registry, dep.PackageRef)
	if r == nil || len(r.Evidence) != 1 {
		t.Fatalf("evidence = %v; a site outside every analyzed root is not absence", pyRoots(r))
	}
	if r.Evidence[0].ModuleRoot != root {
		t.Errorf("module root = %q, want %q", r.Evidence[0].ModuleRoot, root)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path. Detectors record the root they resolved from and this
// analyzer derives roots from the filesystem; when the spellings never
// overlap, a non-match means they are speaking past each other, and dropping
// the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "app")
	dep := pyNodeIn(t, "requests", "2.31.0", "")
	dep.Locations = []model.PackageLocation{{ModuleRoot: "apps/api"}}
	g, registry := pyGraph(t, []*model.DependencyNode{dep}, []string{"PYSEC-1"})

	applyRunnerResult(model.AnalyzeRequest{Graph: g, Registry: registry},
		newRootAttributor(g, []string{root}), root, RunnerResult{}, time.Time{})

	if r := pyReachability(t, registry, dep.PackageRef); r == nil || len(r.Evidence) == 0 {
		t.Fatal("evidence was dropped for a root vocabulary mismatch; the finding is lost")
	}
}

// TestAttributorCalibratesOnOverlap pins the calibration on its own, so both
// halves of the rule hold independently of a full analysis pass.
func TestAttributorCalibratesOnOverlap(t *testing.T) {
	node := pyNodeIn(t, "requests", "2.31.0", "")
	node.Locations = []model.PackageLocation{{ModuleRoot: "/ws/api"}}
	g := model.New()
	if err := g.AddNode(node); err != nil {
		t.Fatal(err)
	}

	shared := newRootAttributor(g, []string{"/ws/api", "/ws/web"})
	if got := shared.attribute(node, "/ws/api"); got != attributedToSite {
		t.Errorf("attribute(own root) = %v, want attributedToSite", got)
	}
	if got := shared.attribute(node, "/ws/web"); got != attributedElsewhere {
		t.Errorf("attribute(other root) = %v, want attributedElsewhere", got)
	}

	foreign := newRootAttributor(g, []string{"/other/one"})
	if got := foreign.attribute(node, "/other/one"); got != attributedToRootOnly {
		t.Errorf("attribute under a foreign vocabulary = %v, want attributedToRootOnly", got)
	}
}
