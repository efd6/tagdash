package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

func main() {
	col := flag.String("colour", "#6092C0", "specify tag colour (web colour)")
	desc := flag.String("desc", "", "specify tag description")
	name := flag.String("tag", "", "specify tag name (required)")
	own := flag.String("owner", "", "pattern to match code owner (regexp)")
	owners := flag.String("codeowners", "", "path to CODEOWNERS file")
	flag.Parse()

	if *name == "" || *owners == "" {
		flag.Usage()
		os.Exit(2)
	}
	if !strings.HasPrefix(*col, "#") {
		flag.Usage()
		os.Exit(2)
	}
	if _, err := strconv.ParseUint(strings.TrimPrefix(*col, "#"), 16, 24); err != nil {
		flag.Usage()
		os.Exit(2)
	}
	owner, err := regexp.Compile(*own)
	if err != nil {
		flag.Usage()
		os.Exit(2)
	}

	pkgs, err := packages(*owners, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	uuid, err := uuidFor(*name, pkgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	pkgs, err = packages(*owners, owner)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, p := range pkgs {
		tag, ref, err := makeTag(p, *name, *desc, *col, uuid)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if tag == nil || ref == nil {
			continue
		}
		err = addTag(p, tag, ref)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}

func uuidFor(name string, pkgs []string) (string, error) {
	found := make(map[string][]string)
	for _, path := range pkgs {
		_, _, tags, err := kibanaPaths(path)
		if err != nil {
			return "", err
		}
		pkg := filepath.Base(path)
		for _, p := range tags {
			b, err := os.ReadFile(p)
			if err != nil {
				return "", err
			}
			var t tag
			err = json.Unmarshal(b, &t)
			if err != nil {
				return "", err
			}
			if t.Attributes.Name == name {
				uuid := strings.TrimPrefix(t.ID, pkg+"-")
				found[uuid] = append(found[uuid], pkg)
			}
		}
	}
	switch len(found) {
	case 0:
		return uuid.New().String(), nil
	case 1:
		for uuid := range found {
			return uuid, nil
		}
		panic("unreachable")
	default:
		return "", fmt.Errorf("multiple UUIDs for %s: %v", name, found)
	}
}

func packages(owners string, owner *regexp.Regexp) ([]string, error) {
	f, err := os.Open(owners)
	if err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(owners, "/.github/CODEOWNERS")
	sc := bufio.NewScanner(f)
	var pkgs []string
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || bytes.HasPrefix(b, []byte("#")) || !bytes.HasPrefix(b, []byte("/")) {
			continue
		}
		fields := bytes.Fields(b)
		if len(fields) < 2 {
			continue
		}
		if owner == nil || owner.Match(bytes.Join(fields[1:], []byte(" "))) {
			pkgs = append(pkgs, base+string(fields[0]))
		}
	}
	return pkgs, sc.Err()
}

func makeTag(path, name, desc, colour, uuid string) (*tag, *reference, error) {
	_, dashboards, tags, err := kibanaPaths(path)
	if err != nil || len(dashboards) == 0 {
		return nil, nil, err
	}
	pkg := filepath.Base(path)

	for _, p := range tags {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		var t tag
		err = json.Unmarshal(b, &t)
		if err != nil {
			return nil, nil, err
		}
		if t.Attributes.Name == name {
			// We already have a tag UUID, so use it.
			uuid = strings.TrimPrefix(t.ID, pkg+"-")
			break
		}
	}

	_, coreMigrationVersion, err := dashBoardDetails(dashboards[0])
	if err != nil {
		return nil, nil, err
	}
	migration := strings.TrimPrefix(semver.Major("v"+coreMigrationVersion), "v")
	if migration == "" {
		return nil, nil, fmt.Errorf("invalid coreMigrationVersion in %s: %q", dashboards[0], coreMigrationVersion)
	}
	migration += ".0.0"
	t := &tag{
		Attributes: attributes{
			Color:       colour,
			Description: desc,
			Name:        name,
		},
		CoreMigrationVersion: coreMigrationVersion,
		ID:                   fmt.Sprintf("%s-%s", pkg, uuid),
		MigrationVersion:     migrationVersion{migration},
		Reference:            []reference{},
		Type:                 "tag",
	}
	r := &reference{
		ID:   t.ID,
		Name: fmt.Sprintf("tag-%s", uuid),
		Type: "tag",
	}
	return t, r, nil
}

func dashBoardDetails(path string) (typ, coreMigrationVersion string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	var dash map[string]interface{}
	err = json.Unmarshal(b, &dash)
	if err != nil {
		return "", "", err
	}
	typ, ok := dash["type"].(string)
	if !ok {
		return "", "", fmt.Errorf("no type in dashboard %s", path)
	}
	coreMigrationVersion, ok = dash["coreMigrationVersion"].(string)
	if !ok {
		return "", "", fmt.Errorf("no coreMigrationVersion in dashboard %s", path)
	}
	return typ, coreMigrationVersion, nil
}

func addTag(path string, t *tag, r *reference) error {
	kibana, dashboards, _, err := kibanaPaths(path)
	if err != nil || len(dashboards) == 0 {
		return err
	}

	// Add the tag object to the kibana tree.
	tags := filepath.Join(kibana, "tag")
	err = os.Mkdir(tags, 0o755)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	tag := filepath.Join(tags, t.ID+".json")
	b, err := json.MarshalIndent(t, "", "    ")
	if err != nil {
		return err
	}
	err = os.WriteFile(tag, b, 0o644)
	if err != nil {
		return err
	}

	// Use the tag in the dashboards.
	for _, p := range dashboards {
		b, err = os.ReadFile(p)
		if err != nil {
			return nil
		}
		var dash map[string]interface{}
		err = json.Unmarshal(b, &dash)
		if err != nil {
			return err
		}
		references, ok := dash["references"]
		if ok {
			refs, ok := references.([]interface{})
			if !ok {
				return fmt.Errorf("unexpected type for dashboard references: %T", references)
			}
			found := false
			for _, o := range refs {
				old, ok := o.(map[string]interface{})
				if !ok {
					return fmt.Errorf("unexpected type for dashboard reference: %T", o)
				}
				if old["id"] == r.ID {
					found = true
					break
				}
			}
			if !found {
				references = append(refs, r)
			}
		} else {
			references = []*reference{r}
		}

		dash["references"] = references
		b, err = json.MarshalIndent(dash, "", "    ")
		if err != nil {
			return err
		}
		err = os.WriteFile(p, b, 0o644)
		if err != nil {
			return err
		}
	}

	return nil
}

func kibanaPaths(path string) (kibana string, dashboards, tags []string, err error) {
	kibana = filepath.Join(path, "kibana")
	_, err = os.Stat(kibana)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, nil, nil
	}
	dashboards, err = filepath.Glob(filepath.Join(kibana, "dashboard", "*.json"))
	if err != nil {
		return "", nil, nil, err
	}
	tags, err = filepath.Glob(filepath.Join(kibana, "tag", "*.json"))
	if err != nil {
		return "", nil, nil, err
	}
	return kibana, dashboards, tags, nil
}

type tag struct {
	Attributes           attributes       `json:"attributes"`
	CoreMigrationVersion string           `json:"coreMigrationVersion"`
	ID                   string           `json:"id"`
	MigrationVersion     migrationVersion `json:"migrationVersion"`
	Reference            []reference      `json:"references"`
	Type                 string           `json:"type"`
}

type attributes struct {
	Color       string `json:"color"`
	Description string `json:"description"`
	Name        string `json:"name"`
}

type migrationVersion struct {
	Tag string `json:"tag"`
}

type reference struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}
