// Package profiles provides an embedded, versioned database of reference
// browser fingerprints used as diff targets.
package profiles

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/North-web-dev/fpcheck/internal/model"
)

//go:embed profiles.json
var raw []byte

// Profile is one reference entry. Accuracy states how much to trust it; JA4
// b/c hashes in particular drift between browser builds.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Accuracy    string `json:"accuracy"`
	JA3Hash     string `json:"ja3_hash,omitempty"`
	JA4         string `json:"ja4,omitempty"`
	AkamaiH2    string `json:"akamai_h2,omitempty"`
}

type db struct {
	Version  int       `json:"version"`
	Note     string    `json:"note"`
	Profiles []Profile `json:"profiles"`
}

var loaded db

func init() {
	if err := json.Unmarshal(raw, &loaded); err != nil {
		panic("profiles: invalid embedded database: " + err.Error())
	}
}

// Get returns the named reference profile as a Fingerprint for diffing.
func Get(name string) (*model.Fingerprint, *Profile, error) {
	for i := range loaded.Profiles {
		if loaded.Profiles[i].Name == name {
			p := loaded.Profiles[i]
			return &model.Fingerprint{
				JA3Hash:  p.JA3Hash,
				JA4:      p.JA4,
				AkamaiH2: p.AkamaiH2,
			}, &p, nil
		}
	}
	return nil, nil, fmt.Errorf("no reference profile %q (have: %v)", name, Names())
}

// Names returns the available profile names, sorted.
func Names() []string {
	out := make([]string, len(loaded.Profiles))
	for i, p := range loaded.Profiles {
		out[i] = p.Name
	}
	sort.Strings(out)
	return out
}
