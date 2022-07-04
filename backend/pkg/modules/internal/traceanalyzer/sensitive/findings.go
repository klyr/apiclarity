// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensitive

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-openapi/jsonpointer"

	oapicommon "github.com/openclarity/apiclarity/api3/common"
	"github.com/openclarity/apiclarity/backend/pkg/modules/internal/traceanalyzer/utils"
)

const (
	RegexpMatchingType = "REGEXP_MATCHING"
)

type AnnotationRegexpMatching struct {
	Matches []RuleMatch `json:"matches"`
}

func NewAnnotationRegexpMatching(matches []RuleMatch) *AnnotationRegexpMatching {
	return &AnnotationRegexpMatching{
		Matches: matches,
	}
}
func (a *AnnotationRegexpMatching) Name() string { return RegexpMatchingType }
func (a *AnnotationRegexpMatching) NewAPIAnnotation(path, method string) utils.TraceAnalyzerAPIAnnotation {
	return NewAPIAnnotationRegexpMatching(path, method)
}
func (a *AnnotationRegexpMatching) Severity() string           { return utils.SeverityMedium }
func (a *AnnotationRegexpMatching) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *AnnotationRegexpMatching) Deserialize(serialized []byte) error {
	var tmp AnnotationRegexpMatching
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a AnnotationRegexpMatching) Redacted() utils.TraceAnalyzerAnnotation {
	return &a
}

func (a *AnnotationRegexpMatching) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Matching regular expression",
		DetailedDesc: fmt.Sprintf("This event matches sensitive information"),
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

type APIAnnotationRegexpMatching struct {
	SpecLocation  string          `json:"spec_location"`
	MatchingRules map[string]bool `json:"matching_rules_id"`
}

func NewAPIAnnotationRegexpMatching(path, method string) *APIAnnotationRegexpMatching {
	pointerTokens := []string{
		jsonpointer.Escape("paths"),
		jsonpointer.Escape(path),
		jsonpointer.Escape(strings.ToLower(method)),
	}
	pointer := strings.Join(pointerTokens, "/")
	return &APIAnnotationRegexpMatching{
		SpecLocation:  pointer,
		MatchingRules: make(map[string]bool),
	}
}
func (a *APIAnnotationRegexpMatching) Name() string { return RegexpMatchingType }
func (a *APIAnnotationRegexpMatching) Aggregate(ann utils.TraceAnalyzerAnnotation) (updated bool) {
	eventAnn, valid := ann.(*AnnotationRegexpMatching)
	if !valid {
		panic("invalid type")
	}

	initialSize := len(a.MatchingRules)
	for _, r := range eventAnn.Matches {
		a.MatchingRules[r.Rule.ID] = true
	}

	return initialSize != len(a.MatchingRules)
}

func (a *APIAnnotationRegexpMatching) Severity() string   { return utils.SeverityInfo }
func (a *APIAnnotationRegexpMatching) TTL() time.Duration { return 24 * time.Hour }

func (a *APIAnnotationRegexpMatching) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *APIAnnotationRegexpMatching) Deserialize(serialized []byte) error {
	var tmp APIAnnotationRegexpMatching
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a APIAnnotationRegexpMatching) Redacted() utils.TraceAnalyzerAPIAnnotation {
	newA := a
	return &newA
}

func (a *APIAnnotationRegexpMatching) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Matching regular expression",
		DetailedDesc: "This event matches sensitive information",
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

func (a *APIAnnotationRegexpMatching) ToAPIFinding() oapicommon.APIFinding {
	var additionalInfo *map[string]interface{}
	if len(a.MatchingRules) > 0 {
		matchingRules := []string{}
		for r := range a.MatchingRules {
			matchingRules = append(matchingRules, r)
		}
		additionalInfo = &map[string]interface{}{
			"matching_rules": matchingRules,
		}
	}
	return oapicommon.APIFinding{
		Source: utils.ModuleName,

		Type:        a.Name(),
		Name:        "Matching regular expression",
		Description: "This event matches sensitive information",

		ProvidedSpecLocation:      &a.SpecLocation,
		ReconstructedSpecLocation: &a.SpecLocation,

		Severity: oapicommon.INFO,

		AdditionalInfo: additionalInfo,
	}
}
