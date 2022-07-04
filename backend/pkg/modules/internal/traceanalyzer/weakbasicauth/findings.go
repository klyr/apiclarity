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

package weakbasicauth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	oapicommon "github.com/openclarity/apiclarity/api3/common"
	"github.com/openclarity/apiclarity/backend/pkg/modules/internal/traceanalyzer/utils"
)

const (
	//nolint:gosec
	KindShortPassword = "BASIC_AUTH_SHORT_PASSWORD"
	//nolint:gosec
	KindKnownPassword = "BASIC_AUTH_KNOWN_PASSWORD"
	//nolint:gosec
	KindSamePassword = "BASIC_AUTH_SAME_PASSWORD"
)

type AnnotationShortPassword struct {
	Password string `json:"password"`
	Length   int    `json:"length"`
	MinSize  int    `json:"min_size"`
}

func NewAnnotationShortPassword(password string, minSize int) *AnnotationShortPassword {
	return &AnnotationShortPassword{Password: password, Length: len(password), MinSize: minSize}
}
func (a *AnnotationShortPassword) Name() string { return KindShortPassword }
func (a *AnnotationShortPassword) NewAPIAnnotation(path, method string) utils.TraceAnalyzerAPIAnnotation {
	return NewAPIAnnotationShortPassword(path, method)
}
func (a *AnnotationShortPassword) Severity() string           { return utils.SeverityMedium }
func (a *AnnotationShortPassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *AnnotationShortPassword) Deserialize(serialized []byte) error {
	var tmp AnnotationShortPassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a AnnotationShortPassword) Redacted() utils.TraceAnalyzerAnnotation {
	return &AnnotationShortPassword{"XXX", a.Length, a.MinSize}
}

func (a *AnnotationShortPassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Too short Basic Auth password",
		DetailedDesc: fmt.Sprintf("The length of Basic Auth password (%s) is too short (%d) should be greater than %d", a.Password, a.Length, a.MinSize),
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

type APIAnnotationShortPassword struct {
	SpecLocation string `json:"spec_location"`
}

func NewAPIAnnotationShortPassword(path, method string) *APIAnnotationShortPassword {
	pointerTokens := []string{}
	pointer := strings.Join(pointerTokens, "/")
	return &APIAnnotationShortPassword{
		SpecLocation: pointer,
	}
}
func (a *APIAnnotationShortPassword) Name() string { return KindShortPassword }
func (a *APIAnnotationShortPassword) Aggregate(ann utils.TraceAnalyzerAnnotation) (updated bool) {
	_, valid := ann.(*AnnotationShortPassword)
	if !valid {
		panic("invalid type")
	}

	return false
}

func (a *APIAnnotationShortPassword) Severity() string   { return utils.SeverityInfo }
func (a *APIAnnotationShortPassword) TTL() time.Duration { return 24 * time.Hour }

func (a *APIAnnotationShortPassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *APIAnnotationShortPassword) Deserialize(serialized []byte) error {
	var tmp APIAnnotationShortPassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a APIAnnotationShortPassword) Redacted() utils.TraceAnalyzerAPIAnnotation {
	newA := a
	return &newA
}

func (a *APIAnnotationShortPassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Too short Basic Auth password",
		DetailedDesc: "Traces were observed with a too short Basic Auth password",
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

func (a *APIAnnotationShortPassword) ToAPIFinding() oapicommon.APIFinding {
	return oapicommon.APIFinding{
		Source: utils.ModuleName,

		Type:        a.Name(),
		Name:        "Too short Basic Auth password",
		Description: "Traces were observed with a too short Basic Auth password",

		ProvidedSpecLocation:      &a.SpecLocation,
		ReconstructedSpecLocation: &a.SpecLocation,

		Severity: oapicommon.INFO,

		AdditionalInfo: nil,
	}
}

type AnnotationKnownPassword struct {
	Password string `json:"password"`
}

func NewAnnotationKnownPassword(password string) *AnnotationKnownPassword {
	return &AnnotationKnownPassword{Password: password}
}
func (a *AnnotationKnownPassword) Name() string { return KindKnownPassword }
func (a *AnnotationKnownPassword) NewAPIAnnotation(path, method string) utils.TraceAnalyzerAPIAnnotation {
	return NewAPIAnnotationKnownPassword(path, method)
}
func (a *AnnotationKnownPassword) Severity() string           { return utils.SeverityMedium }
func (a *AnnotationKnownPassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *AnnotationKnownPassword) Deserialize(serialized []byte) error {
	var tmp AnnotationKnownPassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a *AnnotationKnownPassword) Redacted() utils.TraceAnalyzerAnnotation {
	return NewAnnotationKnownPassword("XXX")
}

func (a *AnnotationKnownPassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Weak Basic Auth password (found in dictionary)",
		DetailedDesc: fmt.Sprintf("The Basic Auth password is too weak because it's too common (%s)", a.Password),
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

type APIAnnotationKnownPassword struct {
	SpecLocation string `json:"spec_location"`
}

func NewAPIAnnotationKnownPassword(path, method string) *APIAnnotationKnownPassword {
	pointerTokens := []string{}
	pointer := strings.Join(pointerTokens, "/")
	return &APIAnnotationKnownPassword{
		SpecLocation: pointer,
	}
}
func (a *APIAnnotationKnownPassword) Name() string { return KindKnownPassword }
func (a *APIAnnotationKnownPassword) Aggregate(ann utils.TraceAnalyzerAnnotation) (updated bool) {
	_, valid := ann.(*AnnotationKnownPassword)
	if !valid {
		panic("invalid type")
	}

	return false
}

func (a *APIAnnotationKnownPassword) Severity() string   { return utils.SeverityInfo }
func (a *APIAnnotationKnownPassword) TTL() time.Duration { return 24 * time.Hour }

func (a *APIAnnotationKnownPassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *APIAnnotationKnownPassword) Deserialize(serialized []byte) error {
	var tmp APIAnnotationKnownPassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a APIAnnotationKnownPassword) Redacted() utils.TraceAnalyzerAPIAnnotation {
	newA := a
	return &newA
}

func (a *APIAnnotationKnownPassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Weak Basic Auth password (found in dictionary)",
		DetailedDesc: "Traces were observed with known Basic Auth passwords",
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

func (a *APIAnnotationKnownPassword) ToAPIFinding() oapicommon.APIFinding {
	return oapicommon.APIFinding{
		Source: utils.ModuleName,

		Type:        a.Name(),
		Name:        "Weak Basic Auth password (found in dictionary)",
		Description: "Traces were observed with known Basic Auth passwords",

		ProvidedSpecLocation:      &a.SpecLocation,
		ReconstructedSpecLocation: &a.SpecLocation,

		Severity: oapicommon.INFO,

		AdditionalInfo: nil,
	}
}

type AnnotationSamePassword struct {
	User     string   `json:"user"`
	Password string   `json:"password"`
	APIs     []string `json:"apis"`
}

func NewAnnotationSamePassword(user, password string, apis []string) *AnnotationSamePassword {
	return &AnnotationSamePassword{User: user, Password: password, APIs: apis}
}
func (a *AnnotationSamePassword) Name() string { return KindSamePassword }
func (a *AnnotationSamePassword) NewAPIAnnotation(path, method string) utils.TraceAnalyzerAPIAnnotation {
	return NewAPIAnnotationSamePassword(path, method)
}
func (a *AnnotationSamePassword) Severity() string           { return utils.SeverityMedium }
func (a *AnnotationSamePassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *AnnotationSamePassword) Deserialize(serialized []byte) error {
	var tmp AnnotationSamePassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a *AnnotationSamePassword) Redacted() utils.TraceAnalyzerAnnotation {
	return NewAnnotationSamePassword(a.User, "XXX", a.APIs)
}

func (a *AnnotationSamePassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Same Basic Auth credentials used for another service",
		DetailedDesc: fmt.Sprintf("The exact same Basic Auth credentials (%s:%s) of this event are used for multiple services (%s)", a.User, a.Password, strings.Join(a.APIs, ",")),
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

type APIAnnotationSamePassword struct {
	APIs []string
}

func NewAPIAnnotationSamePassword(path, method string) *APIAnnotationSamePassword {
	return &APIAnnotationSamePassword{}
}
func (a *APIAnnotationSamePassword) Name() string { return KindSamePassword }
func (a *APIAnnotationSamePassword) Aggregate(ann utils.TraceAnalyzerAnnotation) (updated bool) {
	eventAnn, valid := ann.(*AnnotationSamePassword)
	if !valid {
		panic("invalid type")
	}

	for _, newAPI := range eventAnn.APIs {
		for _, api := range a.APIs {
			if newAPI == api {
				break
			}
		}
		a.APIs = append(a.APIs, newAPI)
		updated = true
	}

	return updated
}

func (a *APIAnnotationSamePassword) Severity() string   { return utils.SeverityInfo }
func (a *APIAnnotationSamePassword) TTL() time.Duration { return 24 * time.Hour }

func (a *APIAnnotationSamePassword) Serialize() ([]byte, error) { return json.Marshal(a) }
func (a *APIAnnotationSamePassword) Deserialize(serialized []byte) error {
	var tmp APIAnnotationSamePassword
	err := json.Unmarshal(serialized, &tmp)
	*a = tmp

	return err
}

func (a APIAnnotationSamePassword) Redacted() utils.TraceAnalyzerAPIAnnotation {
	newA := a
	return &newA
}

func (a *APIAnnotationSamePassword) ToFinding() utils.Finding {
	return utils.Finding{
		ShortDesc:    "Same Basic Auth credentials used for another service",
		DetailedDesc: fmt.Sprintf("Other services are using the same credentials (%s)", strings.Join(a.APIs, ",")),
		Severity:     a.Severity(),
		Alert:        utils.SeverityToAlert(a.Severity()),
	}
}

func (a *APIAnnotationSamePassword) ToAPIFinding() oapicommon.APIFinding {
	return oapicommon.APIFinding{
		Source: utils.ModuleName,

		Type:        a.Name(),
		Name:        "Same Basic Auth credentials used for another service",
		Description: fmt.Sprintf("Other services are using the same credentials (%s)", strings.Join(a.APIs, ",")),

		ProvidedSpecLocation:      nil,
		ReconstructedSpecLocation: nil,

		Severity: oapicommon.INFO,

		AdditionalInfo: nil,
	}
}
