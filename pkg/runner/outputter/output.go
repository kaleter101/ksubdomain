package outputter

import (
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner" // Added for WildcardDetectionResult
)

type Output interface {
	WriteDomainResult(domain result.Result) error
	Close(wildcardInfo map[string]*runner.WildcardDetectionResult) error
}
