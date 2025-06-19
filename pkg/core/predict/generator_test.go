package predict

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDomainGenerator_Default(t *testing.T) {
	outputChan := make(chan string, 10)
	opts := NewDomainGeneratorOptions{Output: outputChan}
	gen, err := NewDomainGenerator(opts)
	defer close(outputChan)


	assert.NoError(t, err)
	assert.NotNil(t, gen)
	assert.NotEmpty(t, gen.categories, "Default categories should be loaded")
	assert.NotEmpty(t, gen.patterns, "Default patterns should be loaded")
	// Check a known default category
	_, okEnv := gen.categories["environment"]
	_, okPrefix := gen.categories["prefix"]
	assert.True(t, okEnv, "Default category [environment] not found")
	assert.True(t, okPrefix, "Default category [prefix] not found")
}

func TestNewDomainGenerator_CustomFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create dummy dict file
	dictContent := `
[custom_env]
testenv
[custom_prefix]
myprefix
`
	dictFilePath := filepath.Join(tempDir, "custom.dict")
	err := os.WriteFile(dictFilePath, []byte(dictContent), 0644)
	assert.NoError(t, err)

	// Create dummy pattern file
	patternContent := `
{custom_env}.{subdomain}.{domain}
{custom_prefix}-{subdomain}.{domain}
`
	patternFilePath := filepath.Join(tempDir, "custom.cfg")
	err = os.WriteFile(patternFilePath, []byte(patternContent), 0644)
	assert.NoError(t, err)

	outputChan := make(chan string, 10)
	opts := NewDomainGeneratorOptions{
		Output:          outputChan,
		DictFilePath:    dictFilePath,
		PatternFilePath: patternFilePath,
	}
	gen, err := NewDomainGenerator(opts)
	defer close(outputChan)


	assert.NoError(t, err)
	assert.NotNil(t, gen)

	assert.Contains(t, gen.categories, "custom_env", "Custom category [custom_env] not loaded")
	assert.Equal(t, []string{"testenv"}, gen.categories["custom_env"])
	assert.Contains(t, gen.categories, "custom_prefix", "Custom category [custom_prefix] not loaded")
	assert.Equal(t, []string{"myprefix"}, gen.categories["custom_prefix"])

	// Default categories should not be loaded if custom dict is provided
	_, okEnv := gen.categories["environment"]
	assert.False(t, okEnv, "Default category [environment] should not be present when custom dict is used")


	expectedPatterns := []string{
		"{custom_env}.{subdomain}.{domain}",
		"{custom_prefix}-{subdomain}.{domain}",
	}
	assert.ElementsMatch(t, expectedPatterns, gen.patterns, "Custom patterns not loaded correctly")
}

func TestNewDomainGenerator_CustomFilesNotExist(t *testing.T) {
	outputChan := make(chan string, 10)
	defer close(outputChan)

	// Test non-existent dict file
	optsDict := NewDomainGeneratorOptions{
		Output:          outputChan,
		DictFilePath:    "nonexistent.dict",
	}
	_, err := NewDomainGenerator(optsDict)
	assert.Error(t, err, "Should error if custom dict file does not exist")
	assert.True(t, strings.Contains(err.Error(), "nonexistent.dict"), "Error message should contain filename")

	// Test non-existent pattern file
	// Need a valid dict file first for this to proceed to pattern loading
	tempDir := t.TempDir()
	dictContent := "[custom_env]\ntestenv" // Minimal valid content
	dictFilePath := filepath.Join(tempDir, "valid.dict")
	err = os.WriteFile(dictFilePath, []byte(dictContent), 0644)
	assert.NoError(t, err)

	optsPattern := NewDomainGeneratorOptions{
		Output:          outputChan,
		DictFilePath:    dictFilePath, // Valid dict
		PatternFilePath: "nonexistent.cfg",
	}
	_, err = NewDomainGenerator(optsPattern)
	assert.Error(t, err, "Should error if custom pattern file does not exist")
	assert.True(t, strings.Contains(err.Error(), "nonexistent.cfg"), "Error message should contain filename")
}


func TestDomainGenerator_GenerateDomains_Simple(t *testing.T) {
	dictContent := `
[env]
dev
test
[app]
web
api
`
	patternContent := `
{env}-{app}.{domain}
{app}.{env}.{domain}
{env}.{subdomain}.{domain}
`
	tempDir := t.TempDir()
	dictFilePath := filepath.Join(tempDir, "test.dict")
	os.WriteFile(dictFilePath, []byte(dictContent), 0644)
	patternFilePath := filepath.Join(tempDir, "test.cfg")
	os.WriteFile(patternFilePath, []byte(patternContent), 0644)

	outputChan := make(chan string, 20) // Buffer large enough
	opts := NewDomainGeneratorOptions{
		Output:          outputChan,
		DictFilePath:    dictFilePath,
		PatternFilePath: patternFilePath,
	}
	gen, err := NewDomainGenerator(opts)
	assert.NoError(t, err)

	gen.SetBaseDomain("sub.example.com") // subdomain=sub, domain=example.com
	count := gen.GenerateDomains()
	close(outputChan)

	expected := []string{
		"dev-web.example.com", "dev-api.example.com",
		"test-web.example.com", "test-api.example.com",
		"web.dev.example.com", "web.test.example.com",
		"api.dev.example.com", "api.test.example.com",
		"dev.sub.example.com", "test.sub.example.com",
	}
	assert.Equal(t, len(expected), count, "Generated domain count mismatch")

	var generatedDomains []string
	for d := range outputChan {
		generatedDomains = append(generatedDomains, d)
	}
	assert.ElementsMatch(t, expected, generatedDomains, "Generated domains do not match expected")

	// Test with root domain (empty subdomain)
	outputChan2 := make(chan string, 20)
	opts2 := NewDomainGeneratorOptions{
		Output:          outputChan2,
		DictFilePath:    dictFilePath,
		PatternFilePath: patternFilePath,
	}
	gen2, err := NewDomainGenerator(opts2)
	assert.NoError(t, err)

	gen2.SetBaseDomain("example.com") // subdomain="", domain=example.com
	count2 := gen2.GenerateDomains()
	close(outputChan2)

	expected2 := []string{
		"dev-web.example.com", "dev-api.example.com",
		"test-web.example.com", "test-api.example.com",
		"web.dev.example.com", "web.test.example.com",
		"api.dev.example.com", "api.test.example.com",
		"dev..example.com", "test..example.com",
	}
	assert.Equal(t, len(expected2), count2, "Generated domain count mismatch for root domain")
	var generatedDomains2 []string
	for d := range outputChan2 {
		generatedDomains2 = append(generatedDomains2, d)
	}
	assert.ElementsMatch(t, expected2, generatedDomains2, "Generated domains for root domain do not match expected")
}

func TestPredictDomains_Wrapper(t *testing.T) {
	dictContent := `[testcat]
item1
`
	patternContent := `{testcat}.{domain}`
	tempDir := t.TempDir()
	dictFilePath := filepath.Join(tempDir, "wtest.dict")
	os.WriteFile(dictFilePath, []byte(dictContent), 0644)
	patternFilePath := filepath.Join(tempDir, "wtest.cfg")
	os.WriteFile(patternFilePath, []byte(patternContent), 0644)

	outputChan := make(chan string, 5)
	count, err := PredictDomains("example.com", outputChan, dictFilePath, patternFilePath)
	close(outputChan)

	assert.NoError(t, err)
	assert.Equal(t, 1, count)

	var generated []string
	for d := range outputChan {
		generated = append(generated, d)
	}
	assert.Equal(t, []string{"item1.example.com"}, generated)

	// Test with default files (empty paths)
	outputChanDef := make(chan string, 200) // Default dict is large
	// This test is primarily to ensure it runs without error with defaults.
	// Exact count can be brittle if default dicts change often.
	countDef, errDef := PredictDomains("example.com", outputChanDef, "", "")
	close(outputChanDef)
	assert.NoError(t, errDef)
	// Check if some domains were generated. The exact number depends on the default dict.
	// For a simple domain like "example.com", many predictions should occur.
	assert.True(t, countDef > 0, "Default prediction should generate some domains for example.com")

	generatedDef := 0
	for range outputChanDef {
		generatedDef++
	}
	assert.Equal(t, countDef, generatedDef, "Count from PredictDomains should match items received")
}
