// Copyright 2023 Paolo Fabio Zaino
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

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ModSecurityRule struct {
	ID        string
	Phase     string
	Action    string
	Status    string
	Message   string
	UserAgent string
	Headers   map[string]string
}

type Ruleset struct {
	RulesetName   string      `yaml:"ruleset_name"`
	FormatVersion string      `yaml:"format_version"`
	Author        string      `yaml:"author"`
	CreatedAt     string      `yaml:"created_at"`
	Description   string      `yaml:"description"`
	RuleGroups    []RuleGroup `yaml:"rule_groups"`
}

type RuleGroup struct {
	GroupName      string          `yaml:"group_name"`
	IsEnabled      bool            `yaml:"is_enabled"`
	DetectionRules []DetectionRule `yaml:"detection_rules"`
}

type DetectionRule struct {
	RuleName         string            `yaml:"rule_name"`
	ObjectName       string            `yaml:"object_name"`
	HTTPHeaderFields []HTTPHeaderField `yaml:"http_header_fields,omitempty"`
}

type HTTPHeaderField struct {
	Key        string   `yaml:"key"`
	Value      []string `yaml:"value"`
	Confidence int      `yaml:"confidence"`
}

// Function to parse ModSecurity rule line
func parseModSecurityRule(line string) *ModSecurityRule {
	rule := &ModSecurityRule{
		Headers: make(map[string]string),
	}

	// Extract the User-Agent from the rule
	userAgentRe := regexp.MustCompile(`REQUEST_HEADERS:User-Agent "([^"]+)"`)
	matches := userAgentRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.UserAgent = matches[1]
	}

	// Extract the rule ID
	idRe := regexp.MustCompile(`id:(\d+)`)
	matches = idRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.ID = matches[1]
	}

	// Extract the phase
	phaseRe := regexp.MustCompile(`phase:(\d+)`)
	matches = phaseRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.Phase = matches[1]
	}

	// Extract the action
	actionRe := regexp.MustCompile(`\b(deny|allow|log)\b`)
	matches = actionRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.Action = matches[1]
	}

	// Extract the status
	statusRe := regexp.MustCompile(`status:(\d+)`)
	matches = statusRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.Status = matches[1]
	}

	// Extract the message
	msgRe := regexp.MustCompile(`msg:'([^']+)'`)
	matches = msgRe.FindStringSubmatch(line)
	if len(matches) > 1 {
		rule.Message = matches[1]
	}

	return rule
}

// Function to create a CROWler detection rule from a ModSecurity rule
func createDetectionRuleFromModSecurity(modsecRule *ModSecurityRule) DetectionRule {
	ruleName := fmt.Sprintf("detect_modsec_rule_%s", modsecRule.ID)
	rule := DetectionRule{
		RuleName:   ruleName,
		ObjectName: fmt.Sprintf("ModSecurity Rule %s", modsecRule.ID),
		HTTPHeaderFields: []HTTPHeaderField{
			{
				Key:        "User-Agent",
				Value:      []string{modsecRule.UserAgent},
				Confidence: 10,
			},
		},
	}

	return rule
}

func main() {
	inpPath := flag.String("source", "", "Path to the ModSecurity rules file")
	outPath := flag.String("output", "./", "Path to the output directory")
	flag.Parse()

	// Open the ModSecurity rules file
	file, err := os.Open(*inpPath)
	if err != nil {
		log.Fatalf("Error reading ModSecurity rules file: %v", err)
	}
	defer file.Close()

	// Initialize the ruleset
	ruleset := Ruleset{
		RulesetName:   "detect_modsecurity_rules",
		FormatVersion: "1.0.4",
		Author:        "Your Name",
		CreatedAt:     time.Now().Format(time.RFC3339),
		Description:   "Ruleset to detect ModSecurity rules.",
		RuleGroups: []RuleGroup{
			{
				GroupName:      "detect_modsecurity_rules",
				IsEnabled:      true,
				DetectionRules: []DetectionRule{},
			},
		},
	}

	// Scan the ModSecurity rules file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue // Skip comments and empty lines
		}

		// Parse the ModSecurity rule
		modsecRule := parseModSecurityRule(line)
		if modsecRule != nil && modsecRule.UserAgent != "" {
			// Create a CROWler detection rule
			detectionRule := createDetectionRuleFromModSecurity(modsecRule)
			ruleset.RuleGroups[0].DetectionRules = append(ruleset.RuleGroups[0].DetectionRules, detectionRule)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}

	// Write the ruleset to a YAML file
	filename := fmt.Sprintf((*outPath) + "/detect-modsecurity-ruleset.yaml")
	outFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating file %s: %v", filename, err)
	}
	defer outFile.Close()

	encoder := yaml.NewEncoder(outFile)
	encoder.SetIndent(2)
	if err := encoder.Encode(&ruleset); err != nil {
		log.Fatalf("Error writing YAML to file %s: %v", filename, err)
	}

	fmt.Println("Ruleset file generated successfully.")
}
