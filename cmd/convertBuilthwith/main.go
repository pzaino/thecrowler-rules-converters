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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Define the structure for the BuiltWith technologies JSON
type BuiltWithTechnology struct {
	Categories []int             `json:"categories"`
	Patterns   BuiltWithPatterns `json:"patterns"`
	Implies    []string          `json:"implies,omitempty"`
}

type BuiltWithPatterns struct {
	URL     string            `json:"url,omitempty"`
	HTML    string            `json:"html,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type BuiltWithTechnologies struct {
	Technologies map[string]BuiltWithTechnology `json:"technologies"`
}

// Define the structure for the CROWler ruleset
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
	RuleName            string                 `yaml:"rule_name"`
	ObjectName          string                 `yaml:"object_name"`
	Implies             []string               `yaml:"implies,omitempty"`
	HTTPHeaderFields    []HTTPHeaderField      `yaml:"http_header_fields,omitempty"`
	MetaTags            []MetaTag              `yaml:"meta_tags,omitempty"`
	PageContentPatterns []PageContentSignature `yaml:"page_content_patterns,omitempty"`
	URLPatterns         []URLMicroSignature    `yaml:"url_micro_signatures,omitempty"`
}

type HTTPHeaderField struct {
	Key        string   `yaml:"key"`
	Value      []string `yaml:"value"`
	Confidence int      `yaml:"confidence"`
}

type MetaTag struct {
	Name       string   `yaml:"name"`
	Content    []string `yaml:"content"`
	Confidence int      `yaml:"confidence"`
}

type PageContentSignature struct {
	Key        string   `yaml:"key"`
	Attribute  string   `yaml:"attribute,omitempty"`
	Signature  []string `yaml:"value,omitempty"`
	Text       []string `yaml:"text,omitempty"`
	Confidence float32  `yaml:"confidence"`
}

type URLMicroSignature struct {
	Signature  string  `yaml:"value"`
	Confidence float32 `yaml:"confidence"`
}

// Define category mappings
var categoryMappings = map[int]string{
	1: "cms",
	2: "web_frameworks",
	// Add other mappings as needed
}

func createRule(name string, details BuiltWithTechnology) DetectionRule {
	rule := DetectionRule{
		RuleName:   fmt.Sprintf("detect_%s", strings.ToLower(strings.ReplaceAll(name, " ", "_"))),
		ObjectName: name,
		Implies:    details.Implies,
	}

	if details.Patterns.Headers != nil {
		for k, v := range details.Patterns.Headers {
			rule.HTTPHeaderFields = append(rule.HTTPHeaderFields, HTTPHeaderField{
				Key:        k,
				Value:      []string{v},
				Confidence: 10,
			})
		}
	}

	if details.Patterns.HTML != "" {
		rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
			Key:        "body",
			Text:       []string{details.Patterns.HTML},
			Confidence: 10,
		})
	}

	if details.Patterns.URL != "" {
		rule.URLPatterns = append(rule.URLPatterns, URLMicroSignature{
			Signature:  details.Patterns.URL,
			Confidence: 10,
		})
	}

	return rule
}

func main() {
	inpPath := flag.String("source", "", "Path to the BuiltWith technologies.json file")
	outPath := flag.String("output", "./", "Path to the output directory")
	flag.Parse()

	// Read technologies.json
	data, err := os.ReadFile(*inpPath)
	if err != nil {
		log.Fatalf("Error reading technologies.json: %v", err)
	}

	var technologies BuiltWithTechnologies
	if err := json.Unmarshal(data, &technologies); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}

	// Initialize category-based rulesets
	rulesets := make(map[string]Ruleset)

	// Process each technology and categorize
	for name, details := range technologies.Technologies {
		rule := createRule(name, details)
		for _, cat := range details.Categories {
			category, exists := categoryMappings[cat]
			if !exists {
				continue
			}

			if _, ok := rulesets[category]; !ok {
				rulesets[category] = Ruleset{
					RulesetName:   fmt.Sprintf("detect_%s_ruleset", category),
					FormatVersion: "1.0.4",
					Author:        "Your Name",
					CreatedAt:     time.Now().Format(time.RFC3339),
					Description:   fmt.Sprintf("Ruleset to detect %s technologies.", strings.ReplaceAll(category, "_", " ")),
					RuleGroups: []RuleGroup{
						{
							GroupName:      "detect_web_technologies",
							IsEnabled:      true,
							DetectionRules: []DetectionRule{},
						},
					},
				}
			}

			ruleset := rulesets[category]
			ruleset.RuleGroups[0].DetectionRules = append(ruleset.RuleGroups[0].DetectionRules, rule)
			rulesets[category] = ruleset
		}
	}

	// Write to multiple YAML files
	for category, ruleset := range rulesets {
		filename := fmt.Sprintf((*outPath)+"/detect-%s-ruleset.yaml", category)
		file, err := os.Create(filename)
		if err != nil {
			log.Fatalf("Error creating file %s: %v", filename, err)
		}
		defer file.Close()

		encoder := yaml.NewEncoder(file)
		encoder.SetIndent(2)
		if err := encoder.Encode(&ruleset); err != nil {
			log.Fatalf("Error writing YAML to file %s: %v", filename, err)
		}
	}

	fmt.Println("Ruleset files generated successfully.")
}
