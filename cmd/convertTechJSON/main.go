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

// Define the structure of technologies.json
type Technology struct {
	Cats    []string          `json:"cats"`
	Cookies map[string]string `json:"cookies"`
	Headers map[string]string `json:"headers"`
	Meta    interface{}       `json:"meta"`
	Html    []string          `json:"html"`
	Scripts []string          `json:"scripts"`
	URL     []string          `json:"url"`
	Website string            `json:"website"`
	Implies []string          `json:"implies"`
}

type Category struct {
	Name string `json:"name"`
}

type Technologies struct {
	Technologies map[string]Technology `json:"technologies"`
	Categories   map[string]Category   `json:"categories"`
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
	SSLSignatures       []SSLSignature         `yaml:"ssl_patterns,omitempty"`
	URLPatterns         []URLMicroSignature    `yaml:"url_micro_signatures,omitempty"`
}

// Use HTTPHeaderField for headers and cookies
type HTTPHeaderField struct {
	Key        string   `yaml:"key"`
	Value      []string `yaml:"value"`
	Confidence int      `yaml:"confidence"`
}

// SSLSignature represents a pattern for matching SSL Certificate fields
type SSLSignature struct {
	Key        string   `yaml:"key"`
	Value      []string `yaml:"value,omitempty"`
	Confidence float32  `yaml:"confidence"`
}

type MetaTag struct {
	Name       string   `yaml:"name"`
	Content    []string `yaml:"content"`
	Confidence int      `yaml:"confidence"`
}

// PageContent micro-signatures are patterns that can be found in the page content
// use this for scripts, html, etc.
type PageContentSignature struct {
	Key        string   `yaml:"key"`
	Attribute  string   `yaml:"attribute,omitempty"`
	Signature  []string `yaml:"value,omitempty"`
	Text       []string `yaml:"text,omitempty"`
	Confidence float32  `yaml:"confidence"`
}

// URLMicroSignature represents a pattern for matching URL micro-signatures
type URLMicroSignature struct {
	Signature  string  `yaml:"value"`
	Confidence float32 `yaml:"confidence"`
}

func createRule(name string, details Technology) DetectionRule {
	rule := DetectionRule{
		RuleName:   fmt.Sprintf("detect_%s", strings.ToLower(strings.ReplaceAll(name, " ", "_"))),
		ObjectName: name,
		Implies:    details.Implies,
	}

	if details.Headers != nil {
		for k, v := range details.Headers {
			rule.HTTPHeaderFields = append(rule.HTTPHeaderFields, HTTPHeaderField{
				Key:        k,
				Value:      []string{v},
				Confidence: 10,
			})
		}
	}

	if details.Cookies != nil {
		for k, v := range details.Cookies {
			rule.HTTPHeaderFields = append(rule.HTTPHeaderFields, HTTPHeaderField{
				Key:        k,
				Value:      []string{v},
				Confidence: 10,
			})
		}
	}

	if details.Meta != nil {
		switch meta := details.Meta.(type) {
		case map[string]interface{}:
			for k, v := range meta {
				switch val := v.(type) {
				case string:
					rule.MetaTags = append(rule.MetaTags, MetaTag{
						Name:       k,
						Content:    []string{val},
						Confidence: 10,
					})
				case []interface{}:
					var contents []string
					for _, item := range val {
						if str, ok := item.(string); ok {
							contents = append(contents, str)
						}
					}
					rule.MetaTags = append(rule.MetaTags, MetaTag{
						Name:       k,
						Content:    contents,
						Confidence: 10,
					})
				default:
					log.Printf("Unexpected value type in Meta field: %T", val)
				}
			}
		case map[string]string:
			for k, v := range meta {
				rule.MetaTags = append(rule.MetaTags, MetaTag{
					Name:       k,
					Content:    []string{v},
					Confidence: 10,
				})
			}
		case []interface{}:
			// Handle other possible cases if required
		default:
			log.Printf("Unexpected type for Meta field: %T", meta)
		}
	}

	if details.Html != nil {
		for _, v := range details.Html {
			rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
				Key:        "html",
				Signature:  []string{v},
				Confidence: 10,
			})
		}
	}

	if details.Scripts != nil {
		for _, v := range details.Scripts {
			rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
				Key:        "script",
				Signature:  []string{v},
				Confidence: 10,
			})
		}
	}

	if details.URL != nil {
		for _, v := range details.URL {
			rule.URLPatterns = append(rule.URLPatterns, URLMicroSignature{
				Signature:  v,
				Confidence: 10,
			})
		}
	}

	if details.Website != "" {
		rule.URLPatterns = append(rule.URLPatterns, URLMicroSignature{
			Signature:  details.Website,
			Confidence: 10,
		})

		// Add a page content pattern for the website URL
		rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
			Key:        "a",
			Attribute:  "href",
			Signature:  []string{details.Website},
			Confidence: 10,
		})

		// Add a page content pattern for the website URL using the link tag
		rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
			Key:        "link",
			Attribute:  "href",
			Signature:  []string{details.Website},
			Confidence: 10,
		})

		// Add a page content pattern for the website URL using the script tag
		rule.PageContentPatterns = append(rule.PageContentPatterns, PageContentSignature{
			Key:        "script",
			Attribute:  "src",
			Signature:  []string{details.Website},
			Confidence: 10,
		})
	}

	return rule
}

func main() {
	inpPath := flag.String("i", "", "Path to the technologies.json file")
	outPath := flag.String("o", "./", "Path to the output directory")
	flag.Parse()

	// Read technologies.json
	data, err := os.ReadFile(*inpPath)
	if err != nil {
		log.Fatalf("Error reading technologies.json: %v", err)
	}

	var technologies Technologies
	if err := json.Unmarshal(data, &technologies); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}

	// Initialize category-based rulesets
	rulesets := make(map[string]Ruleset)

	// Process each technology and categorize
	for name, details := range technologies.Technologies {
		rule := createRule(name, details)
		for _, cat := range details.Cats {
			category, exists := technologies.Categories[cat]
			if !exists {
				continue
			}

			if _, ok := rulesets[category.Name]; !ok {
				rulesets[category.Name] = Ruleset{
					RulesetName:   fmt.Sprintf("detect_%s_ruleset", strings.ReplaceAll(category.Name, " ", "_")),
					FormatVersion: "1.0.4",
					Author:        "Your Name",
					CreatedAt:     time.Now().Format(time.RFC3339),
					Description:   fmt.Sprintf("Ruleset to detect %s technologies.", strings.ReplaceAll(category.Name, "_", " ")),
					RuleGroups: []RuleGroup{
						{
							GroupName:      "detect_web_technologies_" + category.Name,
							IsEnabled:      true,
							DetectionRules: []DetectionRule{},
						},
					},
				}
			}

			ruleset := rulesets[category.Name]
			ruleset.RuleGroups[0].DetectionRules = append(ruleset.RuleGroups[0].DetectionRules, rule)
			rulesets[category.Name] = ruleset
		}
	}

	// Write to multiple YAML files
	for category, ruleset := range rulesets {
		category = strings.ReplaceAll(category, " ", "-")
		category = strings.ReplaceAll(category, "/", "-")
		category = strings.ReplaceAll(category, "\\", "-")
		fmt.Printf("Writing ruleset for %s...\n", category)
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
