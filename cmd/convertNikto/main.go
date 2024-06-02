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
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
}

type HTTPHeaderField struct {
	Key        string   `yaml:"key"`
	Value      []string `yaml:"value"`
	Confidence int      `yaml:"confidence"`
}

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

type PageContentSignature struct {
	Key        string   `yaml:"key"`
	Attribute  string   `yaml:"attribute,omitempty"`
	Signature  []string `yaml:"value,omitempty"`
	Text       []string `yaml:"text,omitempty"`
	MD5Hash    []string `yaml:"md5hash,omitempty"`
	Confidence float32  `yaml:"confidence"`
}

// Function to create a CROWler detection rule from a favicon entry
func createFaviconRule(id, md5hash, description string) DetectionRule {
	ruleName := fmt.Sprintf("detect_%s", strings.ToLower(strings.ReplaceAll(description, " ", "_")))

	rule := DetectionRule{
		RuleName:   ruleName,
		ObjectName: description,
		PageContentPatterns: []PageContentSignature{
			{
				MD5Hash:    []string{md5hash},
				Confidence: 10,
			},
		},
	}

	return rule
}

func main() {
	inpPath := flag.String("source", "", "Path to the db_favicon file")
	outPath := flag.String("output", "./", "Path to the output directory")
	flag.Parse()

	// Open the db_favicon file
	file, err := os.Open(*inpPath)
	if err != nil {
		log.Fatalf("Error reading db_favicon file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Initialize the ruleset
	ruleset := Ruleset{
		RulesetName:   "detect_favicon_hashes",
		FormatVersion: "1.0.4",
		Author:        "Your Name",
		CreatedAt:     time.Now().Format(time.RFC3339),
		Description:   "Ruleset to detect technologies using favicon MD5 hashes.",
		RuleGroups: []RuleGroup{
			{
				GroupName:      "detect_favicon_technologies",
				IsEnabled:      true,
				DetectionRules: []DetectionRule{},
			},
		},
	}

	// Read the header line
	if scanner.Scan() {
		// skip header line
	}

	// Process each line of the file
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || len(line) == 0 {
			continue // Skip comments and empty lines
		}

		// Create a CSV reader for the line
		reader := csv.NewReader(strings.NewReader(line))
		reader.Comma = ','

		fields, err := reader.Read()
		if err != nil {
			log.Printf("Error reading line: %v", err)
			continue
		}

		if len(fields) != 3 {
			log.Printf("Skipping invalid line: %s", line)
			continue // Skip lines that don't have the correct number of fields
		}

		// Trim quotes and create a rule
		id := strings.Trim(fields[0], "\"")
		md5hash := strings.Trim(fields[1], "\"")
		description := strings.Trim(fields[2], "\"")

		rule := createFaviconRule(id, md5hash, description)
		ruleset.RuleGroups[0].DetectionRules = append(ruleset.RuleGroups[0].DetectionRules, rule)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error scanning file: %v", err)
	}

	// Write the ruleset to a YAML file
	filename := fmt.Sprintf((*outPath) + "/detect-favicon-hashes-ruleset.yaml")
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
