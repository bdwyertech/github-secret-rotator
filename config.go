// Encoding: UTF-8
//
// GitHub Secret Rotator - Configuration Renderer
//
// Copyright © 2021 Brian Dwyer - Intelligent Digital Services. All rights reserved.
//

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/go-multierror"
)

type Config struct {
	User    string    `yaml:"user"`
	Secrets []*Secret `yaml:"secrets"`
}

type Secret struct {
	Name    string   `yaml:"name"`
	Value   string   `yaml:"value"`
	Aliases []string `yaml:"aliases"`
}

const UNABLE_TO_RENDER_PREFIX = "#|-+-UNABLE-TO-RENDER-+-|#"

func RenderConfig(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	return cfgRender(scanner)
}

func cfgRender(scanner *bufio.Scanner) (rendered string, errors error) {
	re := regexp.MustCompile(`\$\{.*:::.*\}`)
	var replacer func(string) string
	replacer = func(s string) string {
		// Cascade nested rendering failure
		if strings.Contains(s, UNABLE_TO_RENDER_PREFIX) {
			return s
		}
		s = strings.TrimPrefix(s, "${")
		s = strings.TrimSuffix(s, "}")
		for {
			//
			// Recursively loop through nested variables
			//
			submatches := re.FindAllString(s, -1)
			if submatches == nil {
				break
			}
			s = re.ReplaceAllStringFunc(s, replacer)
		}
		// Cascade nested rendering failure (post-recursion)
		if strings.Contains(s, UNABLE_TO_RENDER_PREFIX) {
			return s
		}

		if pfx := "env:::"; strings.HasPrefix(s, pfx) {
			//
			// Environment Variable
			//
			if val, ok := os.LookupEnv(strings.TrimPrefix(s, pfx)); ok {
				return val
			} else {
				log.Warnln("Unable to locate environment variable:", s)
			}
		} else {
			log.Debugln("Unknown prefix, leaving as-is:", s)
		}
		//
		// Unknown or Unable to Render
		//
		return fmt.Sprintf("%s{%s}", UNABLE_TO_RENDER_PREFIX, s)
	}

	// Recursively loop through, line by line
	for scanner.Scan() {
		s := re.ReplaceAllStringFunc(scanner.Text(), replacer)
		s = strings.Replace(s, UNABLE_TO_RENDER_PREFIX, "$", -1)
		rendered = rendered + fmt.Sprintln(s)
	}

	if err := scanner.Err(); err != nil {
		errors = multierror.Append(err, errors)
	}

	return
}
