/*
 * Flow CLI
 *
 * Copyright 2019-2020 Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"os"
	"regexp"
	"strings"
)

// ReplaceEnv finds env variables and replaces them with env values
func ReplaceEnv(raw string) string {
	envRegex := regexp.MustCompile(`\$\{env\:(.+)\}`)
	envMatches := envRegex.FindAllStringSubmatch(raw, -1)

	for _, match := range envMatches {
		raw = strings.ReplaceAll(
			raw,
			match[0],
			getEnvVariable(match[1]),
		)
	}

	return raw
}

// get environment variable by name
func getEnvVariable(name string) string {
	return os.Getenv(name)
}