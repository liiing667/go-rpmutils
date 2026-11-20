/*
 * Copyright (c) SAS Institute, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpmutils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadMalformedRpmFixtures feeds crafted RPM files through the public
// ReadRpm entry point. Each malformed file must be rejected with an error and
// must never panic or trigger an unbounded allocation.
func TestReadMalformedRpmFixtures(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/malformed/*.rpm")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			f, err := os.Open(fixture)
			require.NoError(t, err)
			defer f.Close()

			defer func() {
				require.Nil(t, recover(), "parsing %s panicked", fixture)
			}()
			rpm, err := ReadRpm(f)
			require.Error(t, err, "malformed RPM %s must be rejected", fixture)
			require.Nil(t, rpm)
			t.Logf("%s rejected with: %s", fixture, err)
		})
	}
}
