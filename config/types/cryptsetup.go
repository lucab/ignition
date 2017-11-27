// Copyright 2017 CoreOS, Inc.
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

package types

import (
	"errors"
	"fmt"

	"github.com/coreos/ignition/config/validate/report"
)

const (
	// csDevicesMax is the maximum number of Cryptsetup devices that can be created at once
	csDevicesMax = 1000
	// csKeyslotsMax is the maximux number of keyslots allowed per Cryptsetup device
	csKeyslotsMax = 1 // TODO(lucab): this could be expanded to 8
)

var (
	// ErrNoKeyslots is reported when 0 keyslots are specified
	ErrNoKeyslots = errors.New("no keyslots specified")
	// ErrNoKeyslotConfig is reported when a keyslot has no configured source
	ErrNoKeyslotConfig = errors.New("keyslot is missing source configuration")
	// ErrTooManyKeyslotConfigs is reported when a keyslot has too many configured sources
	ErrTooManyKeyslotConfigs = errors.New("keyslot has multiple source configurations")
	// ErrNoDevmapperName is reported when no device-mapper name is specified
	ErrNoDevmapperName = errors.New("missing device-mapper name")
	// ErrNoDevicePath is reported when no device path is specified
	ErrNoDevicePath = errors.New("missing device path")
	// ErrTooManyDevices is reported when too many devices are specified
	ErrTooManyDevices = fmt.Errorf("too many devices specified, at most %d allowed", csDevicesMax)
	// ErrTooManyKeyslots is reported when too many keyslots are specified
	ErrTooManyKeyslots = fmt.Errorf("too many keyslots specified, at most %d allowed", csKeyslotsMax)
)

// Validate ensures a Cryptsetup entry is sane
//
// It fulfills validate.validator interface.
func (cs Cryptsetup) Validate() report.Report {
	r := report.Report{}

	if cs.Name == "" {
		r.Add(report.Entry{
			Message: ErrNoDevmapperName.Error(),
			Kind:    report.EntryError,
		})
	}
	if cs.Device == "" {
		r.Add(report.Entry{
			Message: ErrNoDevicePath.Error(),
			Kind:    report.EntryError,
		})
	}
	if len(cs.KeySlots) == 0 {
		r.Add(report.Entry{
			Message: ErrNoKeyslots.Error(),
			Kind:    report.EntryError,
		})
	}
	if len(cs.KeySlots) > csKeyslotsMax {
		r.Add(report.Entry{
			Message: ErrTooManyKeyslots.Error(),
			Kind:    report.EntryError,
		})
	}

	for _, ks := range cs.KeySlots {
		ksConfigured := 0
		if ks.AzureVault != nil {
			ksConfigured++
		}
		if ks.Content != nil {
			ksConfigured++
		}
		if ks.HcVault != nil {
			ksConfigured++
		}
		if ks.Swap != nil {
			ksConfigured++
		}
		if ksConfigured == 0 {
			r.Add(report.Entry{
				Message: ErrNoKeyslotConfig.Error(),
				Kind:    report.EntryError,
			})
		} else if ksConfigured > 1 {
			r.Add(report.Entry{
				Message: ErrTooManyKeyslotConfigs.Error(),
				Kind:    report.EntryError,
			})
		}
	}

	return r
}
