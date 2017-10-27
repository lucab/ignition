// Copyright 2016 CoreOS, Inc.
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
	// luksDevicesMax is the maximum number of LUKS devices that can be created at once
	luksDevicesMax = 1000
	// luksKeySlotsMax is the maximux number of keyslots allowed per LUKS device
	luksKeySlotsMax = 8
)

var (
	// ErrNoKeySlots is reported when 0 keyslots are specified
	ErrNoKeySlots = errors.New("no keyslots specified")
	// ErrNoDevmapperName is reported when no device-mapper name is specified
	ErrNoDevmapperName = errors.New("missing device-mapper name")
	// ErrNoDevicePath is reported when no device path is specified
	ErrNoDevicePath = errors.New("missing device path")
	// ErrTooManyDevices is reported when too many devices are specified
	ErrTooManyDevices = fmt.Errorf("too many devices specified, at most %d allowed", luksDevicesMax)
	// ErrTooManyKeySlots is reported when too many keyslots are specified
	ErrTooManyKeySlots = fmt.Errorf("too many keyslots specified, at most %d allowed", luksKeySlotsMax)
)

// Validate ensures this LuksDevice is sane
//
// It fulfills validate.validator interface.
func (ld LuksDevice) Validate() report.Report {
	r := report.Report{}

	if ld.Name == "" {
		r.Add(report.Entry{
			Message: ErrNoDevmapperName.Error(),
			Kind:    report.EntryError,
		})
	}
	if ld.Device == "" {
		r.Add(report.Entry{
			Message: ErrNoDevicePath.Error(),
			Kind:    report.EntryError,
		})
	}
	if len(ld.KeySlots) == 0 {
		r.Add(report.Entry{
			Message: ErrNoKeySlots.Error(),
			Kind:    report.EntryError,
		})
	}
	if len(ld.KeySlots) > luksKeySlotsMax {
		r.Add(report.Entry{
			Message: ErrTooManyKeySlots.Error(),
			Kind:    report.EntryError,
		})
	}

	return r
}
