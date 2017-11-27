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

// The storage stage is responsible for partitioning disks, creating RAID
// arrays, formatting partitions, writing files, writing systemd units, and
// writing network units.

package disks

import (
	"fmt"

	"github.com/coreos/ignition/config/types"
	"github.com/martinjungblut/cryptsetup"
	"golang.org/x/net/context"
)

// createCryptsetup creates cryptsetup partitions described in config.Storage.Cryptsetup
//
// This assumes that cryptsetup config has already been validated at parsing time.
func (s stage) createCryptsetup(config types.Config) error {
	csCfg := config.Storage.Cryptsetup
	if len(csCfg) == 0 {
		return nil
	}
	s.Logger.PushPrefix("createCryptsetup")
	defer s.Logger.PopPrefix()

	devs := []string{}
	for _, entry := range config.Storage.Cryptsetup {
		devs = append(devs, entry.Device)
	}
	if err := s.waitOnDevicesAndCreateAliases(devs, "crypsetup"); err != nil {
		return err
	}

	for _, csEntry := range csCfg {
		if err := s.createCryptsetupEntry(csEntry); err != nil {
			return err
		}
	}

	return nil
}

// createCryptsetupEntry creates a single cryptsetup partition entry.
func (s stage) createCryptsetupEntry(csEntry types.Cryptsetup) error {
	// Fetch keyslots passphrases
	keys := []string{}
	for i, slot := range csEntry.KeySlots {
		key, err := s.fetchKeyslotPass(context.Background(), slot)
		if err != nil {
			return fmt.Errorf("fetching keyslot passphrase %d for %q: %v", i, csEntry.Name, err)
		}
		keys = append(keys, key)
		// TODO(lucab): remove
		break
	}

	// Initialize device
	// TODO(lucab): make this configurable
	cryptohashKind := "sha256"
	cypherKind := "aes"
	cypherMode := "xts-plain64"
	params := cryptsetup.LUKSParams{
		Hash:           cryptohashKind,
		Data_alignment: 0,
		Data_device:    "",
	}
	err, device := cryptsetup.Init(csEntry.Device)
	if err != nil {
		return fmt.Errorf("unable to initialize cryptsetup on device %q: %v", csEntry.Device, err)
	}
	err = device.FormatLUKS(cypherKind, cypherMode, "", "", 256/8, params)
	if err != nil {
		return fmt.Errorf("unable to format device %q for cryptsetup: %v", csEntry.Device, err)
	}

	// Add passphrases to keyslots
	for i, key := range keys {
		err = device.AddPassphraseToKeyslot(i, "", key)
		if err != nil {
			return fmt.Errorf("error setting keyslot %d passphrase for %q: %v", i, csEntry.Name, err)
		}
	}

	// Leave the device in an active state
	err = device.Load()
	if err != nil {
		return fmt.Errorf("error loading cryptsetup data from device %q: %v", csEntry.Device, err)
	}
	for i, key := range keys {
		err = device.Activate(csEntry.Name, i, key, 0)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to activate cryptsetup entry %q", csEntry.Name)
}

func (s stage) fetchKeyslotPass(ctx context.Context, keyslot types.LuksKeyslot) (string, error) {
	// TODO(lucab): implement
	return "fixedkey", nil
}
