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
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/coreos/ignition/config/types"
	"github.com/martinjungblut/cryptsetup"
	"gitlab.com/lucab/coreos-cryptagent/pkg/providers"
	"golang.org/x/net/context"
)

// createCryptsetup creates cryptsetup partitions described in config.Storage.Encryption
//
// This assumes that cryptsetup config has already been validated at parsing time.
func (s stage) createCryptsetup(config types.Config) error {
	encCfg := config.Storage.Encryption
	if len(encCfg) == 0 {
		return nil
	}
	s.Logger.PushPrefix("createCryptsetup")
	defer s.Logger.PopPrefix()

	devs := []string{}
	for _, entry := range config.Storage.Encryption {
		devs = append(devs, entry.Device)
	}
	if err := s.waitOnDevicesAndCreateAliases(devs, "crypsetup"); err != nil {
		return err
	}

	for _, encEntry := range encCfg {
		if err := s.createCryptsetupEntry(encEntry); err != nil {
			return err
		}
	}

	return nil
}

// createCryptsetupEntry creates a single cryptsetup partition entry.
func (s stage) createCryptsetupEntry(encEntry types.Encryption) error {
	ctx := context.Background()
	// Fetch keyslots passphrases
	keys := []string{}
	for i, slot := range encEntry.KeySlots {
		key, err := s.fetchKeyslotPass(ctx, slot)
		if err != nil {
			return fmt.Errorf("fetching keyslot passphrase %d for %q: %v", i, encEntry.Name, err)
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
	err, device := cryptsetup.Init(encEntry.Device)
	if err != nil {
		return fmt.Errorf("unable to initialize cryptsetup on device %q: %v", encEntry.Device, err)
	}
	err = device.FormatLUKS(cypherKind, cypherMode, "", "", 256/8, params)
	if err != nil {
		return fmt.Errorf("unable to format device %q for cryptsetup: %v", encEntry.Device, err)
	}

	// Add passphrases to keyslots
	for i, key := range keys {
		err = device.AddPassphraseToKeyslot(i, "", key)
		if err != nil {
			return fmt.Errorf("error setting keyslot %d passphrase for %q: %v", i, encEntry.Name, err)
		}
	}

	// Leave the device in an active state
	if err := device.Load(); err != nil {
		return fmt.Errorf("error loading cryptsetup data from device %q: %v", encEntry.Device, err)
	}
	for i, key := range keys {
		err = device.Activate(encEntry.Name, i, key, 0)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("unable to activate cryptsetup entry %q", encEntry.Name)
}

func (s stage) fetchKeyslotPass(ctx context.Context, keyslot types.LuksKeyslot) (string, error) {
	p, err := providers.FromIgnitionV220(keyslot)
	if err != nil {
		return "", err
	}

	ciphertext, err := generateRandomASCIIString(63)
	if err != nil {
		return "", err
	}

	var res providers.Result
	tries := 5
	for tries > 0 {
		ch := make(chan providers.Result, 1)
		p.SetupPassphrase(ctx, ciphertext, ch)
		res = <-ch
		if res.Err == nil {
			break
		}
		tries--
		s.Logger.Debug("retrying in 5s")
		time.Sleep(time.Duration(5) * time.Second)
	}
	return res.Pass, res.Err
}

func generateRandomASCIIString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			return result, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		if n > 32 && n < 127 {
			result += string(n)
		}
	}
}
