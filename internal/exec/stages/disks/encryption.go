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
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/unit"
	"github.com/coreos/ignition/config/types"
	"github.com/martinjungblut/cryptsetup"
	"gitlab.com/lucab/coreos-cryptagent/pkg/config"
	"gitlab.com/lucab/coreos-cryptagent/pkg/providers"
	"golang.org/x/net/context"
)

type contextKey string

var configDir = filepath.Join(os.TempDir(), "ignition-cryptagent")

// createEncryption creates all the encrypted cryptsetup volumes
// described in config.Storage.Encryption.
//
// This assumes that storage.encryption configuration has already been
// validated at parsing time.
func (s stage) createEncryption(ctx context.Context, config types.Config) error {
	encCfg := config.Storage.Encryption
	if len(encCfg) == 0 {
		return nil
	}
	s.Logger.PushPrefix("createEncryption")
	defer s.Logger.PopPrefix()

	devs := []string{}
	for _, entry := range config.Storage.Encryption {
		devs = append(devs, entry.Device)
	}
	if err := s.waitOnDevicesAndCreateAliases(devs, "encryption"); err != nil {
		return err
	}
	s.waitOnEntropyAvailable(256, 5, 5)

	for _, encEntry := range encCfg {
		encEntryCtx := context.WithValue(ctx, contextKey("volName"), encEntry.Name)
		// TODO(lucab): consider running these in parallel (maybe?)
		if err := s.createEncryptedEntry(encEntryCtx, encEntry); err != nil {
			return err
		}
	}

	return nil
}

func (s stage) waitOnEntropyAvailable(bytes int, tries int, pause int) {
	avail := -1
	for tries >= 0 {
		if avail >= 0 && avail < bytes {
			s.Logger.Info("Not enough entropy, retrying in %ds, currently available: %d", pause, avail)
			time.Sleep(time.Duration(pause) * time.Second)
		}
		avail = 0
		tries--
		fp, err := os.Open("/proc/sys/kernel/random/entropy_avail")
		if err != nil {
			continue
		}
		defer fp.Close()
		valueStr, err := bufio.NewReader(fp).ReadString('\n')
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(valueStr))
		if err != nil {
			continue
		}
		avail = n
		if avail >= bytes {
			s.Logger.Info("System has enough entropy (%d bytes), proceeding", avail)
			break
		}
	}
	return
}

// createEncryptedEntry creates a single cryptsetup volume entry.
func (s stage) createEncryptedEntry(ctx context.Context, encEntry types.Encryption) error {
	escaped := unit.UnitNamePathEscape(encEntry.Device)
	volumeDir := filepath.Join(configDir, escaped)
	if err := os.MkdirAll(volumeDir, 0400); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", volumeDir, err)
	}
	// TODO(lucab): make this configurable
	cryptohashKind := "sha256"
	cipherKind := "aes"
	cipherMode := "xts-plain64"
	params := cryptsetup.LUKSParams{
		Hash:           cryptohashKind,
		Data_alignment: 0,
		Data_device:    "",
	}
	volConf, err := agentVolumeConfig(encEntry)
	if err != nil {
		return fmt.Errorf("failed to assemble volume config for %s: %v", encEntry.Name, err)
	}
	if err := s.recordVolumeConfig(volConf, volumeDir); err != nil {
		return err
	}
	device, err := s.createEncryptedVolume(ctx, encEntry, params, cipherKind, cipherMode)
	if err != nil {
		return err
	}

	// Fetch keyslots passphrases
	keys := []string{}
	for i, slot := range encEntry.KeySlots {
		key, err := s.fetchKeyslotPass(ctx, slot)
		if err != nil {
			return fmt.Errorf("fetching keyslot passphrase %d for %s: %v", i, encEntry.Name, err)
		}
		fmt.Printf("fetched key %s\n", key)
		keys = append(keys, key)
		fmt.Printf("keys array: %#v\n", keys)
		if err := s.recordSlotConfig(slot, i, key, volumeDir); err != nil {
			return err
		}
		fmt.Printf("recorded key %s\n", key)
		if err = device.AddPassphraseToKeyslot(i, "", key); err != nil {
			return fmt.Errorf("error setting keyslot %d passphrase for %s: %v", i, encEntry.Name, err)
		}
		fmt.Printf("added key %s\n", key)
		// TODO(lucab): remove when adding support for multiple keyslots
		break
	}

	fmt.Printf("total keys array: %#v\n", keys)
	// Leave the device in an active state
	if err := device.Load(); err != nil {
		return fmt.Errorf("error loading cryptsetup data from device %s: %v", encEntry.Device, err)
	}
	active := false
	for i, key := range keys {
		fmt.Printf("activating %d with key %s", i, key)
		err = device.Activate(encEntry.Name, i, key, 0)
		if err == nil {
			active = true
			break
		} else {
			return fmt.Errorf("failed to activate keyslot %d with key %s: %s", i, key, err)
		}
	}

	if !active {
		return fmt.Errorf("unable to activate cryptsetup entry %s", encEntry.Name)
	}
	return nil
}

func (s stage) recordVolumeConfig(volConf *config.VolumeJSON, volumeDir string) error {
	volumePath := filepath.Join(volumeDir, "volume.json")
	vfp, err := os.OpenFile(volumePath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer vfp.Close()
	vbufwr := bufio.NewWriter(vfp)
	if err := json.NewEncoder(vbufwr).Encode(volConf); err != nil {
		return fmt.Errorf("failed to write %s: %v", volumePath, err)
	}
	if err := vbufwr.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %v", volumePath, err)
	}

	return nil
}

func (s stage) recordSlotConfig(ks types.LuksKeyslot, index int, key string, volumeDir string) error {
	slotConf, err := agentSlotProviderConfig(ks, key)
	if err != nil {
		return fmt.Errorf("failed to assemble slot config: %v", err)
	}
	slotPath := filepath.Join(volumeDir, fmt.Sprintf("%d.json", index))
	sfp, err := os.OpenFile(slotPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer sfp.Close()
	sbufwr := bufio.NewWriter(sfp)
	if err := json.NewEncoder(sbufwr).Encode(slotConf); err != nil {
		return fmt.Errorf("failed to write %s: %v", slotPath, err)
	}
	if err := sbufwr.Flush(); err != nil {
		return fmt.Errorf("failed to flush %s: %v", slotPath, err)
	}

	return nil
}

func agentVolumeConfig(e types.Encryption) (*config.VolumeJSON, error) {
	cs := config.CryptsetupV1{
		Name:           e.Name,
		Device:         e.Device,
		DisableDiscard: &e.DisableDiscard,
	}

	vol := config.VolumeJSON{
		Kind:  config.VolumeCryptsetupV1,
		Value: cs,
	}

	return &vol, nil
}

func agentSlotProviderConfig(l types.LuksKeyslot, key string) (*config.ProviderJSON, error) {
	p, err := providers.FromIgnitionV220(l)
	if err != nil {
		return nil, err
	}
	p.SetCiphertext(key)

	pj, err := p.ToProviderJSON()
	if err != nil {
		return nil, err
	}

	return pj, nil
}

func (s stage) createEncryptedVolume(ctx context.Context, encEntry types.Encryption, params cryptsetup.LUKSParams, cipherKind string, cipherMode string) (*cryptsetup.CryptDevice, error) {
	// Initialize device
	err, device := cryptsetup.Init(encEntry.Device)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize cryptsetup on device %s: %v", encEntry.Device, err)
	}
	err = device.FormatLUKS(cipherKind, cipherMode, "", "", 256/8, params)
	if err != nil {
		return nil, fmt.Errorf("unable to format device %q for cryptsetup: %v", encEntry.Device, err)
	}

	return device, nil
}

func (s stage) fetchKeyslotPass(ctx context.Context, keyslot types.LuksKeyslot) (string, error) {
	p, err := providers.FromIgnitionV220(keyslot)
	if err != nil {
		return "", err
	}

	if p.CanEncrypt() {
		var res providers.Result
		pass, err := generateRandomASCIIString(63)
		if err != nil {
			return "", err
		}
		tries := 5
		for tries > 0 {
			ch := make(chan providers.Result, 1)
			p.Encrypt(ctx, pass, ch)
			res = <-ch
			if res.Err == nil {
				break
			}
			tries--
			s.Logger.Info("Transient error, retrying in 5s, current failure: %s ", res.Err)
			time.Sleep(time.Duration(5) * time.Second)
		}
		if res.Err != nil {
			return "", res.Err
		}
		p.SetCiphertext(res.Ok)
	}

	var res providers.Result
	tries := 5
	for tries > 0 {
		ch := make(chan providers.Result, 1)
		p.GetCleartext(ctx, ch)
		res = <-ch
		if res.Err == nil {
			break
		}
		tries--
		s.Logger.Info("Transient error, retrying in 5s, current failure: %s ", res.Err)
		time.Sleep(time.Duration(5) * time.Second)
	}
	s.Logger.Info("fetched slot key %s\n", res.Ok)
	return res.Ok, res.Err
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
