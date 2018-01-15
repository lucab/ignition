// Copyright 2018 CoreOS, Inc.
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

package config

import (
	"encoding/json"
	"errors"
)

type VolumeKind int

const (
	VolumeInvalid VolumeKind = iota
	VolumeCryptsetupV1
)

func (vk *VolumeKind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "CryptsetupV1":
		*vk = VolumeCryptsetupV1
	default:
		return errors.New("unknown kind")
	}

	return nil
}

func (vk *VolumeKind) MarshalJSON() ([]byte, error) {
	var s string
	switch *vk {
	case VolumeCryptsetupV1:
		s = "CryptsetupV1"
	default:
		return nil, errors.New("unknown kind")
	}

	return json.Marshal(s)
}

type ProviderKind int

const (
	// ProviderInvalid is the nil value for ProviderKind
	ProviderInvalid ProviderKind = iota
	// ProviderContentV1 represents a plain Content (v1) config
	ProviderContentV1
	// ProviderAzureVaultV1 represents an Azure Vault (v1) config
	ProviderAzureVaultV1
	// ProviderHcVaultV1 represents an HashiCorp Vault (v1) config
	ProviderHcVaultV1
)

func (vk *ProviderKind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch s {
	case "ContentV1":
		*vk = ProviderContentV1
	case "AzureVaultV1":
		return errors.New("unimplemented")
	case "HcVaultV1":
		return errors.New("unimplemented")
	default:
		return errors.New("unknown kind")
	}

	return nil
}

func (vk *ProviderKind) MarshalJSON() ([]byte, error) {
	var s string
	switch *vk {
	case ProviderContentV1:
		s = "ContentV1"
	case ProviderAzureVaultV1:
		return nil, errors.New("unimplemented")
	case ProviderHcVaultV1:
		return nil, errors.New("unimplemented")
	default:
		return nil, errors.New("unknown kind")
	}

	return json.Marshal(s)
}
