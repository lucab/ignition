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

package providers

import (
	"context"
	"errors"

	"github.com/coreos/ignition/config/types"
	"gitlab.com/lucab/coreos-cryptagent/pkg/config"
)

// Result represents the result of an async passphrase operation.
// It contains either a password or an operational error.
type Result struct {
	Pass string
	Err  error
}

// PassGetter is an interface that can be used by library consumer
// without having direct access to each individual provider.
type PassGetter interface {
	GetPassphrase(ctx context.Context, doneCh chan<- Result)
	SetupPassphrase(ctx context.Context, cleartext string, doneCh chan<- Result)
	ToProviderJSON() (*config.ProviderJSON, error)
}

// FromIgnitionV220 constructs an opaque PassGetter from an ignition-2.2.0
// keyslot configuration entry.
func FromIgnitionV220(ks types.LuksKeyslot) (PassGetter, error) {
	switch {
	case ks.AzureVault != nil:
		return azureVaultFromIgnitionV220(ks)
	case ks.Content != nil:
		return contentFromIgnitionV220(ks)
	case ks.HcVault != nil:
		return nil, errors.New("unkwnown key")
	}

	return nil, errors.New("invalid keyslot")
}

// FromProviderJSON constructs and opaque PassGetter from any ProviderJSON
// configuration file.
func FromProviderJSON(cfg *config.ProviderJSON) (PassGetter, error) {
	if cfg == nil {
		return nil, errors.New("nil JSON provider configuration")
	}

	switch {
	case cfg.Kind == config.ProviderAzureVaultV1:
		return azureVaultFromConfigV1(cfg)
	case cfg.Kind == config.ProviderContentV1:
		return contentFromConfigV1(cfg)
	case cfg.Kind == config.ProviderHcVaultV1:
		return nil, errors.New("unkwnown key")
	}

	return nil, errors.New("invalid provider")
}
