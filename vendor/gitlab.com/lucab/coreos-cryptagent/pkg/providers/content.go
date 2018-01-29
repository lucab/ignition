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
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/coreos/ignition/config/types"
	"github.com/sirupsen/logrus"
	"gitlab.com/lucab/coreos-cryptagent/pkg/config"
)

type content struct {
	source                 string
	client                 *http.Client
	responseHeadersTimeout int
	totalTimeout           int
	certAuths              []string
}

func contentFromConfigV1(cfg *config.ProviderJSON) (*content, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if cfg.Kind != config.ProviderContentV1 {
		return nil, fmt.Errorf("expected kind %q, got %q", config.ProviderContentV1, cfg.Kind)
	}

	value, ok := cfg.Value.(config.ContentV1)
	if !ok {
		return nil, errors.New("not a ContentV1 value")
	}

	c := content{
		source: value.Source,
		client: nil,
	}
	if value.Timeouts != nil {
		c.totalTimeout = value.Timeouts.HTTPTotal
		c.responseHeadersTimeout = value.Timeouts.HTTPResponseHeaders
	}
	for _, ca := range value.CertificateAuthorities {
		c.certAuths = append(c.certAuths, ca.Authority)
	}

	return &c, nil

}

func contentFromIgnitionV220(ks types.LuksKeyslot, ign types.Ignition) (*content, error) {
	if ks.Content == nil {
		return nil, errors.New("nil Content keyslot")
	}
	if ks.Content.Source == "" {
		return nil, errors.New("empty source in Content keyslot")
	}
	c := content{
		source: ks.Content.Source,
	}
	return &c, nil
}

func (c *content) GetCleartext(ctx context.Context, doneCh chan<- Result) {
	if c == nil {
		doneCh <- Result{"", errors.New("nil content receiver")}
		return
	}
	if c.source == "" {
		doneCh <- Result{"", errors.New("missing source URL")}
		return
	}
	logrus.Debugf("content: fetching from %s\n", c.source)

	req, err := http.NewRequest("GET", c.source, nil)
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	req = req.WithContext(ctx)

	client := c.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		doneCh <- Result{"", err}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		doneCh <- Result{"", fmt.Errorf("%s", resp.Status)}
		return
	}
	logrus.Debugf("content: got positive response\n")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		doneCh <- Result{"", err}
		return
	}

	doneCh <- Result{string(body), nil}
}

func (c *content) Encrypt(ctx context.Context, cleartext string, doneCh chan<- Result) {
	doneCh <- Result{"", errors.New("content does not support encryption")}
}

func (c *content) ToProviderJSON() (*config.ProviderJSON, error) {
	if c == nil {
		return nil, errors.New("nil content receiver")
	}
	v := config.ContentV1{
		Source: c.source,
	}
	pj := config.ProviderJSON{
		Kind:  config.ProviderContentV1,
		Value: v,
	}
	return &pj, nil
}

func (c *content) CanEncrypt() bool {
	return false
}

func (c *content) SetCiphertext(ciphertext string) {
}
