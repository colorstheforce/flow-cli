/*
 * Flow CLI
 *
 * Copyright 2019-2021 Dapper Labs, Inc.
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
package json

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfigNetworkSimple(t *testing.T) {
	b := []byte(`{
    "testnet": "access.testnet.nodes.onflow.org:9000"
	}`)

	var jsonNetworks jsonNetworks
	err := json.Unmarshal(b, &jsonNetworks)
	require.NoError(t, err)

	networks := jsonNetworks.transformToConfig()

	assert.Equal(t, networks.GetByName("testnet").Host, "access.testnet.nodes.onflow.org:9000")
	assert.Equal(t, networks.GetByName("testnet").Name, "testnet")
}

func Test_ConfigNetworkMultiple(t *testing.T) {
	b := []byte(`{
    "emulator": {
      "host": "127.0.0.1:3569",
			"chain": "flow-emulator",
      "serviceAccount": "emulator-service"
    },
    "testnet": "access.testnet.nodes.onflow.org:9000"
	}`)

	var jsonNetworks jsonNetworks
	err := json.Unmarshal(b, &jsonNetworks)
	require.NoError(t, err)

	networks := jsonNetworks.transformToConfig()

	assert.Equal(t, networks.GetByName("testnet").Host, "access.testnet.nodes.onflow.org:9000")
	assert.Equal(t, networks.GetByName("testnet").Name, "testnet")

	assert.Equal(t, networks.GetByName("emulator").Name, "emulator")
	assert.Equal(t, networks.GetByName("emulator").Host, "127.0.0.1:3569")
}

func Test_TransformNetworkToJSON(t *testing.T) {
	b := []byte(`{"emulator":{"host":"127.0.0.1:3569","chain":"flow-emulator"},"testnet":"access.testnet.nodes.onflow.org:9000"}`)

	var jsonNetworks jsonNetworks
	err := json.Unmarshal(b, &jsonNetworks)
	require.NoError(t, err)

	networks := jsonNetworks.transformToConfig()

	j := transformNetworksToJSON(networks)
	x, _ := json.Marshal(j)

	assert.Equal(t, string(b), string(x))
}
