// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

var benefitAccount = common.Hex2Bytes("6080604052600436106100705760003560e01c80639456fbbf1161004e5780639456fbbf1461029c578063a98c6b6714610317578063be89e61414610345578063f18d28811461038057610070565b8063080a6bb6146100755780634a384ae314610151578063643c0295146101a0575b600080fd5b34801561008157600080fd5b5061013b6004803603602081101561009857600080fd5b81019080803590602001906401000000008111156100b557600080fd5b8201836020820111156100c757600080fd5b803590602001918460018302840111640100000000831117156100e957600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505091929192905050506103b8565b6040518082815260200191505060405180910390f35b34801561015d57600080fd5b5061019e6004803603606081101561017457600080fd5b810190808035906020019092919080359060200190929190803590602001909291905050506103c6565b005b3480156101ac57600080fd5b5061029a600480360360808110156101c357600080fd5b810190808035906020019092919080359060200190929190803573ffffffffffffffffffffffffffffffffffffffff1690602001909291908035906020019064010000000081111561021457600080fd5b82018360208201111561022657600080fd5b8035906020019184600183028401116401000000008311171561024857600080fd5b91908080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050509192919290505050610580565b005b3480156102a857600080fd5b506102d5600480360360208110156102bf57600080fd5b8101908080359060200190929190505050610823565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6103436004803603602081101561032d57600080fd5b8101908080359060200190929190505050610862565b005b34801561035157600080fd5b5061037e6004803603602081101561036857600080fd5b8101908080359060200190929190505050610a17565b005b6103b66004803603604081101561039657600080fd5b810190808035906020019092919080359060200190929190505050610c8c565b005b600060019050809050919050565b8282116103d257600080fd5b600080600083815260200190815260200160002090508060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461044457600080fd5b6000600160008360020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090506104bd81600001548360040154610e8e565b81600001819055506104d76104d28587610e8e565b610f17565b82600401819055506104f181600001548360040154610f2b565b81600001819055507fabf4a6f12f1c0567ffb202f8f50c4407620070dc7fa06a40b39d18cbcb2f49e13386866001604051808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018481526020018381526020018215151515815260200194505050505060405180910390a15050505050565b83831161058c57600080fd5b6000610597826103b8565b905060008114610629573373ffffffffffffffffffffffffffffffffffffffff167fcecd070645f79c91f756c6be60422704eacb51da4f1fcb106c5af2942be910cf846000604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001821515151581526020019250505060405180910390a25b60008060008381526020019081526020016000209050600081600501541461065057600080fd5b858160000181905550848160010181905550338160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550838160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000816005018190555060006106fe8688610e8e565b905061070981610f17565b82600401819055506000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905061076681600001548460040154610f2b565b81600001819055503373ffffffffffffffffffffffffffffffffffffffff167f62aacc10b027a85d26fab7fd7a4d64cf2ce67f56fd9b6e708bc1294503b7b2cb8460030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166001604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001821515151581526020019250505060405180910390a25050505050505050565b600080600083815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b600080600083815260200190815260200160002090503373ffffffffffffffffffffffffffffffffffffffff168160030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146108d457600080fd5b6108e2816005015434610f2b565b81600501819055506000600160008360020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905061095f816001015434610f2b565b81600101819055503373ffffffffffffffffffffffffffffffffffffffff167f62aacc10b027a85d26fab7fd7a4d64cf2ce67f56fd9b6e708bc1294503b7b2cb8360020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166001604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001821515151581526020019250505060405180910390a2505050565b600080600083815260200190815260200160002090503373ffffffffffffffffffffffffffffffffffffffff168160020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610a8957600080fd5b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050610ade81600001548360040154610e8e565b8160000181905550610af881600101548360050154610e8e565b8160010181905550600082600501541115610b585760008260020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505050610c89565b60008084815260200190815260200160002060008082016000905560018201600090556002820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556003820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556004820160009055600582016000905550503373ffffffffffffffffffffffffffffffffffffffff167f81d12d1b0650599b32c3f54c013ba638aab17f71dc662906811a59079ac6a93e8360030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166001604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001821515151581526020019250505060405180910390a250505b50565b60008111610c9957600080fd5b600080600084815260200190815260200160002090503373ffffffffffffffffffffffffffffffffffffffff168160030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610d0b57600080fd5b8181600501541015610d60576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b610d6e816005015483610e8e565b81600501819055506000600160008360020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050610deb816001015484610e8e565b81600101819055503373ffffffffffffffffffffffffffffffffffffffff166108fc849081150290604051600060405180830381858888f19350505050158015610e39573d6000803e3d6000fd5b503373ffffffffffffffffffffffffffffffffffffffff167fbe7fa761772fc06c1c7eaded0733611ec365ac2d42a6c75a1ca5a50f70789bc0846040518082815260200191505060405180910390a250505050565b600082821115610f06576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f536166654d6174683a207375627472616374696f6e206f766572666c6f77000081525060200191505060405180910390fd5b600082840390508091505092915050565b6000610f24826001610fb3565b9050919050565b600080828401905083811015610fa9576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601b8152602001807f536166654d6174683a206164646974696f6e206f766572666c6f77000000000081525060200191505060405180910390fd5b8091505092915050565b600080831415610fc65760009050611033565b6000828402905082848281610fd757fe5b041461102e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252602181526020018061103a6021913960400191505060405180910390fd5b809150505b9291505056fe536166654d6174683a206d756c7469706c69636174696f6e206f766572666c6f77a265627a7a72315820e4293183b613d0cb329e60113b9eb1fc2d4cfeb70bb832a2138c21a2d6c258f064736f6c637828302e352e31312d6e696768746c792e323031392e372e32392b636f6d6d69742e32666463303763350058")

var BenefitAccountAddress = common.BytesToAddress([]byte{8})

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      GenesisAlloc        `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	return SetupGenesisBlockWithOverride(db, genesis, nil)
}

func SetupGenesisBlockWithOverride(db ethdb.Database, genesis *Genesis, overrideIstanbul *big.Int) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return genesis.Config, common.Hash{}, err
		}
		return genesis.Config, block.Hash(), nil
	}

	// We have the genesis block in database(perhaps in ancient database)
	// but the corresponding state is missing.
	header := rawdb.ReadHeader(db, stored, 0)
	if _, err := state.New(header.Root, state.NewDatabaseWithCache(db, 0)); err != nil {
		if genesis == nil {
			genesis = DefaultGenesisBlock()
		}
		// Ensure the stored genesis matches with the given one.
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return genesis.Config, hash, err
		}
		return genesis.Config, block.Hash(), nil
	}

	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	if overrideIstanbul != nil {
		newcfg.IstanbulBlock = overrideIstanbul
	}
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	default:
		return params.AllEthashProtocolChanges
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = rawdb.NewMemoryDatabase()
	}
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true)

	return types.NewBlock(head, nil, nil, nil)
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{Alloc: GenesisAlloc{addr: {Balance: balance}}}
	return g.MustCommit(db)
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
		GasLimit:   50000000,
		Difficulty: new(big.Int).SetUint64(18325193796),
		Alloc: map[common.Address]GenesisAccount{
			BenefitAccountAddress:             {Balance: big.NewInt(1), Code: benefitAccount},
			common.BytesToAddress([]byte{21}): {Balance: big.NewInt(1)},
			common.BytesToAddress([]byte{1}):  {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}):  {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}):  {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}):  {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}):  {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}):  {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}):  {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}):  {Balance: big.NewInt(1)}, // ECPairing
		},
	}
}

// DefaultTestnetGenesisBlock returns the Ropsten network genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      decodePrealloc(testnetAllocData),
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DefaultGoerliGenesisBlock returns the Görli network genesis block.
func DefaultGoerliGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.GoerliChainConfig,
		Timestamp:  1548854791,
		ExtraData:  hexutil.MustDecode("0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   10485760,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(goerliAllocData),
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block. Note, this must
// be seeded with the
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   6283185,
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}
