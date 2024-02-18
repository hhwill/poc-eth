package ethpoc

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/net/context"
	"github.com/ethereum/go-ethereum/params"
)

type Mode uint

const (
	ModeNormal   Mode = iota
	ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)

// Config are the configuration parameters of the ethPoc.
type Config struct {
	PocMode Mode
}

// sealTask wraps a seal block with relative result channel for remote sealer thread.
type sealTask struct {
	block   *types.Block
	results chan<- *types.Block
}

// hashrate wraps the hash rate submitted by the remote sealer.
type hashrate struct {
	//id   common.Hash
	ping time.Time
	rate uint64

	done chan struct{}
}

//type sealTask struct {
//	ReqProTime uint64   `json:"reqProTime"`
//	Number     *big.Int `json:"number"`
//	BaseTarget *big.Int `json:"baseTarget"`
//	GenSign    []byte   `json:"genSign"`
//}

type mineResult struct {
	hash    common.Hash
	nonce   uint64
	plotter uint64
	number  uint64

	errc chan [2]string
}

// sealWork wraps a seal work package for remote sealer.
type sealWork struct {
	errc chan error
	res  chan [5]string
}

// EthPoc is a consensus engine based on proof-of-Capacity implementing the ethpoc
// algorithm.
type EthPoc struct {
	config Config

	blockChain  *core.BlockChain
	chainConfig *params.ChainConfig

	am *accounts.Manager

	// Remote sealer related fields
	threads      int              // Number of threads to mine on if mining
	workCh       chan *sealTask   // Notification channel to push new work and relative result channel to remote sealer
	fetchWorkCh  chan *sealWork   // Channel used for remote sealer to fetch mining work
	submitWorkCh chan *mineResult // Channel used for remote sealer to submit their mining result
	fetchRateCh  chan chan uint64 // Channel used to gather submitted hash rate for local or remote sealer.
	//submitRateCh chan *hashrate   // Channel used for remote sealer to submit their mining hashrate

	ctx        context.Context
	cancelFunc context.CancelFunc

	// The fields below are hooks for testing
	//shared    *Ethash       // Shared PoW verifier to avoid cache regeneration
	fakeFail  uint64        // Block number which fails PoW check even in fake mode
	fakeDelay time.Duration // Time delay to sleep for before returning from verify

	update chan struct{} // Notification channel to update mining parameters

	lock      sync.Mutex      // Ensures thread safety for the in-memory caches and mining fields
	closeOnce sync.Once       // Ensures exit channel will not be closed twice.
	exitCh    chan chan error // Notification channel to exiting backend threads
}

// New creates a full sized ethPoc PoW scheme and starts a background thread for
// remote mining, also optionally notifying a batch of remote services of new work
// packages.
func New(chainConfig *params.ChainConfig, am *accounts.Manager, config Config, notify []string, noverify bool) *EthPoc {
	ethPoc := &EthPoc{
		am:           am,
		chainConfig:  chainConfig,
		config:       config,
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		//submitRateCh: make(chan *hashrate),
		exitCh: make(chan chan error),
	}

	ethPoc.ctx, ethPoc.cancelFunc = context.WithCancel(context.Background())

	go ethPoc.remote(notify, noverify)
	return ethPoc
}

func (ethPoc *EthPoc) SetBlockChain(blockChain *core.BlockChain) {
	ethPoc.blockChain = blockChain
}

// NewTester creates a small sized ethPoc PoW scheme useful only for testing
// purposes.
func NewTester(notify []string, noverify bool) *EthPoc {
	ethPoc := &EthPoc{
		config:       Config{PocMode: ModeTest},
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		exitCh:       make(chan chan error),
	}
	go ethPoc.remote(notify, noverify)
	return ethPoc
}

// NewFaker creates a ethPoc consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
func NewFaker() *EthPoc {
	return &EthPoc{
		config: Config{
			PocMode: ModeFake,
		},
	}
}

// NewFakeFailer creates a ethPoc consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Ethereum consensus rules.
func NewFakeFailer(fail uint64) *EthPoc {
	return &EthPoc{
		config: Config{
			PocMode: ModeFake,
		},
		fakeFail: fail,
	}
}

// NewFakeDelayer creates a ethPoc consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Ethereum consensus rules.
func NewFakeDelayer(delay time.Duration) *EthPoc {
	return &EthPoc{
		config: Config{
			PocMode: ModeFake,
		},
		fakeDelay: delay,
	}
}

// NewFullFaker creates an ethPoc consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
func NewFullFaker() *EthPoc {
	return &EthPoc{
		config: Config{
			PocMode: ModeFullFake,
		},
	}
}

// Close closes the exit channel to notify all backend threads exiting.
func (ethPoc *EthPoc) Close() error {
	var err error
	ethPoc.closeOnce.Do(func() {
		// Short circuit if the exit channel is not allocated.
		if ethPoc.exitCh == nil {
			return
		}
		errc := make(chan error)
		ethPoc.exitCh <- errc
		err = <-errc
		close(ethPoc.exitCh)
	})
	return err
}

func (ethPoc *EthPoc) SetThreads(threads int) {
	ethPoc.lock.Lock()
	defer ethPoc.lock.Unlock()

	// Update the threads and ping any running seal to pull in any changes
	ethPoc.threads = threads
	select {
	case ethPoc.update <- struct{}{}:
	default:
	}
}

// Hashrate implements PoW, returning the measured rate of the search invocations
// per second over the last minute.
// Note the returned hashrate includes local hashrate, but also includes the total
// hashrate of all remote miner.
//func (ethPoc *EthPoc) Hashrate() float64 {
//	// Short circuit if we are run the ethPoc in normal/test mode.
//	if ethPoc.config.PocMode != ModeNormal && ethPoc.config.PocMode != ModeTest {
//		return ethPoc.hashrate.Rate1()
//	}
//	var res = make(chan uint64, 1)
//
//	select {
//	case ethPoc.fetchRateCh <- res:
//	case <-ethPoc.exitCh:
//		// Return local hashrate only if ethPoc is stopped.
//		return ethPoc.hashrate.Rate1()
//	}
//
//	// Gather total submitted hash rate of remote sealers.
//	return ethPoc.hashrate.Rate1() + float64(<-res)
//}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (ethPoc *EthPoc) APIs(chain consensus.ChainReader) []rpc.API {
	// In order to ensure backward compatibility, we exposes ethPoc RPC APIs
	// to both eth and ethPoc namespaces.
	return []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &API{ethPoc},
			Public:    true,
		},
		{
			Namespace: "ethPoc",
			Version:   "1.0",
			Service:   &API{ethPoc},
			Public:    true,
		},
	}
}

// SeedHash is the seed to use for generating a verification cache and the mining
// dataset.
//func SeedHash(block uint64) []byte {
//	return seedHash(block)
//}
