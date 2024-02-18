package ethpoc

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"strconv"
)

var errEthashStopped = errors.New("ethash stopped")

// API exposes ethash related methods for the RPC interface.
type API struct {
	ethPoc *EthPoc // Make sure the mode of ethash is normal.
}

// GetWork returns a work package for external miner.
//
// The work package consists of 3 strings:
//   result[0] - 32 bytes hex encoded current block header pow-hash
//   result[1] - 32 bytes hex encoded seed hash used for DAG
//   result[2] - 32 bytes hex encoded boundary condition ("target"), 2^256/difficulty
//   result[3] - hex encoded block number
func (api *API) GetWork() ([5]string, error) {
	if api.ethPoc.config.PocMode != ModeNormal && api.ethPoc.config.PocMode != ModeTest {
		return [5]string{}, errors.New("not supported")
	}

	var (
		workCh = make(chan [5]string, 1)
		errc   = make(chan error, 1)
	)

	select {
	case api.ethPoc.fetchWorkCh <- &sealWork{errc: errc, res: workCh}:
	case <-api.ethPoc.exitCh:
		return [5]string{}, errEthashStopped
	}

	select {
	case work := <-workCh:
		return work, nil
	case err := <-errc:
		return [5]string{}, err
	}
}

// SubmitWork can be used by external miner to submit their POW solution.
// It returns an indication if the work was accepted.
// Note either an invalid solution, a stale work a non-existent work will return false.
func (api *API) SubmitWork(hash common.Hash, nonce, plotter, number uint64) [2]string {
	var result [2]string
	result[0] = strconv.FormatBool(false)

	if api.ethPoc.config.PocMode != ModeNormal && api.ethPoc.config.PocMode != ModeTest {
		return result
	}

	var errc = make(chan [2]string, 1)

	select {
	case api.ethPoc.submitWorkCh <- &mineResult{
		hash:    hash,
		nonce:   nonce,
		plotter: plotter,
		number:  number,
		errc:    errc,
	}:
	case <-api.ethPoc.exitCh:
		return result
	}

	err := <-errc
	return err
}

// SubmitHashrate can be used for remote miners to submit their hash rate.
// This enables the node to report the combined hash rate of all miners
// which submit work through this node.
//
// It accepts the miner hash rate and an identifier which must be unique
// between nodes.
func (api *API) SubmitHashRate(rate hexutil.Uint64, id common.Hash) bool {
	if api.ethPoc.config.PocMode != ModeNormal && api.ethPoc.config.PocMode != ModeTest {
		return false
	}

	var done = make(chan struct{}, 1)

	select {
	//case api.ethPoc.submitRateCh <- &hashrate{done: done, rate: uint64(rate), id: id}:
	case <-api.ethPoc.exitCh:
		return false
	}

	// Block until hash rate submitted successfully.
	<-done

	return true
}

// GetHashrate returns the current hashrate for local CPU miner and remote miner.
func (api *API) GetHashrate() uint64 {
	//return uint64(api.ethPoc.Hashrate())
	return 0
}
