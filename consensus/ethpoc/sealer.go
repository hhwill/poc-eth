package ethpoc

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"math/big"
	"strconv"

	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/net/context"
)

const (
	// staleThreshold is the maximum depth of the acceptable stale but valid ethPoc solution.
	staleThreshold = 7
)

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the block's difficulty requirements.
func (ethPoc *EthPoc) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if ethPoc.config.PocMode == ModeFake || ethPoc.config.PocMode == ModeFullFake {
		header := block.Header()
		header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "mode", "fake", "sealhash", ethPoc.SealHash(block.Header()))
		}
		return nil
	}

	// Push new work to remote sealer
	if ethPoc.workCh != nil {
		ethPoc.workCh <- &sealTask{block: block, results: results}
	}

	ethPoc.cancelFunc()
	ethPoc.ctx, ethPoc.cancelFunc = context.WithCancel(context.Background())
	log.Warn("Start cancel uncomplete work", "number", block.NumberU64()-1)
	return nil

}

// remote is a standalone goroutine to handle remote mining related stuff.

// remote is a standalone goroutine to handle remote mining related stuff.
func (ethPoc *EthPoc) remote(notify []string, noverify bool) {
	var (
		works = make(map[common.Hash]*types.Block)
		rates = make(map[common.Hash]hashrate)

		results      chan<- *types.Block
		currentBlock *types.Block
		currentWork  [5]string

		notifyTransport = &http.Transport{}
		notifyClient    = &http.Client{
			Transport: notifyTransport,
			Timeout:   time.Second,
		}
		notifyReqs = make([]*http.Request, len(notify))
	)
	// notifyWork notifies all the specified mining endpoints of the availability of
	// new work to be processed.
	notifyWork := func() {
		work := currentWork
		blob, _ := json.Marshal(work)

		for i, url := range notify {
			// Terminate any previously pending request and create the new work
			if notifyReqs[i] != nil {
				notifyTransport.CancelRequest(notifyReqs[i])
			}
			notifyReqs[i], _ = http.NewRequest("POST", url, bytes.NewReader(blob))
			notifyReqs[i].Header.Set("Content-Type", "application/json")

			// Push the new work concurrently to all the remote nodes
			go func(req *http.Request, url string) {
				res, err := notifyClient.Do(req)
				if err != nil {
					log.Warn("Failed to notify remote miner", "err", err)
				} else {
					log.Trace("Notified remote miner", "miner", url, "hash", log.Lazy{Fn: func() common.Hash { return common.HexToHash(work[0]) }}, "target", work[2])
					res.Body.Close()
				}
			}(notifyReqs[i], url)
		}
	}
	// makeWork creates a work package for external miner.
	//
	// The work package consists of 3 strings:
	//   result[0], 32 bytes hex encoded current block header pow-hash
	//   result[1], 32 bytes hex encoded seed hash used for DAG
	//   result[2], 32 bytes hex encoded boundary condition ("target"), 2^256/difficulty
	//   result[3], hex encoded block number
	makeWork := func(block *types.Block) {
		hash := ethPoc.SealHash(block.Header())
		header := block.Header()

		currentWork[0] = hash.Hex()
		currentWork[1] = strconv.FormatUint(header.Number.Uint64(), 10)
		currentWork[2] = header.MixDigest.Hex()[2:]
		currentWork[3] = strconv.FormatUint(header.Difficulty.Uint64(), 10)
		currentWork[4] = ""

		// Trace the seal work fetched by remote sealer.
		currentBlock = block
		works[hash] = block
	}
	// submitWork verifies the submitted pow solution, returning
	// whether the solution was accepted or not (not can be both a bad pow as well as
	// any other error, like no pending work or stale mining result).
	submitWork := func(block *types.Block, sealhash common.Hash, nonce, plotter, number uint64, deadLine *big.Int) bool {
		// Verify the correctness of submitted result.
		header := block.Header()
		header.Nonce = types.EncodeNonce(nonce)
		header.PlotterID = plotter
		pTime := header.Time

		nowTime := uint64(time.Now().Unix())
		deadLineU64 := deadLine.Uint64()

		if pTime+deadLineU64 > nowTime {
			interval := pTime + deadLineU64 - nowTime + 1
			t := time.NewTimer(15 * time.Second)
			log.Info("Start sleep", "ptime", pTime, "deadline", deadLineU64, "nowTime", nowTime, "time", interval)
			select {
			case <-t.C:
				break
			case <-ethPoc.ctx.Done():
				log.Info("Calcel sleep", "deadline", deadLineU64, "number", header.Number.Uint64(), "hash", sealhash)
				return false
			}
		}

		start := time.Now()
		header.Time = uint64(start.Unix())

		if !noverify {
			if err := ethPoc.verifySeal(nil, pTime, deadLine, header, true); err != nil {
				log.Warn("Invalid proof-of-work submitted", "sealhash", sealhash, "elapsed", time.Since(start), "err", err)
				return false
			}
		}

		account := accounts.Account{Address: header.Coinbase}
		wallet, err := ethPoc.am.Find(account)
		if err != nil {
			log.Warn("Can not find wallet for coin base address, submitted mining result is rejected", "error", err)
			return false
		}
		sigHash, err := wallet.SignText(account, header.Hash().Bytes())
		if err != nil {
			log.Warn("Sign Block hash error, submitted mining result is rejected", "error", err)
			return false
		}
		header.BlockSign = sigHash

		// Make sure the result channel is assigned.
		if results == nil {
			log.Warn("Ethash result channel is empty, submitted mining result is rejected")
			return false
		}
		log.Trace("Verified correct proof-of-work", "sealhash", sealhash, "elapsed", time.Since(start))

		// Solutions seems to be valid, return to the miner and notify acceptance.
		solution := block.WithSeal(header)

		// The submitted solution is within the scope of acceptance.
		if solution.NumberU64()+staleThreshold > currentBlock.NumberU64() {
			select {
			case results <- solution:
				log.Debug("Work submitted is acceptable", "number", solution.NumberU64(), "sealhash", sealhash, "hash", solution.Hash())
				return true
			default:
				log.Warn("Sealing result is not read by miner", "mode", "remote", "sealhash", sealhash)
				return false
			}
		}
		// The submitted block is too old to accept, drop it.
		log.Warn("Work submitted is too old", "number", solution.NumberU64(), "sealhash", sealhash, "hash", solution.Hash())
		return false
	}

	verifyWork := func(sealhash common.Hash, nonce, plotter, number uint64) (*big.Int, bool) {
		if currentBlock == nil {
			log.Error("Pending work without block", "sealhash", sealhash)
			return nil, false
		}
		// Make sure the work submitted is present
		block := works[sealhash]
		if block == nil {
			log.Warn("Work submitted but none pending", "sealhash", sealhash, "curnumber", currentBlock.NumberU64())
			return nil, false
		}
		// Verify the correctness of submitted result.
		header := block.Header()
		header.Nonce = types.EncodeNonce(nonce)
		header.PlotterID = plotter

		genSign := header.MixDigest.Bytes()
		scoop := int(calculateScoop(genSign, number))
		deadLine := calculateDeadline(header.PlotterID, header.Nonce, scoop, genSign, header.Difficulty)
		log.Info("Compute deadline", "deadLine", deadLine.Uint64())

		benefiter, _, err := callContract(ethPoc.chainConfig, ethPoc.ctx, ethPoc.blockChain, header, plotter)
		if err != nil {
			log.Info("Get benefiter error", "error", err)
			return nil, false
		}
		if common.BytesToAddress(benefiter) != header.Coinbase {
			log.Warn(fmt.Sprintf("Invalid coinbase,benefiter [%x],coin base [%x]", benefiter, header.Coinbase))
			return nil, false
		}

		//fmt.Printf("benefiter %x coinbase %x err %v\n", benefiter, header.Coinbase, err)
		go submitWork(block, sealhash, nonce, plotter, number, deadLine)
		return deadLine, true
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case work := <-ethPoc.workCh:
			// Update current work with new received block.
			// Note same work can be past twice, happens when changing CPU threads.
			results = work.results

			makeWork(work.block)

			// Notify and requested URLs of the new work availability
			notifyWork()

		case work := <-ethPoc.fetchWorkCh:
			// Return current mining work to remote miner.
			if currentBlock == nil {
				work.errc <- errNoMiningWork
			} else {
				work.res <- currentWork
			}

		case result := <-ethPoc.submitWorkCh:
			// Verify submitted PoW solution based on maintained mining blocks.

			var res [2]string
			deadLine, rev := verifyWork(result.hash, result.nonce, result.plotter, result.number)
			if deadLine != nil {
				res[0] = strconv.FormatUint(deadLine.Uint64(), 10)
			}

			res[1] = strconv.FormatBool(rev)

			result.errc <- res

			//case result := <-ethPoc.submitRateCh:
			//	// Trace remote sealer's hash rate by submitted value.
			//	rates[result.id] = hashrate{rate: result.rate, ping: time.Now()}
			//	close(result.done)

		case req := <-ethPoc.fetchRateCh:
			// Gather all hash rate submitted by remote sealer.
			var total uint64
			for _, rate := range rates {
				// this could overflow
				total += rate.rate
			}
			req <- total

		case <-ticker.C:
			// Clear stale submitted hash rate.
			for id, rate := range rates {
				if time.Since(rate.ping) > 10*time.Second {
					delete(rates, id)
				}
			}
			// Clear stale pending blocks
			if currentBlock != nil {
				for hash, block := range works {
					if block.NumberU64()+staleThreshold <= currentBlock.NumberU64() {
						delete(works, hash)
					}
				}
			}

		case errc := <-ethPoc.exitCh:
			// Exit remote loop if ethPoc is closed and return relevant error.
			errc <- nil
			log.Trace("Ethash remote sealer is exiting")
			return
		}
	}
}

func callContract(chainConfig *params.ChainConfig, ctx context.Context, b *core.BlockChain, header *types.Header, plotter uint64) ([]byte, bool, error) {

	pHeader := b.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	stateDb, err := b.StateAt(pHeader.Root)
	if stateDb == nil || err != nil {
		fmt.Printf("get state error %v\n", err)
		return nil, false, err
	}
	// Set sender address or use a default if none specified
	addr := common.BytesToAddress([]byte{8})

	data := make([]byte, 36)
	copy(data, common.Hex2Bytes("57edda67"))
	binary.BigEndian.PutUint64(data[28:36], plotter)

	// Create new call message
	msg := types.NewMessage(header.Coinbase, &addr, 0, big.NewInt(0), math.MaxUint64/2, big.NewInt(0), data, false)

	// Get a new instance of the EVM.
	evmContext := core.NewEVMContext(msg, pHeader, b, nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(evmContext, stateDb, chainConfig, *b.GetVMConfig())

	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		vmenv.Cancel()
	}()

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	res, _, failed, err := core.ApplyMessage(vmenv, msg, gp)
	if err != nil {
		fmt.Printf("ApplyMessage error %v\n", err)
		return nil, false, err
	}

	fmt.Printf("contract address %x res %v err %v\n", res, failed, err)

	return res, failed, err
}
