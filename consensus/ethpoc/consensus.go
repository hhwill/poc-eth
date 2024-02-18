package ethpoc

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/moonfruit/go-shabal"
	"golang.org/x/crypto/sha3"
)

// EthPoc proof-of-work protocol constants.
var (
	FrontierBlockReward              = big.NewInt(5e+18) // Block reward in wei for successfully mining a block
	ByzantiumBlockReward             = big.NewInt(3e+18) // Block reward in wei for successfully mining a block upward from Byzantium
	ConstantinopleBlockReward        = big.NewInt(2e+18) // Block reward in wei for successfully mining a block upward from Constantinople
	maxUncles                        = 2                 // Maximum number of uncles allowed in a single block
	allowedFutureBlockTime           = 15 * time.Second  // Max time from current time allowed for blocks, before they're considered future blocks
	INITIAL_BASE_TARGET       uint64 = 18325193796
	MAX_BASE_TARGET           uint64 = 18325193796
	ADJUST_BLOCK_NUMBER       uint64 = 2700
	BLOCK_INTERVAL            uint64 = 60 * 3

	HASH_SIZE        = 32
	HASHES_PER_SCOOP = 2
	SCOOP_SIZE       = HASHES_PER_SCOOP * HASH_SIZE
	SCOOPS_PER_PLOT  = 4096 // original 1MB/plot = 16384
	PLOT_SIZE        = SCOOPS_PER_PLOT * SCOOP_SIZE
	HASH_CAP         = 4096

	YEAR_TIME            uint64 = 60 * 60 * 24 * 365
	EACH_NUMBER_OF_4YEAR        = 4 * YEAR_TIME / BLOCK_INTERVAL

	// calcDifficultyConstantinople is the difficulty adjustment algorithm for Constantinople.
	// It returns the difficulty that a new block should have when created at time given the
	// parent block's time and difficulty. The calculation uses the Byzantium rules, but with
	// bomb offset 5M.
	// Specification EIP-1234: https://eips.ethereum.org/EIPS/eip-1234
	calcDifficultyConstantinople = makeDifficultyCalculator(big.NewInt(5000000))

	// calcDifficultyByzantium is the difficulty adjustment algorithm. It returns
	// the difficulty that a new block should have when created at time given the
	// parent block's time and difficulty. The calculation uses the Byzantium rules.
	// Specification EIP-649: https://eips.ethereum.org/EIPS/eip-649
	calcDifficultyByzantium = makeDifficultyCalculator(big.NewInt(3000000))
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errZeroBlockTime     = errors.New("timestamp equals parent's")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (ethPoc *EthPoc) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum EthPoc engine.
func (ethPoc *EthPoc) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// If we're running a full engine faking, accept any input as valid
	if ethPoc.config.PocMode == ModeFullFake {
		return nil
	}
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return ethPoc.verifyHeader(chain, header, parent, false, seal)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (ethPoc *EthPoc) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if ethPoc.config.PocMode == ModeFullFake || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs = make(chan int)
		done   = make(chan int, workers)
		errors = make([]error, len(headers))
		abort  = make(chan struct{})
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = ethPoc.verifyHeaderWorker(chain, headers, seals, index)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (ethPoc *EthPoc) verifyHeaderWorker(chain consensus.ChainReader, headers []*types.Header, seals []bool, index int) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if chain.GetHeader(headers[index].Hash(), headers[index].Number.Uint64()) != nil {
		return nil // known block
	}
	return ethPoc.verifyHeader(chain, headers[index], parent, false, seals[index])
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Ethereum EthPoc engine.
func (ethPoc *EthPoc) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {

	if len(block.Uncles()) > 0 {
		return errTooManyUncles
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum EthPoc engine.
// See YP section 4.3.4. "Block Header Validity"
func (ethPoc *EthPoc) verifyHeader(chain consensus.ChainReader, header, parent *types.Header, uncle bool, seal bool) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	if !uncle {
		if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time <= parent.Time {
		return errZeroBlockTime
	}
	// Verify the block's difficulty based in it's timestamp and parent's difficulty
	expected := ethPoc.CalcDifficulty(chain, header.Time, parent)

	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if header.GasLimit > cap {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, cap)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := ethPoc.VerifySeal(chain, header); err != nil {
			return err
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (ethPoc *EthPoc) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return CalcDifficulty(chain, chain.Config(), time, parent)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func CalcDifficulty(chain consensus.ChainReader, config *params.ChainConfig, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	switch {
	case config.IsConstantinople(next):
		return calcDifficultyConstantinople(time, parent)
	case config.IsByzantium(next):
		return calcDifficultyByzantium(time, parent)
	case config.IsHomestead(next):
		return calcDifficultyHomestead(time, parent)
	default:
		return calcBaseTarget(chain, time, parent)
	}
}

// Some weird constants to avoid constant memory allocs for them.
var (
	expDiffPeriod = big.NewInt(100000)
	big1          = big.NewInt(1)
	big2          = big.NewInt(2)
	big9          = big.NewInt(9)
	big10         = big.NewInt(10)
	bigMinus99    = big.NewInt(-99)
)

// makeDifficultyCalculator creates a difficultyCalculator with the given bomb-delay.
// the difficulty is calculated with Byzantium rules, which differs from Homestead in
// how uncles affect the calculation
func makeDifficultyCalculator(bombDelay *big.Int) func(time uint64, parent *types.Header) *big.Int {
	// Note, the calculations below looks at the parent number, which is 1 below
	// the block number. Thus we remove one from the delay given
	bombDelayFromParent := new(big.Int).Sub(bombDelay, big1)
	return func(time uint64, parent *types.Header) *big.Int {
		// https://github.com/ethereum/EIPs/issues/100.
		// algorithm:
		// diff = (parent_diff +
		//         (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
		//        ) + 2^(periodCount - 2)

		bigTime := new(big.Int).SetUint64(time)
		bigParentTime := new(big.Int).SetUint64(parent.Time)

		// holds intermediate values to make the algo easier to read & audit
		x := new(big.Int)
		y := new(big.Int)

		// (2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9
		x.Sub(bigTime, bigParentTime)
		x.Div(x, big9)
		if parent.UncleHash == types.EmptyUncleHash {
			x.Sub(big1, x)
		} else {
			x.Sub(big2, x)
		}
		// max((2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9, -99)
		if x.Cmp(bigMinus99) < 0 {
			x.Set(bigMinus99)
		}
		// parent_diff + (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
		y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
		x.Mul(y, x)
		x.Add(parent.Difficulty, x)

		// minimum difficulty can ever be (before exponential factor)
		if x.Cmp(params.MinimumDifficulty) < 0 {
			x.Set(params.MinimumDifficulty)
		}
		// calculate a fake block number for the ice-age delay
		// Specification: https://eips.ethereum.org/EIPS/eip-1234
		fakeBlockNumber := new(big.Int)
		if parent.Number.Cmp(bombDelayFromParent) >= 0 {
			fakeBlockNumber = fakeBlockNumber.Sub(parent.Number, bombDelayFromParent)
		}
		// for the exponential factor
		periodCount := fakeBlockNumber
		periodCount.Div(periodCount, expDiffPeriod)

		// the exponential factor, commonly referred to as "the bomb"
		// diff = diff + 2^(periodCount - 2)
		if periodCount.Cmp(big1) > 0 {
			y.Sub(periodCount, big2)
			y.Exp(big2, y, nil)
			x.Add(x, y)
		}
		return x
	}
}

// calcDifficultyHomestead is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Homestead rules.
func calcDifficultyHomestead(time uint64, parent *types.Header) *big.Int {
	// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	//        ) + 2^(periodCount - 2)

	bigTime := new(big.Int).SetUint64(time)
	bigParentTime := new(big.Int).SetUint64(parent.Time)

	// holds intermediate values to make the algo easier to read & audit
	x := new(big.Int)
	y := new(big.Int)

	// 1 - (block_timestamp - parent_timestamp) // 10
	x.Sub(bigTime, bigParentTime)
	x.Div(x, big10)
	x.Sub(big1, x)

	// max(1 - (block_timestamp - parent_timestamp) // 10, -99)
	if x.Cmp(bigMinus99) < 0 {
		x.Set(bigMinus99)
	}
	// (parent_diff + parent_diff // 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
	x.Mul(y, x)
	x.Add(parent.Difficulty, x)

	// minimum difficulty can ever be (before exponential factor)
	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}
	// for the exponential factor
	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)

	// the exponential factor, commonly referred to as "the bomb"
	// diff = diff + 2^(periodCount - 2)
	if periodCount.Cmp(big1) > 0 {
		y.Sub(periodCount, big2)
		y.Exp(big2, y, nil)
		x.Add(x, y)
	}
	return x
}

// calcDifficultyFrontier is the difficulty adjustment algorithm. It returns the
// difficulty that a new block should have when created at time given the parent
// block's time and difficulty. The calculation uses the Frontier rules.
func calcDifficultyFrontier(time uint64, parent *types.Header) *big.Int {
	diff := new(big.Int)
	adjust := new(big.Int).Div(parent.Difficulty, params.DifficultyBoundDivisor)
	bigTime := new(big.Int)
	bigParentTime := new(big.Int)

	bigTime.SetUint64(time)
	bigParentTime.SetUint64(parent.Time)

	if bigTime.Sub(bigTime, bigParentTime).Cmp(params.DurationLimit) < 0 {
		diff.Add(parent.Difficulty, adjust)
	} else {
		diff.Sub(parent.Difficulty, adjust)
	}
	if diff.Cmp(params.MinimumDifficulty) < 0 {
		diff.Set(params.MinimumDifficulty)
	}

	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)
	if periodCount.Cmp(big1) > 0 {
		// diff = diff + 2^(periodCount - 2)
		expDiff := periodCount.Sub(periodCount, big2)
		expDiff.Exp(big2, expDiff, nil)
		diff.Add(diff, expDiff)
		diff = math.BigMax(diff, params.MinimumDifficulty)
	}
	return diff
}

func calcBaseTarget(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	number := parent.Number.Uint64()
	if number < 4 {
		return new(big.Int).SetUint64(INITIAL_BASE_TARGET)
	} else if number < ADJUST_BLOCK_NUMBER {
		avgBaseTaget := new(big.Int).Set(parent.Difficulty)
		var header *types.Header
		for i := 1; i < 4; i++ {
			header = chain.GetHeaderByNumber(number - uint64(i))
			avgBaseTaget = new(big.Int).Add(avgBaseTaget, header.Difficulty)
		}
		avgBaseTaget = new(big.Int).Div(avgBaseTaget, big.NewInt(4))
		durTime := parent.Time - header.Time
		newTarget := new(big.Int).Div(new(big.Int).Mul(avgBaseTaget, new(big.Int).SetUint64(durTime)), new(big.Int).SetUint64(BLOCK_INTERVAL*4)).Uint64()
		hisTaget := avgBaseTaget.Uint64()
		if newTarget > MAX_BASE_TARGET {
			newTarget = MAX_BASE_TARGET
		}
		if newTarget < hisTaget*9/10 {
			newTarget = hisTaget * 9 / 10
		}
		if newTarget == 0 {
			newTarget = 1
		}

		if newTarget > hisTaget*11/10 {
			newTarget = hisTaget * 11 / 10
		}
		if newTarget > MAX_BASE_TARGET {
			newTarget = MAX_BASE_TARGET
		}
		fmt.Printf("New target diffculty %d\n", newTarget)
		return new(big.Int).SetUint64(newTarget)

	} else {
		avgBaseTaget := new(big.Int).Set(parent.Difficulty)
		var header *types.Header
		for i := 1; i < 24; i++ {
			header = chain.GetHeaderByNumber(number - uint64(i))
			avgBaseTaget = new(big.Int).Add(avgBaseTaget, header.Difficulty)
		}
		avgBaseTaget = new(big.Int).Div(avgBaseTaget, big.NewInt(24))
		durTime := parent.Time - header.Time
		newTarget := new(big.Int).Div(new(big.Int).Mul(avgBaseTaget, new(big.Int).SetUint64(durTime)), new(big.Int).SetUint64(BLOCK_INTERVAL*24)).Uint64()

		hisTaget := avgBaseTaget.Uint64()
		if newTarget > MAX_BASE_TARGET {
			newTarget = MAX_BASE_TARGET
		}

		if newTarget < hisTaget*8/10 {
			newTarget = hisTaget * 8 / 10
		}
		if newTarget == 0 {
			newTarget = 1
		}

		if newTarget > hisTaget*12/10 {
			newTarget = hisTaget * 12 / 10
		}
		if newTarget > MAX_BASE_TARGET {
			newTarget = MAX_BASE_TARGET
		}
		fmt.Printf("New target diffculty %d\n", newTarget)
		return new(big.Int).SetUint64(newTarget)
	}

}

// VerifySeal implements consensus.Engine, checking whether the given block satisfies
// the PoW difficulty requirements.
func (ethPoc *EthPoc) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	genSign := header.MixDigest.Bytes()
	scoop := int(calculateScoop(genSign, number))
	deadLine := calculateDeadline(header.PlotterID, header.Nonce, scoop, genSign, header.Difficulty)
	return ethPoc.verifySeal(chain, parent.Time, deadLine, header, false)
}

// verifySeal checks whether a block satisfies the PoW difficulty requirements,
// either using the usual EthPoc cache for it, or alternatively using a full DAG
// to make remote mining fast.
func (ethPoc *EthPoc) verifySeal(chain consensus.ChainReader, pTime uint64, deadLine *big.Int, header *types.Header, fulldag bool) error {

	if header.Time > deadLine.Uint64()+pTime {
		return nil
	}
	//return nil

	//TODO:checkout nonce
	return errors.New("DeadLine error")
}

func calculateDeadline(plotter uint64, nonce types.BlockNonce, scoop int, newGenSig []byte, baseTarget *big.Int) *big.Int {
	hit := calculateHit(plotter, nonce, scoop, newGenSig)
	return new(big.Int).Div(hit, baseTarget)
}

func calculateGenSign(lastGenSig []byte, lastGenId uint64) []byte {
	baseBuf := make([]byte, HASH_SIZE+8)
	copy(baseBuf[0:HASH_SIZE], lastGenSig)
	binary.BigEndian.PutUint64(baseBuf[HASH_SIZE:HASH_SIZE+8], lastGenId)

	sl := shabal.NewShabal256()
	sl.Write(baseBuf)
	return sl.Sum(nil)
}

func calculateScoop(genSig []byte, number uint64) int64 {
	baseBuf := make([]byte, HASH_SIZE+8)
	copy(baseBuf[0:HASH_SIZE], genSig)
	binary.BigEndian.PutUint64(baseBuf[HASH_SIZE:], number)

	sl := shabal.NewShabal256()
	sl.Write(baseBuf)
	hash := sl.Sum(nil)

	return new(big.Int).Mod(new(big.Int).SetBytes(hash), big.NewInt(int64(SCOOPS_PER_PLOT))).Int64()
}

func calculateHit(plotter uint64, nonce types.BlockNonce, scoop int, newGenSig []byte) *big.Int {
	data := miningPlot(plotter, nonce)
	sl := shabal.NewShabal256()
	sl.Write(newGenSig)
	sl.Write(data[scoop*SCOOP_SIZE : scoop*SCOOP_SIZE+SCOOP_SIZE])
	hash := sl.Sum(nil)

	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		copy(b[i:], hash[7-i:7-i+1])
	}

	return new(big.Int).SetBytes(b)
}

func miningPlot(plotter uint64, nonce types.BlockNonce) []byte {
	baseBuf := make([]byte, 16)
	binary.BigEndian.PutUint64(baseBuf[0:8], plotter)
	binary.BigEndian.PutUint64(baseBuf[8:16], nonce.Uint64())

	sl := shabal.NewShabal256()

	plotBuf := make([]byte, PLOT_SIZE+len(baseBuf))
	copy(plotBuf[PLOT_SIZE:], baseBuf[0:])
	for i := PLOT_SIZE; i > 0; i -= HASH_SIZE {
		index := PLOT_SIZE + len(baseBuf) - i
		if index > HASH_CAP {
			index = HASH_CAP
		}
		sl.Write(plotBuf[i : i+index])
		copy(plotBuf[i-HASH_SIZE:i], sl.Sum(nil))
	}

	sl.Write(plotBuf)
	finalHash := sl.Sum(nil)

	data := make([]byte, PLOT_SIZE)
	for i := 0; i < PLOT_SIZE; i++ {
		data[i] = (byte)(plotBuf[i] ^ finalHash[i%HASH_SIZE])
	}

	hashBuffer := make([]byte, HASH_SIZE)
	revPos := PLOT_SIZE - HASH_SIZE
	for pos := 32; pos < (PLOT_SIZE / 2); pos += 64 {
		copy(hashBuffer, data[pos:pos+HASH_SIZE])
		copy(data[pos:pos+HASH_SIZE], data[revPos:revPos+HASH_SIZE])
		copy(data[revPos:revPos+HASH_SIZE], hashBuffer[0:HASH_SIZE])
		revPos -= 64 //move backwards
	}
	return data
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the EthPoc protocol. The changes are done inline.
func (ethPoc *EthPoc) Prepare(chain consensus.ChainReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	hash := calculateGenSign(parent.MixDigest.Bytes(), header.PlotterID)
	header.MixDigest = common.BytesToHash(hash)
	header.Difficulty = ethPoc.CalcDifficulty(chain, header.Time, parent)
	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (ethPoc *EthPoc) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) {
	// Accumulate any block and uncle rewards and commit the final state root
	accumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}


// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (ethPoc *EthPoc) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	accumulateRewards(chain.Config(), state, header, uncles)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts), nil
}


// SealHash returns the hash of a block prior to it being sealed.
func (ethPoc *EthPoc) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Extra,
	})
	hasher.Sum(hash[:0])
	return hash
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	//TODO:change reward
	if len(uncles) > 0 {
		return
	}
	// Select the correct block reward based on chain progression
	initReward := FrontierBlockReward
	rewardYears := new(big.Int).Div(header.Number, new(big.Int).SetUint64(EACH_NUMBER_OF_4YEAR))

	if rewardYears.Uint64() > 33 {
		return
	}
	blockReward := new(big.Int).Div(initReward, new(big.Int).Exp(big.NewInt(2), rewardYears, big.NewInt(0)))
	state.AddBalance(header.Coinbase, blockReward)
}
