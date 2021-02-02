package neutrinoclient

import (
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	w "github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/headerfs"
)

// NeutrinoClient is an implementation of the btcwalet chain.Interface interface.
type NeutrinoClient struct {
	CS *neutrino.ChainService

	wallet *w.Wallet

	chainParams *chaincfg.Params

	// We currently support one rescan/notifiction goroutine per client
	rescan *neutrino.Rescan

	// Holds all potential callbacks used to notify clients
	notifications           Notifications
	walletSynced            bool
	rescanning              bool
	lastFilteredBlockHeader *wire.BlockHeader
	scanStartBlock          waddrmgr.BlockStamp
	scanEndBlock            headerfs.BlockStamp
	currentBlock            *waddrmgr.BlockStamp

	quit       chan struct{}
	rescanQuit chan struct{}
	rescanErr  <-chan error
	wg         sync.WaitGroup
	started    bool

	clientMtx       sync.Mutex
	notificationsMu sync.Mutex
}

type Notifications interface {
	Synced()
	RescanStarted()
	RescanProgress(rescannedThrough int32)
	RescanFinished()
}

// NewNeutrinoClient creates a new NeutrinoClient struct with a backing
// ChainService.
func NewNeutrinoClient(wallet *w.Wallet, chainParams *chaincfg.Params,
	chainService *neutrino.ChainService) *NeutrinoClient {

	return &NeutrinoClient{
		CS:          chainService,
		wallet:      wallet,
		chainParams: chainParams,
	}
}

func (s *NeutrinoClient) synced() {
	go func() {
		s.notificationsMu.Lock()
		if s.notifications != nil {
			s.notifications.Synced()
		}
		s.notificationsMu.Unlock()
	}()
}

func (s *NeutrinoClient) rescanStart() {
	go func() {
		s.notificationsMu.Lock()
		if s.notifications != nil {
			s.notifications.RescanStarted()
		}
		s.notificationsMu.Unlock()
	}()
}

func (s *NeutrinoClient) rescanProgress(rescannedThrough int32) {
	go func() {
		s.notificationsMu.Lock()
		if s.notifications != nil {
			s.notifications.RescanProgress(rescannedThrough)
		}
		s.notificationsMu.Unlock()
	}()
}

func (s *NeutrinoClient) rescanFinished() {
	go func() {
		s.notificationsMu.Lock()
		if s.notifications != nil {
			s.notifications.RescanFinished()
		}
		s.notificationsMu.Unlock()
	}()
}

// SetNotifications sets the possible various callbacks that are used
// to notify interested parties to the syncing progress.
func (s *NeutrinoClient) SetNotifications(ntfns Notifications) {
	s.notificationsMu.Lock()
	s.notifications = ntfns
	s.notificationsMu.Unlock()
}

// BackEnd returns the name of the driver.
func (s *NeutrinoClient) BackEnd() string {
	return "neutrino"
}

// Start replicates the RPC client's Start method.
func (s *NeutrinoClient) Start() error {
	s.CS.Start()
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	if !s.started {
		s.currentBlock = nil
		s.quit = make(chan struct{})
		s.started = true
		s.wg.Add(1)
	}
	return nil
}

// Stop replicates the RPC client's Stop method.
func (s *NeutrinoClient) Stop() {
	s.clientMtx.Lock()
	if !s.started {
		s.clientMtx.Unlock()
		return
	}
	s.clientMtx.Unlock()
	close(s.quit)
	s.clientMtx.Lock()
	s.started = false
	s.clientMtx.Unlock()
}

// WaitForShutdown replicates the RPC client's WaitForShutdown method.
func (s *NeutrinoClient) WaitForShutdown() {
	s.wg.Wait()
}

func (s *NeutrinoClient) IsRescanning() bool {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()

	return s.rescanning
}

func (s *NeutrinoClient) StartupSync() error {
	birthdayStamp, err := s.wallet.BirthdayBlock()
	if err != nil {
		return err
	}

	bestBlock, err := s.CS.BestBlock()
	if err != nil {
		return fmt.Errorf("can't get chain service's best block: %s", err)
	}

	err = s.wallet.RollbackMissingBlocks(birthdayStamp)
	if err != nil {
		return err
	}

	s.clientMtx.Lock()

	s.scanStartBlock = s.wallet.Manager.SyncedTo()
	s.scanEndBlock = *bestBlock
	s.walletSynced = false
	s.rescanning = false
	s.lastFilteredBlockHeader = nil
	s.rescanQuit = make(chan struct{})
	s.clientMtx.Unlock()

	endBlockHeader, err := s.CS.GetBlockHeader(&s.scanEndBlock.Hash)
	if err != nil {
		return fmt.Errorf("can't get block header for hash %v: %s",
			bestBlock.Hash, err)
	}

	s.clientMtx.Lock()
	s.currentBlock = &waddrmgr.BlockStamp{Height: bestBlock.Height, Hash: endBlockHeader.BlockHash(), Timestamp: endBlockHeader.Timestamp}
	log.Infof("Sync starting Start height: %d, End: %d, Bestblock: %d", s.scanStartBlock.Height, s.scanEndBlock.Height, bestBlock.Height)
	s.clientMtx.Unlock()

	if endBlockHeader.BlockHash() == s.scanStartBlock.Hash {
		log.Info("Start hash and end hash is equal, quiting rescan")

		s.wallet.SetChainSynced(true)

		s.clientMtx.Lock()
		s.walletSynced = true
		s.clientMtx.Unlock()

		s.rescanFinished()
		s.synced()

		log.Info("Dispatched rescan finished/synced notification")
		// listen for headers
	}

	addrs, outpoints, err := s.wallet.ActiveData()
	if err != nil {
		return err
	}

	var inputsToWatch []neutrino.InputWithScript
	for op, addr := range outpoints {
		addrScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}

		inputsToWatch = append(inputsToWatch, neutrino.InputWithScript{
			OutPoint: op,
			PkScript: addrScript,
		})
	}

	s.clientMtx.Lock()
	newRescan := neutrino.NewRescan(
		&neutrino.RescanChainSource{
			ChainService: s.CS,
		},

		neutrino.NotificationHandlers(rpcclient.NotificationHandlers{
			OnBlockConnected:         s.onBlockConnected,
			OnFilteredBlockConnected: s.onFilteredBlockConnected,
			OnBlockDisconnected:      s.onBlockDisconnected,
		}),

		neutrino.StartBlock(&headerfs.BlockStamp{Hash: s.scanStartBlock.Hash}),
		neutrino.StartTime(s.scanStartBlock.Timestamp),
		neutrino.QuitChan(s.rescanQuit),
		neutrino.WatchAddrs(addrs...),
		neutrino.WatchInputs(inputsToWatch...),
	)

	s.rescan = newRescan
	s.rescanErr = s.rescan.Start()
	s.clientMtx.Unlock()
	s.rescanStart()

	return nil
}

// GetBlock replicates the RPC client's GetBlock command.
func (s *NeutrinoClient) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	// TODO(roasbeef): add a block cache?
	//  * which evication strategy? depends on use case
	//  Should the block cache be INSIDE neutrino instead of in btcwallet?
	block, err := s.CS.GetBlock(*hash)
	if err != nil {
		return nil, err
	}
	return block.MsgBlock(), nil
}

// GetBlockHeight gets the height of a block by its hash. It serves as a
// replacement for the use of GetBlockVerboseTxAsync for the wallet package
// since we can't actually return a FutureGetBlockVerboseResult because the
// underlying type is private to rpcclient.
func (s *NeutrinoClient) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	return s.CS.GetBlockHeight(hash)
}

// GetBestBlock replicates the RPC client's GetBestBlock command.
func (s *NeutrinoClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	chainTip, err := s.CS.BestBlock()
	if err != nil {
		return nil, 0, err
	}

	return &chainTip.Hash, chainTip.Height, nil
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (s *NeutrinoClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	return s.currentBlock, nil
}

// GetBlockHash returns the block hash for the given height, or an error if the
// client has been shut down or the hash at the block height doesn't exist or
// is unknown.
func (s *NeutrinoClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	return s.CS.GetBlockHash(height)
}

// GetBlockHeader returns the block header for the given block hash, or an error
// if the client has been shut down or the hash doesn't exist or is unknown.
func (s *NeutrinoClient) GetBlockHeader(
	blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return s.CS.GetBlockHeader(blockHash)
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (s *NeutrinoClient) IsCurrent() bool {
	return s.CS.IsCurrent()
}

// SendRawTransaction replicates the RPC client's SendRawTransaction command.
func (s *NeutrinoClient) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (
	*chainhash.Hash, error) {
	err := s.CS.SendTransaction(tx)
	if err != nil {
		return nil, err
	}
	hash := tx.TxHash()
	return &hash, nil
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. For each requested block, the corresponding compact
// filter will first be checked for matches, skipping those that do not report
// anything. If the filter returns a positive match, the full block will be
// fetched and filtered. This method returns a FilterBlocksReponse for the first
// block containing a matching address. If no matches are found in the range of
// blocks requested, the returned response will be nil.
func (s *NeutrinoClient) FilterBlocks(
	req *chain.FilterBlocksRequest) (*chain.FilterBlocksResponse, error) {

	blockFilterer := chain.NewBlockFilterer(s.chainParams, req)

	// Construct the watchlist using the addresses and outpoints contained
	// in the filter blocks request.
	watchList, err := chain.BuildFilterBlocksWatchList(req)
	if err != nil {
		return nil, err
	}

	// Iterate over the requested blocks, fetching the compact filter for
	// each one, and matching it against the watchlist generated above. If
	// the filter returns a positive match, the full block is then requested
	// and scanned for addresses using the block filterer.
	for i, blk := range req.Blocks {
		filter, err := s.pollCFilter(&blk.Hash)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter == nil || filter.N() == 0 {
			continue
		}

		key := builder.DeriveKey(&blk.Hash)
		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, err
		} else if !matched {
			continue
		}

		log.Infof("Fetching block height=%d hash=%v",
			blk.Height, blk.Hash)

		// TODO(conner): can optimize bandwidth by only fetching
		// stripped blocks
		rawBlock, err := s.GetBlock(&blk.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &chain.FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          blk,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

// pollCFilter attempts to fetch a CFilter from the neutrino client. This is
// used to get around the fact that the filter headers may lag behind the
// highest known block header.
func (s *NeutrinoClient) pollCFilter(hash *chainhash.Hash) (*gcs.Filter, error) {
	var (
		filter *gcs.Filter
		err    error
		count  int
	)

	const maxFilterRetries = 50
	for count < maxFilterRetries {
		if count > 0 {
			time.Sleep(100 * time.Millisecond)
		}

		filter, err = s.CS.GetCFilter(*hash, wire.GCSFilterRegular)
		if err != nil {
			count++
			continue
		}

		return filter, nil
	}

	return nil, err
}

// Rescan replicates the RPC client's Rescan command.
func (s *NeutrinoClient) Rescan(startHeight int64) error {

	s.clientMtx.Lock()
	if !s.started {
		s.clientMtx.Unlock()
		return fmt.Errorf("can't do a rescan when the chain client " +
			"is not started")
	}

	if s.rescan != nil {
		log.Info("Killing current rescan to start another")
		// Restart the rescan by killing the existing rescan.
		rescan := s.rescan

		s.clientMtx.Unlock()
		close(s.rescanQuit)

		log.Info("Waiting for rescan to shutdown")
		rescan.WaitForShutdown()
		log.Info("Rescan shutdown successful")

		s.clientMtx.Lock()
		s.rescan = nil
		s.rescanErr = nil

	}

	s.rescanQuit = make(chan struct{})
	s.lastFilteredBlockHeader = nil
	s.clientMtx.Unlock()

	bestBlock, err := s.CS.BestBlock()
	if err != nil {
		return fmt.Errorf("can't get chain service's best block: %s", err)
	}

	startBlockHash, err := s.GetBlockHash(startHeight)
	if err != nil {
		return fmt.Errorf("unable to get start block hash: %s", err)
	}

	startBlock, err := s.GetBlockHeader(startBlockHash)
	if err != nil {
		return fmt.Errorf("unable to get start block: %s", err)
	}

	startBlockStamp := waddrmgr.BlockStamp{
		Height:    int32(startHeight),
		Hash:      *startBlockHash,
		Timestamp: startBlock.Timestamp,
	}

	s.clientMtx.Lock()
	s.scanStartBlock = startBlockStamp
	s.scanEndBlock = *bestBlock
	s.clientMtx.Unlock()

	log.Infof("Rescan starting Start height: %d, Bestblock height: %d", startBlockStamp.Height, bestBlock.Hash)
	// If the wallet is already fully caught up, or the rescan has started
	// with state that indicates a "fresh" wallet, we'll send a
	// notification indicating the rescan has "finished".
	if bestBlock.Height == startBlockStamp.Height {
		log.Info("rescan Start height and end height is equal")
		s.rescanFinished()
	}

	addrs, outpoints, err := s.wallet.ActiveData()
	if err != nil {
		return err
	}

	var inputsToWatch []neutrino.InputWithScript
	for op, addr := range outpoints {
		addrScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return err
		}

		inputsToWatch = append(inputsToWatch, neutrino.InputWithScript{
			OutPoint: op,
			PkScript: addrScript,
		})
	}

	s.clientMtx.Lock()
	newRescan := neutrino.NewRescan(
		&neutrino.RescanChainSource{
			ChainService: s.CS,
		},
		neutrino.NotificationHandlers(rpcclient.NotificationHandlers{
			OnBlockConnected:         s.onBlockConnected,
			OnFilteredBlockConnected: s.onFilteredBlockConnected,
			OnBlockDisconnected:      s.onBlockDisconnected,
		}),
		neutrino.StartBlock(&headerfs.BlockStamp{Hash: *startBlockHash}),
		neutrino.StartTime(startBlockStamp.Timestamp),
		neutrino.QuitChan(s.rescanQuit),
		neutrino.WatchAddrs(addrs...),
		neutrino.WatchInputs(inputsToWatch...),
	)
	s.rescan = newRescan
	s.rescanning = true
	s.rescanErr = s.rescan.Start()
	s.clientMtx.Unlock()

	return nil
}

func (s *NeutrinoClient) Notifications() <-chan interface{} {
	return nil
}

// NotifyBlocks replicates the RPC client's NotifyBlocks command.
func (s *NeutrinoClient) NotifyBlocks() error {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()
	// If we're synced, we're already notifying on blocks. Otherwise,
	// start a rescan without watching any addresses.
	if !s.walletSynced {
		return fmt.Errorf("wallet not synced")
	}

	return nil
}

// NotifyReceived replicates the RPC client's NotifyReceived command.
func (s *NeutrinoClient) NotifyReceived(addrs []btcutil.Address) error {
	s.clientMtx.Lock()
	defer s.clientMtx.Unlock()

	// If we have a rescan running, we just need to add the appropriate
	// addresses to the watch list.
	if s.walletSynced {
		return s.rescan.Update(neutrino.AddAddrs(addrs...))
	}

	return fmt.Errorf("wallet not synced")
}

// onFilteredBlockConnected sends appropriate notifications to the notification
// channel.
func (s *NeutrinoClient) onFilteredBlockConnected(height int32, header *wire.BlockHeader, relevantTxs []*btcutil.Tx) {

	blockMeta := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   header.BlockHash(),
			Height: height,
		},
		Time: header.Timestamp,
	}

	for _, tx := range relevantTxs {
		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx.MsgTx(),
			header.Timestamp)
		if err != nil {
			log.Errorf("cannot create transaction record for "+
				"relevant tx: %s", err)
			continue
		}

		err = s.wallet.AddRelevantTx(rec, blockMeta)
		if err != nil {
			log.Errorf("cannot add relevant tx: %s", err)
			continue
		}
	}

	s.clientMtx.Lock()
	s.lastFilteredBlockHeader = header
	s.currentBlock = &waddrmgr.BlockStamp{Height: height, Hash: header.BlockHash(), Timestamp: header.Timestamp}
	s.clientMtx.Unlock()
}

// onBlockDisconnected sends appropriate notifications to the notification
// channel.
func (s *NeutrinoClient) onBlockDisconnected(hash *chainhash.Hash, height int32, t time.Time) {
	blockMeta := chain.BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: t,
	}
	err := s.wallet.DisconnectBlock(wtxmgr.BlockMeta(blockMeta))
	if err != nil {
		log.Error(err)
	}
}

func (s *NeutrinoClient) onBlockConnected(hash *chainhash.Hash, height int32, blockTime time.Time) {
	sendRescanProgress := func() {
		err := s.wallet.CatchUpHashes(height)
		if err != nil {
			log.Errorf("Error catching up hashes: %v", err)
		}

		if height%1000 == 0 {
			log.Info("Rescanned to block:", height)
			s.rescanProgress(height)
		}
	}
	s.clientMtx.Lock()
	if height < s.scanEndBlock.Height {
		s.clientMtx.Unlock()
		sendRescanProgress()
	} else {

		if !s.walletSynced || s.rescanning {

			sendRescanProgress()

			log.Info("Wallet is synced")

			s.wallet.SetChainSynced(true)
			s.walletSynced = true
			s.rescanning = false

			s.rescanFinished()
			s.synced()

			log.Info("Dispatched rescan finished and synced notification")
		}
		s.clientMtx.Unlock()

		log.Info("Block connected:", height)
		blockMeta := wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: blockTime,
		}

		err := s.wallet.ConnectBlock(blockMeta)
		if err != nil {
			log.Errorf("Error connecting: %v", err)
		}
	}
}
