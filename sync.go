package btclibwallet

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/decred/dcrwallet/errors/v2"
	"github.com/lightninglabs/neutrino"
	"golang.org/x/sync/errgroup"
)

// reading/writing of properties of this struct are protected by mutex.x
type syncData struct {
	mu sync.RWMutex

	syncProgressListeners map[string]SyncProgressListener
	showLogs              bool

	synced       bool
	syncing      bool
	chainClient  chain.Interface
	syncCanceled chan struct{}

	// Flag to notify syncCanceled callback if the sync was canceled so as to be restarted.
	restartSyncRequested bool

	rescanning     bool
	connectedPeers int32

	*activeSyncData
}

// reading/writing of properties of this struct are protected by syncData.mu.
type activeSyncData struct {
	syncStage int32

	cFiltersFetchProgress CFiltersFetchProgressReport

	beginFetchTimeStamp    int64
	startCFiltersHeight    int32
	cFiltersFetchTimeSpent int64

	rescanStartTime int64

	totalInactiveSeconds int64
}

const (
	InvalidSyncStage       = -1
	CFiltersFetchSyncStage = 0
	HeadersRescanSyncStage = 2
)

func (mw *MultiWallet) initActiveSyncData() {
	mw.syncData.mu.Lock()

	cFiltersFetchProgress := CFiltersFetchProgressReport{}
	cFiltersFetchProgress.GeneralSyncProgress = &GeneralSyncProgress{}

	mw.syncData.activeSyncData = &activeSyncData{
		syncStage: InvalidSyncStage,

		cFiltersFetchProgress: cFiltersFetchProgress,

		beginFetchTimeStamp:    -1,
		cFiltersFetchTimeSpent: -1,
	}
	mw.syncData.mu.Unlock()
}

func (mw *MultiWallet) IsSyncProgressListenerRegisteredFor(uniqueIdentifier string) bool {
	mw.syncData.mu.RLock()
	_, exists := mw.syncData.syncProgressListeners[uniqueIdentifier]
	mw.syncData.mu.RUnlock()
	return exists
}

func (mw *MultiWallet) AddSyncProgressListener(syncProgressListener SyncProgressListener, uniqueIdentifier string) error {
	if mw.IsSyncProgressListenerRegisteredFor(uniqueIdentifier) {
		return errors.New(ErrListenerAlreadyExist)
	}

	mw.syncData.mu.Lock()
	mw.syncData.syncProgressListeners[uniqueIdentifier] = syncProgressListener
	mw.syncData.mu.Unlock()

	// If sync is already on, notify this newly added listener of the current progress report.
	return mw.PublishLastSyncProgress(uniqueIdentifier)
}

func (mw *MultiWallet) RemoveSyncProgressListener(uniqueIdentifier string) {
	mw.syncData.mu.Lock()
	delete(mw.syncData.syncProgressListeners, uniqueIdentifier)
	mw.syncData.mu.Unlock()
}

func (mw *MultiWallet) syncProgressListeners() []SyncProgressListener {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()

	listeners := make([]SyncProgressListener, 0, len(mw.syncData.syncProgressListeners))
	for _, listener := range mw.syncData.syncProgressListeners {
		listeners = append(listeners, listener)
	}

	return listeners
}

func (mw *MultiWallet) PublishLastSyncProgress(uniqueIdentifier string) error {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()

	syncProgressListener, exists := mw.syncData.syncProgressListeners[uniqueIdentifier]
	if !exists {
		return errors.New(ErrInvalid)
	}

	if mw.syncData.syncing && mw.syncData.activeSyncData != nil {
		switch mw.syncData.activeSyncData.syncStage {
		case CFiltersFetchSyncStage:
			syncProgressListener.OnCFiltersFetchProgress(&mw.syncData.cFiltersFetchProgress)
		}
	}

	return nil
}

func (mw *MultiWallet) EnableSyncLogs() {
	mw.syncData.mu.Lock()
	mw.syncData.showLogs = true
	mw.syncData.mu.Unlock()
}

func (mw *MultiWallet) SyncInactiveForPeriod(totalInactiveSeconds int64) {
	mw.syncData.mu.Lock()
	defer mw.syncData.mu.Unlock()

	if !mw.syncData.syncing || mw.syncData.activeSyncData == nil {
		log.Debug("Not accounting for inactive time, wallet is not syncing.")
		return
	}

	mw.syncData.totalInactiveSeconds += totalInactiveSeconds
	if mw.syncData.connectedPeers == 0 {
		// assume it would take another 60 seconds to reconnect to peers
		mw.syncData.totalInactiveSeconds += 60
	}
}

func (mw *MultiWallet) SpvSync() error {
	// prevent an attempt to sync when the previous syncing has not been canceled
	if mw.IsSyncing() || mw.IsSynced() {
		return errors.New(ErrSyncAlreadyInProgress)
	}

	var validPeerAddresses []string
	peerAddresses := mw.ReadStringConfigValueForKey(SpvPersistentPeerAddressesConfigKey)
	if peerAddresses != "" {
		addresses := strings.Split(peerAddresses, ";")
		for _, address := range addresses {
			peerAddress, err := NormalizeAddress(address, mw.chainParams.DefaultPort)
			if err != nil {
				log.Errorf("SPV peer address(%s) is invalid: %v", peerAddress, err)
			} else {
				validPeerAddresses = append(validPeerAddresses, peerAddress)
			}
		}

		if len(validPeerAddresses) == 0 {
			return errors.New(ErrInvalidPeers)
		}
	}

	// init activeSyncData to be used to hold data used
	// to calculate sync estimates only during sync
	mw.initActiveSyncData()

	wallet := mw.wallets[1]
	wallet.waiting = true
	wallet.syncing = true

	go func() {
		neutrino.MaxPeers = neutrino.MaxPeers
		neutrino.BanDuration = neutrino.BanDuration
		neutrino.BanThreshold = neutrino.BanThreshold

		var (
			chainService *neutrino.ChainService
			spvdb        walletdb.DB
		)
		spvdb, err := walletdb.Create("bdb",
			filepath.Join(mw.rootDir, "neutrino.db"), true)
		defer spvdb.Close()
		if err != nil {
			log.Errorf("Unable to create Neutrino DB: %s", err)
			return
		}

		chainService, err = neutrino.NewChainService(
			neutrino.Config{
				DataDir:      mw.rootDir,
				Database:     spvdb,
				ChainParams:  *mw.chainParams,
				ConnectPeers: validPeerAddresses,
				AddPeers:     []string{}, //TODO
			}, mw.spvSyncNotificationCallbacks())
		if err != nil {
			log.Errorf("Couldn't create Neutrino ChainService: %s", err)
			return
		}

		log.Info("Starting spv")
		chainClient := chain.NewNeutrinoClient(mw.chainParams, chainService)
		err = chainClient.Start()
		if err != nil {
			log.Errorf("Couldn't start Neutrino client: %s", err)
			return
		}

		wallet.internal.SynchronizeRPC(chainClient)

		mw.setNetworkBackend(chainClient)
		go mw.registerNotifications()
		if err = chainClient.NotifyBlocks(); err != nil {
			log.Error("Notification error", err)
		}

		var restartSyncRequested bool

		mw.syncData.mu.Lock()
		restartSyncRequested = mw.syncData.restartSyncRequested
		mw.syncData.restartSyncRequested = false
		mw.syncData.syncing = true
		mw.syncData.syncCanceled = make(chan struct{})
		mw.syncData.mu.Unlock()

		log.Info("Sync started broadcasting")
		for _, listener := range mw.syncProgressListeners() {
			listener.OnSyncStarted(restartSyncRequested)
		}

		chainClient.WaitForShutdown()
		log.Info("Chainclient stopped")
		close(mw.syncData.syncCanceled)

		mw.resetSyncData()
	}()
	return nil
}

func (mw *MultiWallet) registerNotifications() {
	for {
		select {
		case n, ok := <-mw.chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			switch n := n.(type) {
			case chain.ClientConnected:
				notificationName = "client connected"
			case chain.BlockConnected:
				notificationName = "block connected"
				continue
			case chain.BlockDisconnected:
				notificationName = "block disconnected"
			case chain.RelevantTx:
				notificationName = "relevant transaction"
			case chain.FilteredBlockConnected:
				notificationName = "filtered block connected"
				continue
			case *chain.RescanProgress:

				wallet := mw.WalletWithID(1)

				_, bestBlock, _ := mw.chainClient.GetBestBlock()

				rescanProgressReport := &RescanProgressReport{
					TotalHeadersToScan:  bestBlock,
					CurrentRescanHeight: n.Height,
					RescanProgress:      (n.Height / bestBlock) * 100,
				}

				for _, syncProgressListener := range mw.syncProgressListeners() {
					syncProgressListener.OnRescanProgress(rescanProgressReport)
				}

				notificationName = fmt.Sprintf("rescan progress %d of %d, Synced: %v, Syncing: %v",
					n.Height, bestBlock, wallet.internal.ChainSynced(), wallet.internal.SynchronizingToNetwork())

			case *chain.RescanFinished:

				notificationName = "Rescan done"
				mw.synced()

				wallet := mw.WalletWithID(1)
				balance, err := wallet.GetAccountBalance(0)
				if err != nil {
					log.Errorf("Error acccount balance: %v", err)
				} else {
					notificationName += fmt.Sprintf("\nNNNAddress: %s, Balance: %d", "", btcutil.Amount(balance.Total))
				}

				notificationName += fmt.Sprintf("\nrescan finished Synced: %v", wallet.internal.ChainSynced())
			}

			log.Info("Notication type:", notificationName)
		case <-mw.syncData.syncCanceled:
			log.Info("Sync cancelled")
			return
		}
	}
}

func (mw *MultiWallet) RestartSpvSync() error {
	mw.syncData.mu.Lock()
	mw.syncData.restartSyncRequested = true
	mw.syncData.mu.Unlock()

	mw.CancelSync() // necessary to unset the network backend.
	return mw.SpvSync()
}

func (mw *MultiWallet) CancelSync() {
	mw.syncData.mu.RLock()
	chainClient := mw.syncData.chainClient
	mw.syncData.mu.RUnlock()

	if chainClient != nil {
		log.Info("Canceling sync. May take a while for sync to fully cancel.")

		chainClient.Stop()

		// When sync terminates and syncer.Run returns `err == context.Canceled`,
		// we will get notified on this channel.
		<-mw.syncData.syncCanceled

		log.Info("Sync fully canceled.")
	}

	mw.setNetworkBackend(nil)
	for _, syncProgressListener := range mw.syncProgressListeners() {
		syncProgressListener.OnSyncCanceled(false)
	}
}

func (mw *MultiWallet) resetSyncData() {

	mw.syncData.mu.Lock()
	mw.syncData.syncing = false
	mw.syncData.synced = false
	mw.syncData.syncCanceled = nil
	mw.syncData.activeSyncData = nil
	mw.syncData.mu.Unlock()

	for _, wallet := range mw.wallets {
		wallet.waiting = true
		wallet.LockWallet() // lock wallet if previously unlocked to perform account discovery.
	}
}

func (mw *MultiWallet) synced() {

	wallet := mw.wallets[1]
	wallet.syncing = false
	mw.listenForTransactions(wallet.ID)
	log.Info("Synced")

	mw.syncData.mu.Lock()
	mw.syncData.syncing = false
	mw.syncData.synced = true
	mw.syncData.mu.Unlock()

	// begin indexing transactions after sync is completed,
	// syncProgressListeners.OnSynced() will be invoked after transactions are indexed
	var txIndexing errgroup.Group
	txIndexing.Go(wallet.IndexTransactions)

	go func() {
		err := txIndexing.Wait()
		if err != nil {
			log.Errorf("Tx Index Error: %v", err)
		}

		for _, syncProgressListener := range mw.syncProgressListeners() {
			syncProgressListener.OnSyncCompleted()
		}
	}()
}

func (wallet *Wallet) Rescan() error {
	if wallet.internal.ChainClient != nil {

		accounts, err := wallet.GetAccountsRaw()
		if err != nil {
			return err
		}

		var accountAddresses []btcutil.Address
		for _, account := range accounts.Acc {
			addrs, err := wallet.internal.AccountAddresses(uint32(account.Number))
			if err != nil {
				return err
			}

			accountAddresses = append(accountAddresses, addrs...)
		}

		log.Infof("Starting rescan with %d address froom %d account", len(accountAddresses), len(accounts.Acc))
		go func() {
			err = wallet.internal.Rescan(accountAddresses, []wtxmgr.Credit{})
			if err != nil {
				log.Error(err)
			}
		}()

		return nil
	}

	return fmt.Errorf(ErrNotConnected)
}

func (wallet *Wallet) IsWaiting() bool {
	return wallet.waiting
}

func (wallet *Wallet) IsSynced() bool {
	chainClient := wallet.internal.ChainClient()
	if chainClient == nil {
		log.Info("Chain client nil")
		return false
	}

	// Grab the best chain state the wallet is currently aware of.
	syncState := wallet.internal.Manager.SyncedTo()

	// Next, query the chain backend to grab the info about the tip of the
	// main chain.
	bestHash, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		log.Error(err)
		return false
	}

	// If the wallet hasn't yet fully synced to the node's best chain tip,
	// then we're not yet fully synced.
	if syncState.Height < bestHeight || !wallet.internal.ChainSynced() {
		// log.Infof("Wallet Not Synced: %v, %d < %d", wallet.internal.ChainSynced(), syncState.Height, bestHeight)
		return false
	}

	// If the wallet is on par with the current best chain tip, then we
	// still may not yet be synced as the chain backend may still be
	// catching up to the main chain. So we'll grab the block header in
	// order to make a guess based on the current time stamp.
	blockHeader, err := chainClient.GetBlockHeader(bestHash)
	if err != nil {
		log.Error(err)
		return false
	}

	// If the timestamp on the best header is more than 2 hours in the
	// past, then we're not yet synced.
	minus24Hours := time.Now().Add(-2 * time.Hour)
	if blockHeader.Timestamp.Before(minus24Hours) {
		log.Info("Low timestamp")
		return false
	}

	return true
}

func (wallet *Wallet) IsSyncing() bool {
	return wallet.syncing
}

func (mw *MultiWallet) IsConnectedToDecredNetwork() bool {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()
	return mw.syncData.syncing || mw.syncData.synced
}

func (mw *MultiWallet) IsSynced() bool {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()
	return mw.syncData.synced
}

func (mw *MultiWallet) IsSyncing() bool {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()
	return mw.syncData.syncing
}

func (mw *MultiWallet) CurrentSyncStage() int32 {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()

	if mw.syncData != nil && mw.syncData.syncing {
		return mw.syncData.syncStage
	}
	return InvalidSyncStage
}

func (mw *MultiWallet) ConnectedPeers() int32 {
	mw.syncData.mu.RLock()
	defer mw.syncData.mu.RUnlock()
	return mw.syncData.connectedPeers
}

func (mw *MultiWallet) GetBestBlock() *BlockInfo {
	var bestBlock int32 = -1
	var blockInfo *BlockInfo
	for _, wallet := range mw.wallets {
		if !wallet.WalletOpened() {
			continue
		}

		walletBestBLock := wallet.GetBestBlock()
		if walletBestBLock > bestBlock || bestBlock == -1 {
			bestBlock = walletBestBLock
			blockInfo = &BlockInfo{Height: bestBlock, Timestamp: wallet.GetBestBlockTimeStamp()}
		}
	}

	return blockInfo
}

func (mw *MultiWallet) GetLowestBlock() *BlockInfo {
	var lowestBlock int32 = -1
	var blockInfo *BlockInfo
	for _, wallet := range mw.wallets {
		if !wallet.WalletOpened() {
			continue
		}
		walletBestBLock := wallet.GetBestBlock()
		if walletBestBLock < lowestBlock || lowestBlock == -1 {
			lowestBlock = walletBestBLock
			blockInfo = &BlockInfo{Height: lowestBlock, Timestamp: wallet.GetBestBlockTimeStamp()}
		}
	}

	return blockInfo
}

func (wallet *Wallet) GetBestBlock() int32 {
	if wallet.internal == nil {
		// This method is sometimes called after a wallet is deleted and causes crash.
		log.Error("Attempting to read best block height without a loaded wallet.")
		return 0
	}

	blk := wallet.internal.Manager.SyncedTo()
	return blk.Height
}

func (wallet *Wallet) GetBestBlockTimeStamp() int64 {
	if wallet.internal == nil {
		// This method is sometimes called after a wallet is deleted and causes crash.
		log.Error("Attempting to read best block timestamp without a loaded wallet.")
		return 0
	}

	blk := wallet.internal.Manager.SyncedTo()
	return blk.Timestamp.UnixNano() / int64(time.Millisecond)
}

func (mw *MultiWallet) GetLowestBlockTimestamp() int64 {
	var timestamp int64 = -1
	for _, wallet := range mw.wallets {
		bestBlockTimestamp := wallet.GetBestBlockTimeStamp()
		if bestBlockTimestamp < timestamp || timestamp == -1 {
			timestamp = bestBlockTimestamp
		}
	}
	return timestamp
}
