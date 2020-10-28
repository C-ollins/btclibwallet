package btclibwallet

import (
	"context"
	"os"
	"path/filepath"

	"github.com/asdine/storm"
	"github.com/btcsuite/btcwallet/chain"
	w "github.com/btcsuite/btcwallet/wallet"
	"github.com/decred/dcrwallet/errors/v2"
	"github.com/kevinburke/nacl"
	"github.com/kevinburke/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	logFileName   = "btclibwallet.log"
	walletsDbName = "wallets.db"

	walletsMetadataBucketName    = "metadata"
	walletstartupPassphraseField = "startup-passphrase"
)

func (mw *MultiWallet) batchDbTransaction(dbOp func(node storm.Node) error) (err error) {
	dbTx, err := mw.db.Begin(true)
	if err != nil {
		return err
	}

	// Commit or rollback the transaction after f returns or panics.  Do not
	// recover from the panic to keep the original stack trace intact.
	panicked := true
	defer func() {
		if panicked || err != nil {
			dbTx.Rollback()
			return
		}

		err = dbTx.Commit()
	}()

	err = dbOp(dbTx)
	panicked = false
	return err
}

func (mw *MultiWallet) loadWalletTemporarily(ctx context.Context, walletDataDir, walletPublicPass string,
	onLoaded func(*w.Wallet) error) error {

	if walletPublicPass == "" {
		walletPublicPass = w.InsecurePubPassphrase
	}

	// initialize the wallet loader
	walletLoader := initWalletLoader(mw.chainParams, walletDataDir)

	// open the wallet to get ready for temporary use
	wallet, err := walletLoader.OpenExistingWallet([]byte(walletPublicPass), false)
	if err != nil {
		return translateError(err)
	}

	// unload wallet after temporary use
	defer walletLoader.UnloadWallet()

	if onLoaded != nil {
		return onLoaded(wallet)
	}

	return nil
}

func (mw *MultiWallet) setNetworkBackend(chainClient chain.Interface) {
	mw.chainClient = chainClient

	if chainClient == nil {
		for _, wallet := range mw.wallets {
			if wallet.WalletOpened() {

				wallet.internal.SetChainSynced(false)

				wallet.internal.Stop()
				wallet.internal.WaitForShutdown()
				wallet.internal.Start()
				log.Info("Wallet was restarted due to sync cancellation")
			}
		}
	}
}

// RootDirFileSizeInBytes returns the total directory size of
// multiwallet's root directory in bytes.
func (mw *MultiWallet) RootDirFileSizeInBytes() (int64, error) {
	var size int64
	err := filepath.Walk(mw.rootDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

// naclLoadFromPass derives a nacl.Key from pass using scrypt.Key.
func naclLoadFromPass(pass []byte) (nacl.Key, error) {

	const N, r, p = 1 << 15, 8, 1

	hash, err := scrypt.Key(pass, nil, N, r, p, 32)
	if err != nil {
		return nil, err
	}
	return nacl.Load(EncodeHex(hash))
}

// encryptWalletSeed encrypts the seed with secretbox.EasySeal using pass.
func encryptWalletSeed(pass []byte, seed string) ([]byte, error) {
	key, err := naclLoadFromPass(pass)
	if err != nil {
		return nil, err
	}
	return secretbox.EasySeal([]byte(seed), key), nil
}

// decryptWalletSeed decrypts the encryptedSeed with secretbox.EasyOpen using pass.
func decryptWalletSeed(pass []byte, encryptedSeed []byte) (string, error) {
	key, err := naclLoadFromPass(pass)
	if err != nil {
		return "", err
	}

	decryptedSeed, err := secretbox.EasyOpen(encryptedSeed, key)
	if err != nil {
		return "", errors.New(ErrInvalidPassphrase)
	}

	return string(decryptedSeed), nil
}
