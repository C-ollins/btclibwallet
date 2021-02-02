module github.com/c-ollins/btclibwallet

require (
	github.com/DataDog/zstd v1.3.5 // indirect
	github.com/asdine/storm v0.0.0-20190216191021-fe89819f6282
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/btcutil v1.0.2
	github.com/btcsuite/btcwallet v0.11.0
	github.com/btcsuite/btcwallet/wallet/txauthor v1.0.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.0.0
	github.com/btcsuite/btcwallet/wallet/txsizes v1.0.0
	github.com/btcsuite/btcwallet/walletdb v1.2.0
	github.com/btcsuite/btcwallet/wtxmgr v1.0.0
	github.com/decred/dcrwallet/errors/v2 v2.0.0
	github.com/golang/protobuf v1.3.2 // indirect
	github.com/jrick/logrotate v1.0.0
	github.com/kevinburke/nacl v0.0.0-20190829012316-f3ed23dbd7f8
	github.com/lightninglabs/neutrino v0.11.0
	github.com/onsi/ginkgo v1.8.0
	github.com/onsi/gomega v1.5.0
	github.com/stretchr/testify v1.3.0 // indirect
	go.etcd.io/bbolt v1.3.3
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
	golang.org/x/net v0.0.0-20190813141303-74dc4d7220e7 // indirect
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20191010194322-b09406accb47 // indirect
	golang.org/x/text v0.3.2 // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898 // indirect
	google.golang.org/appengine v1.5.0 // indirect
)

replace (
	github.com/btcsuite/btcwallet => github.com/C-ollins/btcwallet v0.0.0-20210202144357-a5c58ae1ff51
	github.com/lightninglabs/neutrino => github.com/C-ollins/neutrino v0.11.1-0.20201028075217-1535c1765f1a
)

go 1.13
