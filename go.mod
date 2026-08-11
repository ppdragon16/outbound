module github.com/daeuniverse/outbound

go 1.24.0

require (
	github.com/awnumar/fastrand v0.0.0-20210315215012-30ee0990fa2d
	github.com/daeuniverse/quic-go v0.0.0-20250210145620-2083199a7851
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d
	github.com/dgryski/go-idea v0.0.0-20170306091226-d2fb45a411fb
	github.com/dgryski/go-rc2 v0.0.0-20150621095337-8a9021637152
	github.com/eknkc/basex v1.0.1
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/json-iterator/go v1.1.12
	github.com/mzz2017/disk-bloom v1.0.1
	github.com/refraction-networking/utls v1.8.1
	github.com/samber/oops v1.19.4
	github.com/seiflotfy/cuckoofilter v0.0.0-20240715131351-a2f2c23f1771
	github.com/sirupsen/logrus v1.9.3
	gitlab.com/yawning/chacha20.git v0.0.0-20230427033715-7877545b1b37
	golang.org/x/crypto v0.45.0
	golang.org/x/exp v0.0.0-20251125195548-87e1e737ad39
	golang.org/x/net v0.47.0
	golang.org/x/sys v0.38.0
	google.golang.org/grpc v1.77.0
	google.golang.org/protobuf v1.36.10
	lukechampine.com/blake3 v1.4.1
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/awnumar/memcall v0.5.0 // indirect
	github.com/awnumar/memguard v0.23.0 // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/ebfe/rc2 v0.0.0-20131011165748-24b9757f5521 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20251114195745-4902fdda35c8 // indirect
	github.com/klauspost/compress v1.18.1 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/onsi/ginkgo/v2 v2.27.2 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/samber/lo v1.52.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251124214823-79d6a2a48846 // indirect
)

replace github.com/daeuniverse/quic-go => github.com/ppdragon16/quic-go v0.0.0-next.utls
