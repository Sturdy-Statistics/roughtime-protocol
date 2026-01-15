(ns load-test.core
  (:require
   [criterium.core :as crit]

   [roughtime-protocol.sign :as sign]

   [roughtime-protocol.request :as rq]
   [roughtime-protocol.server :as server]))

(set! *warn-on-reflection* true)

(defn runme []
 (let [lt!!     (sign/gen-ed25519-kp)
       lt-pub   (.getPublic lt!!)
       lt-prv!! (.getPrivate lt!!)

       public-key (-> lt-pub sign/public-key->raw-pub32)

       cert-map   (server/mint-new-certificate-map lt-prv!!)]

   (letfn [(run [req-bytes] (server/respond {:request-bytes req-bytes
                                             :cert-map cert-map}))]
     (let [req-bytes (rq/make-request
                      {:ver [0x00] ;;[0x8000000c]
                       :msg-size 1024
                       :public-key public-key})]

       (crit/quick-bench (run req-bytes))))))

(defn runme-batched []
  (let [lt!!     (sign/gen-ed25519-kp)
        lt-pub   (.getPublic lt!!)
        lt-prv!! (.getPrivate lt!!)

        public-key (-> lt-pub sign/public-key->raw-pub32)

        cert-map   (server/mint-new-certificate-map lt-prv!!)

        ver        0x8000000c]

    (letfn [(req [_]
              (rq/make-request
               {:ver [ver] :msg-size 1024 :public-key public-key}))

            (parse [^bytes request-bytes]
              (rq/parse-request request-bytes
                                {:min-size-bytes 1024}))]

      (let [batch-size    128
            request-batch (mapv req (range batch-size))

            parsed-batch  (mapv parse request-batch)]

        (crit/quick-bench
         (server/batch-respond--single-version
          ver parsed-batch cert-map))))))


(defn runme-mixed-batched []
  (let [lt!!      (sign/gen-ed25519-kp)
        lt-pub    (.getPublic lt!!)
        lt-prv!!  (.getPrivate lt!!)
        public-key (-> lt-pub sign/public-key->raw-pub32)
        cert-map   (server/mint-new-certificate-map lt-prv!!)
        ;; A mix of Google-style (0x00) and IETF-style (0x80...) versions
        versions   [0x00 0x80000008 0x8000000b 0x8000000c]]

    (letfn [(req [i]
              (let [ver (nth versions (mod i (count versions)))]
                (rq/make-request
                 {:ver [ver] :msg-size 1024 :public-key public-key})))]

      (let [batch-size 1024
            request-batch (mapv req (range batch-size))]

        (crit/quick-bench
         (server/batch-respond request-batch cert-map))))))

(def ^bytes dummy-sig
  ;; 64-byte constant signature (Ed25519 signatures are 64 bytes)
  (byte-array 64 (byte 0x42)))

(defn run
  "Entry point for load testing"
  [_]

  (println "Running with BouncyCastle ED25519 signatures")
  (runme)

  (println "\n")
  (println "Running with ED25519 signatures stubbed to no-op")
  (with-redefs [sign/sign-with-context   (fn ^bytes [_ctx _content _prv] dummy-sig)
                sign/verify-with-context (fn [_ctx _content _pub _sig] true)]
    (runme))

  (println "\n")
  (println "Running batches of 128 with BouncyCastle ED25519 signatures")
  (runme-batched)

  (println "\n")
  (println "Running batches of 128 with ED25519 signatures stubbed to no-op")
  (with-redefs [sign/sign-with-context   (fn ^bytes [_ctx _content _prv] dummy-sig)
                sign/verify-with-context (fn [_ctx _content _pub _sig] true)]
    (runme-batched))


  (println "\n")
  (println "Running batches of 1024 (Mixed Versions) with BouncyCastle ED25519")
  (runme-mixed-batched)

  (println "\nRunning batches of 1024 (Mixed Versions) with ED25519 stubbed")
  (with-redefs [sign/sign-with-context   (fn ^bytes [_ctx _content _prv] dummy-sig)
                sign/verify-with-context (fn [_ctx _content _pub _sig] true)]
    (runme-mixed-batched)))
