(ns roughtime-protocol.batched-request-test
  (:require
   [clojure.test :refer [deftest is testing]]
   ;; [clojure.pprint :refer [pprint]]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.sign :as sign]
   [roughtime-protocol.request :as rq]
   [roughtime-protocol.client :as client]
   [roughtime-protocol.server :as server]))

(set! *warn-on-reflection* true)

(defn run-test [ver]
  (testing (format "Running batched round-trips with version 0x%08x" ver)
    (let [lt!!     (sign/gen-ed25519-kp)
          lt-pub   (.getPublic lt!!)
          lt-prv!! (.getPrivate lt!!)

          public-key (-> lt-pub sign/public-key->raw-pub32)

          cert-map   (server/mint-new-certificate-map lt-prv!!)]

      (letfn [(req [_]
                (rq/make-request
                 {:ver [ver] :msg-size 1024 :public-key public-key}))

              (parse [^bytes request-bytes]
                (rq/parse-request request-bytes
                                  {:min-size-bytes 1024}))

              (exch [^bytes request-bytes ^bytes response-bytes]
                (client/response->exchange
                 {:request-bytes   request-bytes
                  :response-bytes  {:bytes response-bytes}
                  :server-map      {:public-key (u/bytes->b64 public-key)}}))]

        (let [request-batch (mapv req (range 100))

              parsed-batch  (mapv parse request-batch)

              resp-batch    (server/batch-respond--single-version
                             ver parsed-batch cert-map)

              exch-batch    (mapv exch request-batch resp-batch)  ]

          ;; NB this throws on validation failure
          (doseq [exchange exch-batch]
            (is (= :ok (client/validate-response exchange)))))))
    :ok))

(deftest batched-response-roundtrip

  (doseq [ver [0x00 0x80000008 0x8000000b 0x8000000c]]
   (is (= :ok (run-test ver)))))

(deftest multi-version-batch-test
  (testing "batch-respond handles a mix of protocol versions and maintains order"
    (let [versions [0x00 0x80000008 0x8000000b 0x8000000c]
          lt!!     (sign/gen-ed25519-kp)
          lt-pub   (.getPublic lt!!)
          lt-prv!! (.getPrivate lt!!)
          public-key (-> lt-pub sign/public-key->raw-pub32)
          cert-map   (server/mint-new-certificate-map lt-prv!!)

          ;; 1. Generate a batch with mixed versions
          request-batch (mapv (fn [i]
                                (let [ver (nth versions (mod i (count versions)))]
                                  (rq/make-request
                                   {:ver [ver] :msg-size 1024 :public-key public-key})))
                              (range 128))

          ;; 2. Process the entire batch at once
          response-batch (server/batch-respond request-batch cert-map)]

      (is (= (count request-batch) (count response-batch))
          "Response batch size should match request batch size")

      ;; 3. Validate each response against its original request
      (doseq [i (range (count request-batch))]
        (let [req-bytes (nth request-batch i)
              res-bytes (nth response-batch i)
              exchange (client/response->exchange
                        {:request-bytes   req-bytes
                         :response-bytes  {:bytes res-bytes}
                         :server-map      {:public-key (u/bytes->b64 public-key)}})]

          ;; If the order was preserved, this validation will succeed.
          ;; If responses were shuffled, the nonce/merkle-path validation will fail.
          (is (= :ok (client/validate-response exchange))
              (str "Validation failed for request at index " i)))))))

(deftest batch-respond-error-handling-test
  (let [lt!!       (sign/gen-ed25519-kp)
        lt-prv!!   (.getPrivate lt!!)
        cert-map   (server/mint-new-certificate-map lt-prv!!)
        public-key (-> (.getPublic lt!!) sign/public-key->raw-pub32)

        valid-req  (rq/make-request {:ver [0x00] :msg-size 1024 :public-key public-key})
        v1-req     (rq/make-request {:ver [0x80000001] :msg-size 1024 :public-key public-key})
        v2-req     (rq/make-request {:ver [0x80000002] :msg-size 1024 :public-key public-key})
        junk-req   (byte-array [0xDE 0xAD 0xBE 0xEF])]

    (testing "Malformed and unsupported requests result in nil responses within a batch"
      (let [request-batch [valid-req   ;; 0: Valid
                           junk-req    ;; 1: Parse Error
                           v1-req      ;; 2: Batching unsupported (throws in sub-batch)
                           valid-req   ;; 3: Valid
                           v2-req      ;; 4: Batching unsupported (throws in sub-batch)
                           junk-req]   ;; 5: Parse Error

            responses (server/batch-respond request-batch cert-map)]

        (is (= 6 (count responses)) "Batch size must be preserved")

        (testing "Specific slots are nil or valid"
          (is (some? (nth responses 0)) "Index 0 should be a valid response")
          (is (nil?  (nth responses 1)) "Index 1 (junk) should be nil")
          (is (nil?  (nth responses 2)) "Index 2 (v1) should be nil")
          (is (some? (nth responses 3)) "Index 3 should be a valid response")
          (is (nil?  (nth responses 4)) "Index 4 (v2) should be nil")
          (is (nil?  (nth responses 5)) "Index 5 (junk) should be nil"))))

    (testing "A batch of entirely junk requests"
      (let [junk-batch (vec (repeat 5 junk-req))
            responses  (server/batch-respond junk-batch cert-map)]
        (is (= [nil nil nil nil nil] responses))))))
