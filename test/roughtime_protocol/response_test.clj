(ns roughtime-protocol.response-test
  (:require
   [clojure.test                :refer [deftest is testing]]
   [roughtime-protocol.sign     :as sign]
   [roughtime-protocol.response :as resp]
   [roughtime-protocol.tlv      :as tlv]
   [roughtime-protocol.sig      :as sig]
   [roughtime-protocol.cert     :as rcert]
   [roughtime-protocol.endian   :as e]))

(set! *warn-on-reflection* true)

(deftest assemble-and-verify-response
  (testing "Full response has expected tags and verifies both signatures"
    ;; Keys
    (let [lt      (sign/gen-ed25519-kp)      ; long-term
          lt-prv  (.getPrivate lt)
          lt-pub  (.getPublic  lt)
          onl     (sign/gen-ed25519-kp)      ; online
          onl-prv (.getPrivate onl)
          onl-pub (.getPublic  onl)
          ;; Deterministic inputs
          req   (.getBytes "ROUGHTIM" "US-ASCII")
          nonce (byte-array 32)
          mint  1700000000
          maxt  1700086400
          version 0x8000000c
          cert  (rcert/make-certificate onl-pub lt-prv
                                        {:mint-seconds   mint
                                         :maxt-seconds   maxt
                                         :version version})
          bs    (resp/response-bytes {:request-packet req
                                      :chosen-version version
                                      :nonce nonce
                                      :online-prv onl-prv
                                      :cert-bytes cert
                                      :index 0
                                      :path (byte-array 0)})
          top   (tlv/decode-rt-message bs)]

      ;; Top-level tags present
      (is (every? #(contains? top %)
                  ["SIG" "NONC" "TYPE" "PATH" "SREP" "CERT" "INDX"]))
      (is (= (-> top keys set)
             (set ["SIG" "NONC" "TYPE" "PATH" "SREP" "CERT" "INDX"])))

      ;; INDX=0, PATH empty
      (is (= 0 (e/uint32-le->long (get top "INDX"))))
      (is (= 0 (alength ^bytes (get top "PATH"))))

      ;; Verify CERT using long-term key
      (let [certb (get top "CERT")
            info  (rcert/verify-cert? certb lt-pub {:version version})]
        (is info)
        (is (= mint (:mint info)))
        (is (= maxt (:maxt info)))
        ;; Extract online raw pubkey from DELE and verify SREP signature
        (let [;; onl-raw (:pubk info)
              ;; srepb   (get top "SREP")
              sig     (get top "SIG")]
          (is (= 64 (alength ^bytes sig)))))

      ;; Extract online raw pubkey from the verified CERT
      (let [certb   (get top "CERT")
            info    (rcert/verify-cert? certb lt-pub {:version version})
            onl-raw (:pubk info) ;; This is the raw 32-byte key from the DELE
            srepb   (get top "SREP")
            sig     (get top "SIG")
            ;; Convert raw 32-byte key back to a Java PublicKey for verification
            onl-pub-reconstructed (sign/raw-pub32->public-key onl-raw)]

        (is (true? (sig/verify-srep? srepb onl-pub-reconstructed sig))
            "The SREP signature must be valid for the reconstructed online public key")))))

(deftest assemble-and-verify-response-v11
  (testing "Full response has expected tags and verifies both signatures (v11)"
    ;; Keys
    (let [lt      (sign/gen-ed25519-kp)      ; long-term
          lt-prv  (.getPrivate lt)
          lt-pub  (.getPublic  lt)
          onl     (sign/gen-ed25519-kp)      ; online
          onl-prv (.getPrivate onl)
          onl-pub (.getPublic  onl)
          ;; Deterministic inputs
          req   (.getBytes "ROUGHTIM" "US-ASCII")
          nonce (byte-array 32)
          mint  1700000000
          maxt  1700086400
          version 0x8000000b
          cert  (rcert/make-certificate onl-pub lt-prv
                                        {:mint-seconds   mint
                                         :maxt-seconds   maxt
                                         :version        version})
          bs    (resp/response-bytes {:request-packet req
                                      :chosen-version version
                                      :nonce nonce
                                      :online-prv onl-prv
                                      :cert-bytes cert
                                      :index 0
                                      :path (byte-array 0)})
          top   (tlv/decode-rt-message bs)]

      ;; Top-level tags present
      (is (every? #(contains? top %)
                  ["SIG" "NONC" "TYPE" "PATH" "VER" "SREP" "CERT" "INDX"]))
      (is (= (-> top keys set)
             (set ["SIG" "NONC" "TYPE" "PATH" "VER" "SREP" "CERT" "INDX"])))

      ;; INDX=0, PATH empty
      (is (= 0 (e/uint32-le->long (get top "INDX"))))
      (is (= 0 (alength ^bytes (get top "PATH"))))

      ;; Verify CERT using long-term key
      (let [certb (get top "CERT")
            info  (rcert/verify-cert? certb lt-pub {:version version})]
        (is info)
        (is (= mint (:mint info)))
        (is (= maxt (:maxt info)))
        ;; Extract online raw pubkey from DELE and verify SREP signature
        (let [;; onl-raw (:pubk info)
              ;; srepb   (get top "SREP")
              sig     (get top "SIG")]
          (is (= 64 (alength ^bytes sig)))))

      ;; Extract online raw pubkey from the verified CERT
      (let [certb   (get top "CERT")
            info    (rcert/verify-cert? certb lt-pub {:version version})
            onl-raw (:pubk info) ;; This is the raw 32-byte key from the DELE
            srepb   (get top "SREP")
            sig     (get top "SIG")
            ;; Convert raw 32-byte key back to a Java PublicKey for verification
            onl-pub-reconstructed (sign/raw-pub32->public-key onl-raw)]

        (is (true? (sig/verify-srep? srepb onl-pub-reconstructed sig))
            "The SREP signature must be valid for the reconstructed online public key")))))

(deftest assemble-and-verify-response-v2
  (testing "Full response has expected tags and verifies both signatures (v2)"
    ;; Keys
    (let [lt      (sign/gen-ed25519-kp)      ; long-term
          lt-prv  (.getPrivate lt)
          lt-pub  (.getPublic  lt)
          onl     (sign/gen-ed25519-kp)      ; online
          onl-prv (.getPrivate onl)
          onl-pub (.getPublic  onl)
          ;; Deterministic inputs
          req   (.getBytes "ROUGHTIM" "US-ASCII")
          nonce (byte-array 32)
          mint  1700000000
          maxt  1700086400
          version 0x80000002
          cert  (rcert/make-certificate onl-pub lt-prv
                                        {:mint-seconds   mint
                                         :maxt-seconds   maxt
                                         :version        version})
          bs    (resp/response-bytes {:request-packet req
                                      :chosen-version version
                                      :nonce nonce
                                      :online-prv onl-prv
                                      :cert-bytes cert
                                      :index 0
                                      :path (byte-array 0)})
          top   (tlv/decode-rt-message bs)]

      ;; Top-level tags present
      (is (every? #(contains? top %)
                  ["SREP" "SIG" "VER" "INDX" "PATH" "CERT"]))
      (is (= (-> top keys set)
             (set ["SREP" "SIG" "VER" "INDX" "PATH" "CERT"])))

      ;; INDX=0, PATH empty
      (is (= 0 (e/uint32-le->long (get top "INDX"))))
      (is (= 0 (alength ^bytes (get top "PATH"))))

      ;; Verify CERT using long-term key
      (let [certb (get top "CERT")
            info  (rcert/verify-cert? certb lt-pub {:version version})]
        (is info)
        (is (= mint (:mint info)))
        (is (= maxt (:maxt info)))
        ;; Extract online raw pubkey from DELE and verify SREP signature
        (let [;; onl-raw (:pubk info)
              ;; srepb   (get top "SREP")
              sig     (get top "SIG")]
          (is (= 64 (alength ^bytes sig)))))

      ;; Extract online raw pubkey from the verified CERT
      (let [certb   (get top "CERT")
            info    (rcert/verify-cert? certb lt-pub {:version version})
            onl-raw (:pubk info) ;; This is the raw 32-byte key from the DELE
            srepb   (get top "SREP")
            sig     (get top "SIG")
            ;; Convert raw 32-byte key back to a Java PublicKey for verification
            onl-pub-reconstructed (sign/raw-pub32->public-key onl-raw)]

        (is (true? (sig/verify-srep? srepb onl-pub-reconstructed sig))
            "The SREP signature must be valid for the reconstructed online public key")))))

(deftest assemble-and-verify-response-google
  (testing "Full response has expected tags and verifies both signatures (google)"
    ;; Keys
    (let [lt      (sign/gen-ed25519-kp)      ; long-term
          lt-prv  (.getPrivate lt)
          lt-pub  (.getPublic  lt)
          onl     (sign/gen-ed25519-kp)      ; online
          onl-prv (.getPrivate onl)
          onl-pub (.getPublic  onl)
          ;; Deterministic inputs
          req   (.getBytes "ROUGHTIM" "US-ASCII")
          nonce (byte-array 64)
          mint  (* 1700000000 1000 1000)
          maxt  (* 1700086400 1000 1000)
          version 0x00
          cert  (rcert/make-certificate onl-pub lt-prv
                                        {:mint-seconds   mint
                                         :maxt-seconds   maxt
                                         :version        version})
          bs    (resp/response-bytes {:request-packet req
                                      :chosen-version version
                                      :nonce nonce
                                      :online-prv onl-prv
                                      :cert-bytes cert
                                      :index 0
                                      :path (byte-array 0)})
          top   (tlv/decode-rt-message bs)]

      ;; Top-level tags present
      (is (every? #(contains? top %)
                  ["SREP" "SIG" "INDX" "PATH" "CERT"]))
      (is (= (-> top keys set)
             (set ["SREP" "SIG" "INDX" "PATH" "CERT"])))

      ;; INDX=0, PATH empty
      ;; TODO: 64 bytes!!!
      (is (= 0 (e/uint32-le->long (get top "INDX"))))
      (is (= 0 (alength ^bytes (get top "PATH"))))

      ;; Verify CERT using long-term key
      (let [certb (get top "CERT")
            info  (rcert/verify-cert? certb lt-pub {:version version})]
        (is info)
        (is (= (quot mint 1000000) (:mint info)))
        (is (= (quot maxt 1000000) (:maxt info)))
        ;; Extract online raw pubkey from DELE and verify SREP signature
        (let [;; onl-raw (:pubk info)
              ;; srepb   (get top "SREP")
              sig     (get top "SIG")]
          (is (= 64 (alength ^bytes sig)))))

      ;; Extract online raw pubkey from the verified CERT
      (let [certb   (get top "CERT")
            info    (rcert/verify-cert? certb lt-pub {:version version})
            onl-raw (:pubk info) ;; This is the raw 32-byte key from the DELE
            srepb   (get top "SREP")
            sig     (get top "SIG")
            ;; Convert raw 32-byte key back to a Java PublicKey for verification
            onl-pub-reconstructed (sign/raw-pub32->public-key onl-raw)]

        (is (true? (sig/verify-srep? srepb onl-pub-reconstructed sig))
            "The SREP signature must be valid for the reconstructed online public key")))))
