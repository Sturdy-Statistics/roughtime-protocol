(ns roughtime-protocol.request-test
  (:require
   [clojure.test               :refer [deftest is testing]]
   [roughtime-protocol.util    :refer [concat-bytes bytes->hex-string]]
   [roughtime-protocol.request :as rq]
   [roughtime-protocol.tlv     :as tlv]
   [roughtime-protocol.packet  :as packet]
   [roughtime-protocol.endian  :as e]
   [roughtime-protocol.config :refer [fiducial-version]]))

(set! *warn-on-reflection* true)

(deftest parse-happy
  (testing "valid request with NONC + VER"
    (let [nonce (byte-array 32)         ; zeros OK for test
          versb (concat-bytes (mapv e/long->uint32-le [1 2]))
          msg   (tlv/encode-rt-message {"NONC" nonce
                                        "VER" versb
                                        "TYPE" (e/long->uint32-le 0)
                                        "ZZZZ" (byte-array 1000)}) ; typical padding
          pkt   (packet/encode-packet msg)
          out   (rq/parse-request pkt {:min-size-bytes 1000})]
      (is (= 32 (alength ^bytes (:nonce out))))
      (is (= [1 2] (:client-vers out)))
      (is (>= (:message-len out) 1000)))))

(deftest parse-errors
  (testing "missing NONC"
    (let [pkt (tlv/encode-rt-message {"VER" (e/long->uint32-le 1)})]
      (is (thrown? clojure.lang.ExceptionInfo (rq/parse-request pkt {})))))

  (testing "bad NONC len"
    (let [pkt (tlv/encode-rt-message {"NONC" (byte-array 63)
                                      "VER" (e/long->uint32-le 1)})]
      (is (thrown? clojure.lang.ExceptionInfo (rq/parse-request pkt {})))))

  (testing "missing VER"
    (let [pkt (tlv/encode-rt-message {"NONC" (byte-array 64)})]
      (is (thrown? clojure.lang.ExceptionInfo (rq/parse-request pkt {})))))

  (testing "VER not ascending / too many"
    (let [nonce (byte-array 64)
          vbad  (concat-bytes (mapv e/long->uint32-le [2 2 3]))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (rq/parse-request (tlv/encode-rt-message {"NONC" nonce "VER" vbad}) {}))))
    (let [nonce (byte-array 64)
          many  (byte-array (apply concat (map e/long->uint32-le (range 33))))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (rq/parse-request (tlv/encode-rt-message {"NONC" nonce "VER" many}) {})))))

  (testing "min-size policy"
    (let [pkt (tlv/encode-rt-message {"NONC" (byte-array 64)
                                      "VER" (e/long->uint32-le 1)})]
      (is (thrown? clojure.lang.ExceptionInfo
                   (rq/parse-request pkt {:min-size-bytes 1024}))))))

(deftest parse-legacy-google
  (testing "valid Google-style request (64-byte nonce, no VER/TYPE)"
    (let [nonce (byte-array 64)
          ;; Use the helper to ensure correct PAD\xff tag and 1024 byte size
          pkt   (rq/make-request {:ver      [0x00]
                                  :nonce    nonce
                                  :msg-size 1024})
          out   (rq/parse-request pkt {:min-size-bytes 1024})]
      (is (= 64 (alength ^bytes (:nonce out))))
      (is (= 0 (:version out)) "Should identify as Google Protocol (0)")
      (is (= [0] (:client-vers out)))
      (is (>= (:message-len out) 1012)))))

(deftest version-negotiation-scenarios
  (testing "client sends multiple versions including one we support"
    (let [nonce (byte-array 32)
          ;; Client supports Draft 1, Draft 15, and a future Draft 99
          vers  [0x80000001 0x8000000c 0x800000ff]
          msg   (rq/make-request-msg {:ver vers :nonce nonce})
          pkt   (packet/encode-packet msg)
          out   (rq/parse-request pkt)]
      (is (= 0x8000000c (:version out)) "Should pick the highest supported overlap")
      (is (= 32 (alength ^bytes (:nonce out))))))

  (testing "client sends only unsupported versions"
    (let [nonce (byte-array 32)
          vers  [0x80000005 0x80000007]  ; these are expired
          msg   (rq/make-request-msg {:ver vers :nonce nonce})
          pkt   (packet/encode-packet msg)]
      ;; should default to 0x8000000c
      (is (= fiducial-version (:version (rq/parse-request pkt)))))))

(deftest padding-tag-interop
  (testing "Google requests can be padded with PAD\\xff"
    (let [g-tag (byte-array [(byte \P) (byte \A) (byte \D) (unchecked-byte 0xff)])
          nonce (byte-array 64)
          msg   (tlv/encode-rt-message {"NONC" nonce
                                        g-tag (byte-array 900)})
          pkt   (packet/encode-packet msg)
          out   (rq/parse-request pkt {:min-size-bytes 0})]
      (is (= 0 (:version out)))

      (let [k (->> (:message out)
                   keys
                   (remove #(= java.lang.String (type %)))
                   first
                   bytes->hex-string)]
        (is (= (bytes->hex-string g-tag) k)
            "Should correctly preserve the legacy padding tag")))))

(deftest nonce-length-enforcement
  (testing "IETF request with 64-byte nonce must fail"
    (let [nonce (byte-array 64)
          vers  (e/u32-list->bytes [fiducial-version])
          msg   (tlv/encode-rt-message {"NONC" nonce "VER" vers "TYPE" (e/long->uint32-le 0)})]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"NONC has incorrect length"
                            (rq/parse-request (packet/encode-packet msg)
                                              {:min-size-bytes 0})))))

  (testing "Google request with 32-byte nonce must fail"
    (let [nonce (byte-array 32)
          msg   (tlv/encode-rt-message {"NONC" nonce})]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"NONC has incorrect length"
                            (rq/parse-request (packet/encode-packet msg)
                                              {:min-size-bytes 0}))))))
