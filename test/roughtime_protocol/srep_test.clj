(ns roughtime-protocol.srep-test
  (:require
   [clojure.test              :refer [deftest is testing]]
   [roughtime-protocol.util   :refer [u8-ba gen-nonce bytes=]]
   [roughtime-protocol.srep   :as srep]
   [roughtime-protocol.tlv    :as tlv]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.merkle :as m]))

(set! *warn-on-reflection* true)

(deftest srep-build-minimal
  (testing "SREP encodes a valid nested TLV with required tags and values"
    ;; 1. Setup deterministic inputs
    (let [opts     {:tree-order :natural
                    :hash-size  32}
          request  (u8-ba 0x52 0x54 0x10 0x20 0x30)
          ver      0x8000000c
          ;; 2. Compute the root manually for the test
          root     (m/compute-root [request] opts)
          ;; 3. Pass the root to the new srep-bytes signature
          srep-bs  (srep/srep-bytes root {:version ver})

          decoded  (tlv/decode-rt-message srep-bs)
          v-VER    (get decoded "VER")
          v-RADI   (get decoded "RADI")
          _v-MIDP  (get decoded "MIDP")
          _v-VERS  (get decoded "VERS")
          v-ROOT   (get decoded "ROOT")]

      ;; Presence and Sizes checks remain the same...
      (is (= (-> decoded keys set) (set ["RADI" "MIDP" "ROOT" "VER" "VERS"])))
      (is (every? #(contains? decoded %) ["VER" "RADI" "MIDP" "VERS" "ROOT"]))
      (is (= 32 (alength ^bytes v-ROOT)))

      ;; Numeric fields match
      (is (= ver (e/uint32-le->long v-VER)))
      (is (= (srep/radi-seconds) (e/uint32-le->long v-RADI)))

      ;; 4. Verify ROOT matches what we passed in
      (is (bytes= root v-ROOT))))

  (testing "SREP for legacy google version"
    ;; 1. Setup deterministic inputs
    (let [opts     {:tree-order :natural
                    :hash-size  64}
          ;;
          request  (u8-ba 0x52 0x54 0x10 0x20 0x30)
          ver      0x00
          ;; 2. Compute the root manually for the test
          root     (m/compute-root [request] opts)
          ;; 3. Pass the root to the new srep-bytes signature
          srep-bs  (srep/srep-bytes root {:version ver})

          decoded  (tlv/decode-rt-message srep-bs)
          v-RADI   (get decoded "RADI")
          _v-MIDP  (get decoded "MIDP")
          v-ROOT   (get decoded "ROOT")]

      ;; Presence and Sizes checks remain the same...
      (is (every? #(contains? decoded %) ["RADI" "MIDP" "ROOT"]))
      (is (= 64 (alength ^bytes v-ROOT)))

      ;; Numeric fields match
      (is (= (srep/radi-seconds) (e/uint32-le->long v-RADI)))

      ;; 4. Verify ROOT matches what we passed in
      (is (bytes= root v-ROOT))))

  (testing "SREP for legacy IETF version"
    ;; 1. Setup deterministic inputs
    (let [opts     {:tree-order :natural
                    :hash-size  32}
          ;;
          request  (u8-ba 0x52 0x54 0x10 0x20 0x30)
          ver      0x80000002
          nonce    (gen-nonce {:len 64})
          ;; 2. Compute the root manually for the test
          root     (m/compute-root [request] opts)
          ;; 3. Pass the root to the new srep-bytes signature
          srep-bs  (srep/srep-bytes root {:version ver
                                          :nonce nonce})

          decoded  (tlv/decode-rt-message srep-bs)
          v-RADI   (get decoded "RADI")
          _v-MIDP  (get decoded "MIDP")
          v-ROOT   (get decoded "ROOT")
          v-NONC   (get decoded "NONC")]

      ;; Presence and Sizes checks remain the same...
      (is (= (-> decoded keys set) (set ["RADI" "MIDP" "ROOT" "NONC"])))
      (is (every? #(contains? decoded %) ["RADI" "MIDP" "ROOT" "NONC"]))
      (is (= 32 (alength ^bytes v-ROOT)))

      ;; Numeric fields match
      (is (= (srep/radi-seconds) (e/uint32-le->long v-RADI)))
      (is (bytes= v-NONC nonce))

      ;; 4. Verify ROOT matches what we passed in
      (is (bytes= root v-ROOT))))

  (testing "SREP for Cloudflare-era IETF version"
    ;; 1. Setup deterministic inputs
    (let [opts     {:tree-order :natural
                    :hash-size  32}
          ;;
          request  (u8-ba 0x52 0x54 0x10 0x20 0x30)
          ver      0x8000000a
          nonce    (gen-nonce {:len 32})
          ;; 2. Compute the root manually for the test
          root     (m/compute-root [request] opts)
          ;; 3. Pass the root to the new srep-bytes signature
          srep-bs  (srep/srep-bytes root {:version ver
                                          :nonce nonce})

          decoded  (tlv/decode-rt-message srep-bs)
          v-RADI   (get decoded "RADI")
          _v-MIDP  (get decoded "MIDP")
          v-ROOT   (get decoded "ROOT")]

      ;; Presence and Sizes checks remain the same...
      (is (= (-> decoded keys set) (set ["RADI" "MIDP" "ROOT"])))
      (is (every? #(contains? decoded %) ["RADI" "MIDP" "ROOT"]))
      (is (= 32 (alength ^bytes v-ROOT)))

      ;; Numeric fields match
      (is (= (srep/radi-seconds) (e/uint32-le->long v-RADI)))

      ;; 4. Verify ROOT matches what we passed in
      (is (bytes= root v-ROOT)))))

(deftest srep-validations
  (testing "fails when VERS doesn't include VER"
    ;; Pass a dummy 32-byte root to trigger validation checks
    (is (thrown? clojure.lang.ExceptionInfo
                 (srep/srep-bytes (byte-array 32)
                                  {:version 2})))))
