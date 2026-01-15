(ns roughtime-protocol.packet-test
  (:require
   [clojure.test              :refer [deftest is testing]]
   [roughtime-protocol.util   :refer [concat-bytes u8-ba bytes=]]
   [roughtime-protocol.packet :as pkt]
   [roughtime-protocol.tlv    :as tlv]
   [roughtime-protocol.tag    :as tag]
   [roughtime-protocol.endian :as e])
  (:import
   (java.util Arrays)))

(set! *warn-on-reflection* true)

;; -------- happy path --------

(deftest encode-decode-roundtrip
  (testing "TLV message wrapped into a packet decodes back with same content"
    (let [msg (tlv/encode-rt-message
               {"NONC" (byte-array 64)
                "VERS" (e/u32-list->bytes [1 2])})
          pktb (pkt/encode-packet msg)
          out  (pkt/decode-packet pktb {:min-size-bytes 0})]
      (is (= (alength pktb) (:packet-len out)))
      (is (bytes= msg (:message-bytes out)))
      ;; and the decoded map matches what we encoded
      (is (= {"NONC" (get (:message out) "NONC")
              "VERS" (get (:message out) "VERS")}
             (:message out))))))

;; -------- minimum-size policy --------

(deftest min-size-policy
  (testing "enforces minimum packet size if provided"
    (let [msg  (tlv/encode-rt-message {"NONC" (byte-array 64)
                                       "VERS" (e/long->uint32-le 1)})
          pktb (pkt/encode-packet msg)]
      ;; No policy (or zero) → ok
      (is (map? (pkt/decode-packet pktb {:min-size-bytes 0})))
      ;; Enforce 1024 → should reject if smaller
      (is (thrown? clojure.lang.ExceptionInfo
                   (pkt/decode-packet pktb {:min-size-bytes 1024}))))))

;; -------- bad magic --------

(deftest rejects-bad-magic
  (testing "decoder rejects packets whose magic is not ROUGHTIM"
    (let [msg    (tlv/encode-rt-message {"NONC" (byte-array 64)
                                         "VERS" (e/long->uint32-le 1)})
          good   (pkt/encode-packet msg)
          ;; forge: change magic to some other u64
          badmag (e/long->uint64-le 0x0102030405060708)
          rest   (Arrays/copyOfRange good 8 (alength good))
          forged (concat-bytes [badmag rest])]
      (is (thrown? clojure.lang.ExceptionInfo
                   (pkt/decode-packet forged {:min-size-bytes 0}))))))

;; -------- truncated header --------

(deftest rejects-truncated
  (testing "decoder rejects packets shorter than 12 bytes (missing header fields)"
    (is (thrown? clojure.lang.ExceptionInfo
                 (pkt/decode-packet (byte-array 11))))))

;; -------- length mismatch --------

(deftest rejects-length-mismatch
  (testing "declared msg_len must match actual remaining bytes"
    (let [magic (tag/str->bytes8 "ROUGHTIM")
          mlen  (e/long->uint32-le 8) ; claim 8 bytes
          body  (u8-ba 0x00 0x01 0x02 0x03 0x04 0x05) ; only 6 bytes present
          forged (concat-bytes [magic mlen body])]
      (is (thrown? clojure.lang.ExceptionInfo
                   (pkt/decode-packet forged {:min-size-bytes 0}))))))

;; -------- non-multiple-of-4 message length --------

(deftest rejects-msglen-not-multiple-of-4
  (testing "message length must be a multiple of 4 (alignment)"
    (let [magic (tag/str->bytes8 "ROUGHTIM")
          mlen  (e/long->uint32-le 5) ; invalid length (not multiple of 4)
          body  (u8-ba 1 2 3 4 5)
          forged (concat-bytes [magic mlen body])]
      ;; decoder should reject *before* attempting TLV decode
      (is (thrown? clojure.lang.ExceptionInfo
                   (pkt/decode-packet forged {:min-size-bytes 0}))))))

;; -------- TLV decode path exercised --------

(deftest tlv-decode-still-happens
  (testing "valid packet with valid TLV body gets TLV-decoded"
    (let [mmap {"A" (e/long->uint32-le 7)
                "B" (byte-array 8)}
          msg  (tlv/encode-rt-message mmap)
          pktb (pkt/encode-packet msg)
          out  (pkt/decode-packet pktb {:min-size-bytes 0})
          m2   (:message out)]
      (is (= 7 (e/uint32-le->long (get m2 "A"))))
      (is (= 8 (alength ^bytes (get m2 "B")))))))
