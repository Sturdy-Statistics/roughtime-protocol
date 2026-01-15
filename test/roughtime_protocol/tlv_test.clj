(ns roughtime-protocol.tlv-test
  (:require
   [clojure.test               :refer [deftest is testing]]
    [roughtime-protocol.util   :refer [u8 u8-ba u8-vec slice bytes=]]
    [roughtime-protocol.tlv    :as tlv]
    [roughtime-protocol.endian :as e]
    [roughtime-protocol.tag    :as tag]))

(set! *warn-on-reflection* true)

;; ---------- Round-trip / padding / order ----------

(deftest roundtrip-two-tags
  (testing "encode → decode round-trip; padding added; values preserved"
    (let [msg {"NONC" (u8-ba 1 2 3 4)
               "VER"  (u8-ba 5 6 7)} ; gets padded
          enc (tlv/encode-rt-message msg)
          dec (tlv/decode-rt-message enc)]
      (is (= #{"NONC" "VER"} (set (keys dec))))
      (is (= [1 2 3 4] (u8-vec (get dec "NONC"))))
      (is (= [5 6 7 0] (u8-vec (get dec "VER")))))))

(deftest encode-header-layout
  (testing "header fields (num_tags, offsets, tags) are laid out correctly and sorted"
    (let [msg {"VER"  (u8-ba 8 7 6 5)
               "NONC" (u8-ba 4 3 2 1)}
          bs  (tlv/encode-rt-message msg)
          ;; num_tags = 2 at 0..4
          n   (e/uint32-le->long (slice bs 0 4))
          ;; offsets for tags 1..N-1 (one offset) at 4..8
          off (e/uint32-le->long (slice bs 4 8))
          ;; tags region starts at 4 + 4*(N-1) = 8
          t0  (slice bs 8 12)
          t1  (slice bs 12 16)]
      (is (= 2 n))
      ;; The first tag in header should be "VER" (sorted before "NONC")
      (is (= "VER"  (tag/bytes->tag t0)))
      (is (= "NONC" (tag/bytes->tag t1)))
      ;; The offset should equal the (padded) length of the first value
      ;; First value corresponds to tag "NONC" (4 bytes)
      (is (= 4 off)))))

(deftest empty-message
  (testing "empty {} encodes to 4-byte header and decodes back to {}"
    (let [enc (tlv/encode-rt-message {})]
      (is (= [0 0 0 0] (u8-vec enc)))
      (is (= {} (tlv/decode-rt-message enc))))))

;; ---------- Malformed / validation cases ----------

(deftest rejects-non-ascending-tags
  (testing "decode rejects non-ascending tag order"
    ;; Forge a minimal bad message by hand:
    ;; num=2, offset=0, tags=[2,1], payload empty
    (let [b (byte-array 16)]
      ;; num_tags = 2
      (System/arraycopy (e/long->uint32-le 2) 0 b 0 4)
      ;; offsets[0] = 0 (invalid for our 'ok-offset?' too, but order check should trip first)
      (System/arraycopy (e/long->uint32-le 0) 0 b 4 4)
      ;; tags: 2 then 1 (descending)
      (System/arraycopy (e/long->uint32-le 2) 0 b 8 4)
      (System/arraycopy (e/long->uint32-le 1) 0 b 12 4)
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message b))))))

(deftest rejects-misaligned-offset
  (testing "offset must be a multiple of 4 and > 0"
    ;; num=2, offset=3 (misaligned), tags ok, no payload
    (let [b (byte-array 16)]
      (System/arraycopy (e/long->uint32-le 2) 0 b 0 4)
      (System/arraycopy (e/long->uint32-le 3) 0 b 4 4)  ; invalid alignment
      (System/arraycopy (e/long->uint32-le 10) 0 b 8 4) ; ascending tags
      (System/arraycopy (e/long->uint32-le 20) 0 b 12 4)
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message b))))))

(deftest rejects-zero-offset
  (testing "offset cannot be zero (first value is implicitly at 0)"
    ;; num=2, offset=0, tags ok → offset invalid by ok-offset?
    (let [b (byte-array 16)]
      (System/arraycopy (e/long->uint32-le 2) 0 b 0 4)
      (System/arraycopy (e/long->uint32-le 0) 0 b 4 4)  ; zero offset → invalid
      (System/arraycopy (e/long->uint32-le 10) 0 b 8 4)
      (System/arraycopy (e/long->uint32-le 20) 0 b 12 4)
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message b))))))

(deftest rejects-offset-out-of-bounds
  (testing "offset must be ≤ payload length"
    ;; Build a legit one-tag message, then tamper the offset to exceed payload
    (let [msg {"A" (u8-ba 1 2 3 4)
               "B" (u8-ba 9 9 9 9)}
          good (tlv/encode-rt-message msg)
          ;; header size = 8*N = 16
          bad (byte-array (alength good))]
      (System/arraycopy good 0 bad 0 (alength good))
      ;; Overwrite the single offset to something huge
      (System/arraycopy (e/long->uint32-le 9999) 0 bad 4 4)
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message bad))))))

(deftest rejects-truncated-header
  (testing "header too short for declared num_tags"
    ;; num=3 but only 8 bytes in the array
    (let [b (byte-array 8)]
      (System/arraycopy (e/long->uint32-le 3) 0 b 0 4)
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message b))))))

(deftest rejects-non-multiple-of-4-value-len
  (testing "value lengths must be multiples of 4"
    ;; Craft a one-tag message where payload len is 3 (invalid)
    ;; header (n=1): [num(4)] + [no offsets] + [tag(4)] = 8 bytes
    ;; put "A" as tag, payload len 3
    (let [b (byte-array 11)]
      ;; num_tags = 1
      (System/arraycopy (e/long->uint32-le 1) 0 b 0 4)
      ;; tag at index 4..8: "A" → 0x00000041 LE = [41 00 00 00]
      (System/arraycopy (tag/tag->bytes "A") 0 b 4 4)
      ;; payload: 3 bytes (invalid length)
      (aset-byte b 8  (u8 0x01))
      (aset-byte b 9  (u8 0x02))
      (aset-byte b 10 (u8 0x03))
      (is (thrown? clojure.lang.ExceptionInfo (tlv/decode-rt-message b))))))

;; ---------- A quick property-ish sanity test ----------

(deftest random-roundtrips
  (testing "random small maps round-trip"
    (doseq [_ (range 20)]
      (let [ks (shuffle ["A" "B" "C" "NONC" "VER"])
            n  (+ 1 (rand-int 3))
            m  (into {}
                     (for [k (take n ks)]
                       (let [len (* 4 (inc (rand-int 3)))
                             v   (byte-array len)]
                         (java.util.Arrays/fill v (unchecked-byte (rand-int 256)))
                         [k v])))
            enc (tlv/encode-rt-message m)
            dec (tlv/decode-rt-message enc)]
        ;; keys same (set ignores order)
        (is (= (set (keys m)) (set (keys dec))))
        ;; values equal byte-for-byte
        (doseq [k (keys m)]
          (is (bytes= (get m k) (get dec k))
              (str "mismatch at tag " k)))))))

(deftest rejects-duplicate-and-unsorted-tags
  (testing "decode must throw if tags are not strictly increasing numerically"
    ;; Forge a 24-byte message: 4(num) + 4(offset) + 8(tags) + 8(dummy payload)
    (let [b (byte-array 24)]
      (System/arraycopy (e/long->uint32-le 2) 0 b 0 4)   ; num_tags = 2
      (System/arraycopy (e/long->uint32-le 4) 0 b 4 4)   ; offset = 4 (1st val is 4 bytes)
      (System/arraycopy (tag/tag->bytes "NONC") 0 b 8 4) ; tag 0
      (System/arraycopy (tag/tag->bytes "NONC") 0 b 12 4); tag 1 (duplicate)
      ;; The total payload length is 24 - 16 = 8.
      ;; boundaries will be [0 4 8], which is monotonic.
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"strictly increasing"
                            (tlv/decode-rt-message b))))))
