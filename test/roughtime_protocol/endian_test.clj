(ns roughtime-protocol.endian-test
  (:require
   [clojure.test              :refer [deftest is testing]]
   [roughtime-protocol.util   :as util :refer [u8-ba u8-vec bytes=]]
   [roughtime-protocol.endian :as e]))

(set! *warn-on-reflection* true)

(deftest encode-uint32-known-example
  (testing "32-bit little-endian encoding matches example 0x12345678"
    (let [x 0x12345678
          bs (e/long->uint32-le x)]
      (is (= [120 86 52 18] (u8-vec bs))))))

(deftest encode-uint32-masks-to-low-32-bits
  (testing "values larger than 32 bits are masked to low 32"
    (let [x 0x123456789
          ;; low 32 bits are 0x23456789 → LE: [0x89 0x67 0x45 0x23]
          bs (e/long->uint32-le x)]
      (is (= [137 103 69 35] (u8-vec bs))))))

(deftest encode-uint32-boundaries
  (testing "0 encodes to four zero bytes"
    (is (= [0 0 0 0] (u8-vec (e/long->uint32-le 0)))))
  (testing "-1 encodes to 0xFFFFFFFF"
    (is (= [255 255 255 255] (u8-vec (e/long->uint32-le -1)))))
  (testing "0x80000000 (high bit set) encodes correctly"
    (is (= [0 0 0 128] (u8-vec (e/long->uint32-le 0x80000000))))))

(deftest encode-uint64-known-example
  (testing "64-bit little-endian encoding matches example 0x1122334455667788"
    (let [x 0x1122334455667788
          bs (e/long->uint64-le x)]
      (is (= [136 119 102 85 68 51 34 17] (u8-vec bs))))))

(deftest encode-uint64-boundaries
  (testing "0 encodes to eight zero bytes"
    (is (= [0 0 0 0 0 0 0 0] (u8-vec (e/long->uint64-le 0)))))
  (testing "-1 encodes to 0xFFFFFFFFFFFFFFFF"
    (is (= [255 255 255 255 255 255 255 255] (u8-vec (e/long->uint64-le -1))))))

(deftest decode-uint32-known-example
  (testing "decoding 0x78 56 34 12 yields 0x12345678"
    (let [ba (byte-array [(byte 0x78) (byte 0x56) (byte 0x34) (byte 0x12)])]
      (is (= 0x12345678 (e/uint32-le->long ba))))))

(deftest decode-uint32-accepts-signed-bytes
  (testing "decoding with signed byte values (e.g., 0xFF -> -1 as byte) works"
    (let [ba (byte-array [(unchecked-byte 0xFF) (unchecked-byte 0xFF) (unchecked-byte 0xFF) (unchecked-byte 0xFF)])]
      (is (= 0xFFFFFFFF (e/uint32-le->long ba))))))

(deftest uint32-roundtrip-selected-values
  (testing "encode -> decode round-trip for representative values"
    (doseq [x [0
               1
               0x7FFFFFFF
               0x80000000
               0xDEADBEEF
               0xFFFFFFFF]]
      (let [bs (e/long->uint32-le x)
            y  (e/uint32-le->long bs)]
        (is (= (bit-and x 0xFFFFFFFF) y)
            (format "round-trip failed for 0x%08X" x))))))



;; Helpers
(deftest uint32-known-example
  (testing "uint32-le->long decodes 0x12345678"
    (let [ba (u8-ba 0x78 0x56 0x34 0x12)]
      (is (= 0x12345678 (e/uint32-le->long ba))))))

(deftest uint32-boundaries
  (testing "uint32: 0 and all-ones"
    (is (= 0 (e/uint32-le->long (u8-ba 0x00 0x00 0x00 0x00))))
    (is (= 4294967295 (e/uint32-le->long (u8-ba 0xff 0xff 0xff 0xff))))))

(deftest uint32-bad-length
  (testing "uint32-le->long rejects wrong lengths"
    (is (thrown? clojure.lang.ExceptionInfo (e/uint32-le->long (u8-ba 0x00))))
    (is (thrown? clojure.lang.ExceptionInfo (e/uint32-le->long (u8-ba 0x00 0x00 0x00 0x00 0x00))))))

(deftest uint64-known-example
  (testing "uint64-le->bigint decodes 0x1122334455667788"
    (let [ba (u8-ba 0x88 0x77 0x66 0x55 0x44 0x33 0x22 0x11)]
      (is (= 1234605616436508552 (e/uint64-le->bigint ba))))))

(deftest uint64-boundaries
  (testing "uint64: zero"
    (is (= 0 (e/uint64-le->bigint (u8-ba 0 0 0 0 0 0 0 0))))))

(deftest uint64-bad-length
  (testing "uint64-le->bigint rejects wrong lengths"
    (is (thrown? clojure.lang.ExceptionInfo (e/uint64-le->bigint (u8-ba 0x00))))
    (is (thrown? clojure.lang.ExceptionInfo (e/uint64-le->bigint (u8-ba 0 0 0 0 0 0 0))))))

(deftest uint32-roundtrip
  (testing "uint32 round-trip via long->uint32-le"
    (doseq [x [0
               1
               0x7fffffff
               0x80000000
               0xdeadbeef
               0xffffffff]]
      (let [enc (e/long->uint32-le x)
            dec (e/uint32-le->long enc)]
        (is (= (bit-and x 0xffffffff) dec)
            (format "round-trip failed for 0x%08X" x))))))

(deftest uint64-roundtrip-safe-range
  (testing "uint64 round-trip via long->uint64-le (values within signed 64-bit range)"
    ;; Stay <= Long/MAX_VALUE to avoid two's complement surprises in equality
    (doseq [x [0
               1
               0x00000000ffffffff   ; 2^32-1
               0x0000000100000000   ; 2^32
               0x0123456789abcdef   ; fits in signed 64
               0x7fffffffffffffff]] ; Long/MAX_VALUE
      (let [enc (e/long->uint64-le x)
            dec (e/uint64-le->bigint enc)]
        (is (= x dec)
            (format "round-trip failed for 0x%016X" x))))))



;; ---------------- Round-trip tests ----------------

(deftest u32-list->bytes->list-roundtrip
  (testing "list → bytes → list round-trip on typical inputs"
    (doseq [xs [[]
                [0]
                [1]
                [0xDEADBEEF]
                [0 1 2 3]
                [0xFFFFFFFF 0x80000000 0x7FFFFFFF 0x00000001]]]
      (let [ba (e/u32-list->bytes xs)
            ys (e/bytes->u32-list ba)]
        (is (= xs ys) (str "round-trip mismatch for " xs))))))

(deftest bytes->list->bytes-roundtrip
  (testing "bytes → list → bytes round-trip with constructed buffers"
    (let [words [[0x00000000]
                 [0x12345678 0x9ABCDEF0]
                 [0xFFFFFFFF 0x00000001 0xCAFEBABE 0x0BADF00D]]]
      (doseq [ws words]
        (let [parts (map e/long->uint32-le ws)
              ba    (util/concat-bytes parts)
              lst   (e/bytes->u32-list ba)
              ba'   (e/u32-list->bytes lst)]
          (is (= ws lst) (str "decoded words mismatch for " ws))
          (is (bytes= ba ba') (str "re-encoded bytes mismatch for " ws)))))))

;; ---------------- Edge cases ----------------

(deftest empty-inputs
  (testing "empty list ↔ empty byte-array"
    (is (= [] (e/bytes->u32-list (byte-array 0))))
    (is (= 0 (alength (e/u32-list->bytes []))))))

(deftest boundaries
  (testing "min/max uint32 values"
    (let [xs [0 0xFFFFFFFF]]
      (is (= xs (e/bytes->u32-list (e/u32-list->bytes xs)))))))

;; ---------------- Error handling ----------------

(deftest bytes->u32-list-rejects-bad-length
  (testing "reject byte arrays whose length is not a multiple of 4"
    (doseq [n [1 2 3 5 6 7 9]]
      (let [ba (byte-array n)]
        (is (thrown? clojure.lang.ExceptionInfo (e/bytes->u32-list ba))
            (str "expected ExceptionInfo for length " n))))))

;; ---------------- A light randomized smoke test ----------------

(deftest small-randomized
  (testing "random short vectors of u32 round-trip"
    (doseq [_ (range 20)]
      (let [cnt (rand-int 6)
            xs  (vec (repeatedly cnt #(long (rand-int 0x010000000))))]
        (is (= xs (e/bytes->u32-list (e/u32-list->bytes xs))))
        ;; and ensure the length is 4*cnt
        (is (= (* 4 cnt) (alength (e/u32-list->bytes xs))))))))
