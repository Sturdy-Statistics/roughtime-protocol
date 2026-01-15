(ns roughtime-protocol.compat-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [roughtime-protocol.compat :as compat]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.tag :as tag]
   [roughtime-protocol.util :as util]))

(set! *warn-on-reflection* true)

(deftest version-negotiation
  (testing "choose-version logic"
    (is (= 0 (compat/choose-version nil))
        "No version tag should result in Google Protocol (0)")

    (is (= 0x8000000c (compat/choose-version [0x8000000c]))
        "Direct match for Draft 15 should work")

    (is (= 0x8000000c (compat/choose-version [0x99999999]))
        "No overlap should default to our preferred Draft 15 (0x8000000c)")

    (is (= 0x8000000c (compat/choose-version [0x80000001 0x8000000c]))
        "Should choose the maximum supported version from the overlap")))

(deftest nonce-validation
  (let [nonce32 (byte-array 32)
        nonce64 (byte-array 64)]

    (testing "Google Protocol (v0) requires 64 bytes"
      (is (= :ok (compat/validate-nonce 0 nonce64)))
      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-nonce 0 nonce32))))

    (testing "IETF Draft 15 (0x8000000c) requires 32 bytes"
      (is (= :ok (compat/validate-nonce 0x8000000c nonce32)))
      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-nonce 0x8000000c nonce64))))

    (testing "Early IETF Drafts (v1-4) required 64 bytes"
      (is (= :ok (compat/validate-nonce 0x80000001 nonce64)))
      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-nonce 0x80000001 nonce32))))))

(deftest type-validation
  (let [type0 (e/long->uint32-le 0)
        type1 (e/long->uint32-le 1)]

    (testing "Draft 15 (0x8000000c) requires TYPE 0"
      (is (= :ok (compat/validate-type 0x8000000c type0)))
      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-type 0x8000000c type1))))

    (testing "Legacy versions ignore TYPE"
      (is (= :ok (compat/validate-type 0 nil)) "Google has no TYPE")
      (is (= :ok (compat/validate-type 0x80000001 type1)) "Early IETF ignores TYPE"))))

(deftest ver-list-validation
  (testing "Draft 15 strictness for VER list"
    (let [valid (e/u32-list->bytes [0x80000001 0x8000000c])
          unordered (e/u32-list->bytes [0x8000000c 0x80000001])
          too-many (e/u32-list->bytes (range 0x80000001 (+ 0x80000001 33)))]

      (is (map? (compat/validate-and-return-vers valid)))

      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-and-return-vers unordered))
          "Must be strictly ascending")

      (is (thrown? clojure.lang.ExceptionInfo (compat/validate-and-return-vers too-many))
          "Must not exceed 32 entries"))))

(deftest padding-tag-bytes-test
  (testing "Google PAD tag has the 0xFF suffix"
    (let [p-tag (compat/pad-tag 0)
          p-bytes (tag/tag->bytes p-tag)]
      (is (= "504144ff" (util/bytes->hex-string p-bytes)))))

  (testing "Modern ZZZZ tag"
    (let [p-tag (compat/pad-tag 0x8000000c)
          p-bytes (tag/tag->bytes p-tag)]
      (is (= "5a5a5a5a" (util/bytes->hex-string p-bytes)))))

  (testing "Early IETF PAD tag (null padded)"
    (let [p-tag (compat/pad-tag 0x80000001)
          p-bytes (tag/tag->bytes p-tag)]
      (is (= "50414400" (util/bytes->hex-string p-bytes))))))
