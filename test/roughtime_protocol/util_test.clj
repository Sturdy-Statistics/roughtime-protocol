(ns roughtime-protocol.util-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [roughtime-protocol.util :as util])
  (:import
   (java.util Arrays)))

(set! *warn-on-reflection* true)

(deftest concat-bytes-test
  (testing "Concatenating multiple byte arrays"
    (let [ba1 (byte-array [(byte 1) (byte 2)])
          ba2 (byte-array [(byte 3)])
          ba3 (byte-array [(byte 4) (byte 5)])
          result (util/concat-bytes [ba1 ba2 ba3])]
      (is (Arrays/equals (byte-array [(byte 1) (byte 2) (byte 3) (byte 4) (byte 5)])
                         result)))))

(deftest hex-conversion-test
  (let [bytes (byte-array [(unchecked-byte 0xde) (unchecked-byte 0xad) (unchecked-byte 0xbe) (unchecked-byte 0xef)])
        hex "deadbeef"]
    (testing "bytes->hex-string"
      (is (= hex (util/bytes->hex-string bytes))))

    (testing "hex-string->bytes"
      (is (Arrays/equals bytes (util/hex-string->bytes hex))))))

(deftest base64-conversion-test
  (let [bytes (.getBytes "Hello Roughtime" "UTF-8")
        b64 "SGVsbG8gUm91Z2h0aW1l"]
    (testing "bytes->b64"
      (is (= b64 (util/bytes->b64 bytes))))

    (testing "b64->bytes"
      (is (Arrays/equals bytes (util/b64->bytes b64))))))

(deftest slice-test
  (let [ba (byte-array [0 1 2 3 4 5])]
    (is (Arrays/equals ^bytes (byte-array [1 2 3]) ^bytes (util/slice ba 1 4)))))

(deftest gen-nonce-test
  (testing "Nonce generation"
    (let [n1 (util/gen-nonce)
          n2 (util/gen-nonce)]
      (is (= 32 (alength n1)) "Nonce should be 32 bytes")
      (is (not (Arrays/equals n1 n2)) "Subsequent nonces should not be equal"))))

(deftest sha512-bytes-test
  (testing "Hashing basic string"
    (let [input (.getBytes "roughtime" "UTF-8")
          h (util/sha512-bytes 32 input)]
      (is (= 32 (alength ^bytes h)))
      ;; Verified against: echo -n "roughtime" | shasum -a 512 | cut -c1-64
      (is (= "95cb973f104116c1b8c03b3ffcad5d4e7456a2d92b628ee6335fcb9e9f142c60"
             (util/bytes->hex-string h)))))

  (testing "Hashing with prefix-byte"
    (let [prefix (byte 0x00)
          input (byte-array [1 2 3])
          h (util/sha512-bytes 32 prefix input)]
      (is (= 32 (alength ^bytes h)))
      ;; This tests that the prefix is actually included in the hash
      (is (not= (util/bytes->hex-string (util/sha512-bytes 32 input))
                (util/bytes->hex-string h))))))

(deftest formatting-test
  (testing "hex-str->blocks formatting"
    (let [hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
      (is (= ["01234567 89abcdef 01234567 89abcdef"
              "01234567 89abcdef 01234567 89abcdef"]
             (util/hex-str->blocks hex))))))
