(ns roughtime-protocol.tag-test
  (:require
    [clojure.test            :refer [deftest is testing]]
    [roughtime-protocol.util :refer [u8-ba u8-vec bytes->hex-string hex-string->bytes bytes=]]
    [roughtime-protocol.endian :as e]
    [roughtime-protocol.tag  :as tag :refer [pad4]]))

(set! *warn-on-reflection* true)

(deftest pad4-behavior
  (testing "pad4 pads to multiples of 4 with zeros"
    (let [b0 (byte-array 0)
          b1 (u8-ba 1)
          b2 (u8-ba 1 2)
          b3 (u8-ba 1 2 3)
          b4 (u8-ba 1 2 3 4)
          p0 (pad4 b0)
          p1 (pad4 b1)
          p2 (pad4 b2)
          p3 (pad4 b3)
          p4 (pad4 b4)]
      (is (= 0 (alength p0)))
      (is (= 4 (alength p1)))
      (is (= 4 (alength p2)))
      (is (= 4 (alength p3)))
      (is (= 4 (alength p4)))
      ;; Original content preserved at the front
      (is (= [1 0 0 0] (u8-vec p1)))
      (is (= [1 2 0 0] (u8-vec p2)))
      (is (= [1 2 3 0] (u8-vec p3))))))

;;; NOTE: spec writes `0x434e4f4e`.  this is big-endian.  bytes on
;;; wire are reverse of that.

(deftest ascii-tag-known-values
  (testing "\"NONC\" encodes to 0x434e4f4e (LE bytes [4e 4f 4e 43])"
    (let [b (tag/tag->bytes "NONC")]
      (is (= 4 (alength b)))
      (is (= "4e4f4e43" (bytes->hex-string b)))))
  (testing "\"VER\" encodes to 0x00524556 (LE bytes [56 45 52 00])"
    (let [b (tag/tag->bytes "VER")]
      (is (= 4 (alength b)))
      (is (= "56455200" (bytes->hex-string b))))))

(deftest byte-array-tag-handling
  (testing "tag->bytes handles raw byte-arrays (e.g. Google PAD\\xff)"
    (let [;; Google PAD tag: 'P' 'A' 'D' 0xFF
          google-pad (byte-array [(byte \P) (byte \A) (byte \D) (unchecked-byte 0xff)])
          encoded    (tag/tag->bytes google-pad)]
      (is (= 4 (alength encoded)))
      ;; 50 41 44 ff
      (is (= "504144ff" (bytes->hex-string encoded))
          "Google padding tag must preserve the 0xFF trailing byte"))))

(deftest ascii-tag-roundtrip
  (testing "Round-trip for 1..4 char tags"
    (doseq [s ["A" "AB" "ABC" "ABCD" "NONC" "VER" "ZZZZ"]]
      (let [enc (tag/tag->bytes s)
            dec (tag/bytes->tag enc)]
        ;; The decoded string should equal the original (no trailing NULs)
        (is (= s dec) (str "round-trip failed for " s))))))

(defn- hex-string->tag
  [h]
  (tag/bytes->tag (hex-string->bytes h)))

(deftest bytes->tag-accepts-signed-bytes
  (testing "Decoding works even if the byte array contains signed bytes (JVM bytes)"
    (is (= "VER" (hex-string->tag "56455200")))
    (is (= "NONC" (hex-string->tag "4e4f4e43")))))

;; TODO: add all these:

(def ^:private tag-registry
 {"CERT" "43455254"
  "INDX" "494e4458"
  "MAXT" "4d415854"
  "MIDP" "4d494450"
  "MINT" "4d494e54"
  "NONC" "4e4f4e43"
  "PATH" "50415448"
  "PUBK" "5055424b"
  "RADI" "52414449"
  "ROOT" "524f4f54"
  "SIG"  "53494700"
  "SREP" "53524550"
  "SRV"  "53525600"
  "TYPE" "54595045"
  "VER"  "56455200"
  "VERS" "56455253"
  "ZZZZ" "5a5a5a5a"})

(deftest ascii-tag-all-known-values
  (testing "check all registered tag values"
   (doseq [[k h] tag-registry]
     (let [b (tag/tag->bytes k)]
       (is (= 4 (alength b)) (str "wrong length for tag: " k))
       (is (= h (bytes->hex-string b))
           (str "encoding failed for tag: " k))))))

(deftest tag-decoding-hybrid-types
  (testing "bytes->tag returns String for ASCII and byte-array for binary"
    (let [ascii-enc (tag/tag->bytes "NONC")
          bin-enc   (byte-array [(byte \P) (byte \A) (byte \D) (unchecked-byte 0xff)])]

      (is (string? (tag/bytes->tag ascii-enc)))
      (is (= "NONC" (tag/bytes->tag ascii-enc)))

      (is (bytes? (tag/bytes->tag bin-enc)))
      (is (bytes= bin-enc (tag/bytes->tag bin-enc))))))

(deftest tag-numeric-ordering-test
  (testing "Verify ordering for Google vs IETF padding tags"
    (let [legacy-pad    "PAD"                                          ;; Early IETF (0x00444150)
          modern-pad    "ZZZZ"                                         ;; Modern IETF (0x5a5a5a5a)
          google-pad-ff (byte-array [(byte \P) (byte \A) (byte \D)
                                     (unchecked-byte 0xff)])           ;; Google Legacy (0xff444150)

          ;; Convert all to their uint32 wire values
          val-legacy (e/uint32-le->long (tag/tag->bytes legacy-pad))
          val-modern (e/uint32-le->long (tag/tag->bytes modern-pad))
          val-google (e/uint32-le->long (tag/tag->bytes google-pad-ff))]

      (testing "Numeric hierarchy"
        ;; PAD (4,473,168) < ZZZZ (1,515,870,810) < PAD\xff (4,282,663,248)
        (is (< val-legacy val-modern) "PAD must be less than ZZZZ")
        (is (< val-modern val-google) "ZZZZ must be less than PAD\\xff")
        (is (< val-legacy val-google) "PAD must be less than PAD\\xff"))

      (testing "Logical sorting"
        (let [unsorted [google-pad-ff modern-pad legacy-pad]
              sorted   (sort-by #(e/uint32-le->long (tag/tag->bytes %)) unsorted)]
          (is (= [legacy-pad modern-pad google-pad-ff] (vec sorted))
              "Tags must sort numerically: PAD -> ZZZZ -> PAD\\xff"))))))
