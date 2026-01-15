(ns roughtime-protocol.sign-test
  (:require
    [clojure.test            :refer [deftest is testing]]
    [clojure.string          :as str]
    [roughtime-protocol.sign :as sign])
  (:import
    (java.nio.charset StandardCharsets)))

(set! *warn-on-reflection* true)

;; ---------- tiny hex helpers (for fixtures) ----------

(defn hex->bytes ^bytes [^String s]
  (let [s (str/replace s #"[\s:]" "")]
    (byte-array
      (map (fn [[a b]]
             (unchecked-byte (Integer/parseInt (str a b) 16)))
           (partition 2 s)))))

(defn bytes->hex [^bytes bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn utf8-bytes ^bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

;; ---------- RFC 8032 test vector #1 (Ed25519, message = empty) ----------
;; https://www.rfc-editor.org/rfc/rfc8032 (Ed25519 test vectors)
;; seed (32), public (32), signature (64) for empty message.

(def rfc8032-v1
  {:seed "9d61b19deffd5a60ba844af492ec2cc4
          4449c5697b326919703bac031cae7f60"
   :pub  "d75a980182b10ab7d54bfed3c964073a
          0ee172f3daa62325af021a68f707511a"
   :sig  "e5564300c360ac729086e2cc806e828a
          84877f1eb8e5d974d873e06522490155
          5fb8821590a33bacc61e39701cf9b46b
          d25bf5f0595bbe24655141438e7a100b"})

;; ---------- Tests ----------

(deftest sign-verify-basic
  (testing "sign/verify round-trip succeeds"
    (let [kp      (sign/gen-ed25519-kp)
          prv     (.getPrivate kp)
          pub     (.getPublic  kp)
          msg     (utf8-bytes "hello roughtime")
          sig     (sign/sign msg prv)]
      (is (= 64 (alength sig)))
      (is (true? (sign/verify msg pub sig))))))

(deftest sign-verify-negative-cases
  (testing "wrong key or mutated message fails verification"
    (let [kp1 (sign/gen-ed25519-kp)
          kp2 (sign/gen-ed25519-kp)
          prv (.getPrivate kp1)
          pub1 (.getPublic kp1)
          pub2 (.getPublic kp2)
          msg (utf8-bytes "authentic message")
          bad (utf8-bytes "tampered message")
          sig (sign/sign msg prv)]
      (is (false? (sign/verify bad pub1 sig)) "mutated message should fail")
      (is (false? (sign/verify msg pub2 sig)) "wrong public key should fail"))))

(deftest determinism-ed25519
  (testing "Ed25519 signatures are deterministic for the same msg+key"
    (let [kp  (sign/gen-ed25519-kp)
          prv (.getPrivate kp)
          msg (utf8-bytes "determinism")]
      (is (= (bytes->hex (sign/sign msg prv))
             (bytes->hex (sign/sign msg prv)))))))

(deftest thread-safety-via-thread-local
  (testing "threaded sign/verify loops succeed (Signature is thread-local)"
    (let [kp  (sign/gen-ed25519-kp)
          prv (.getPrivate kp)
          pub (.getPublic  kp)
          msgs (map #(utf8-bytes (str "msg-" %)) (range 200))
          results (doall
                    (pmap (fn [m]
                            (let [sig (sign/sign m prv)]
                              (and (= 64 (alength sig))
                                   (sign/verify m pub sig))))
                          msgs))]
      (is (every? true? results)))))

(deftest spki-pkcs8-raw-roundtrips
  (testing "SPKI/PKCS#8 <-> raw 32-byte conversions round-trip"
    (let [kp     (sign/gen-ed25519-kp)
          pub    (.getPublic kp)
          prv    (.getPrivate kp)
          rawpub (sign/public-key->raw-pub32 pub)
          rawseed (sign/private-key->raw-seed32 prv)
          pub2   (sign/raw-pub32->public-key rawpub)
          prv2   (sign/raw-seed32->private-key rawseed)
          msg    (utf8-bytes "round-trip")]
      ;; sanity: lengths
      (is (= 32 (alength rawpub)))
      (is (= 32 (alength rawseed)))
      ;; use reconstructed keys for sign/verify
      (let [sig (sign/sign msg prv2)]
        (is (true? (sign/verify msg pub2 sig)))))))

(deftest rfc8032-known-answer
  (testing "Matches RFC 8032 Ed25519 test vector #1 (empty message)"
    (let [seed   (hex->bytes (:seed rfc8032-v1))
          pubraw (hex->bytes (:pub  rfc8032-v1))
          sigexp (hex->bytes (:sig  rfc8032-v1))
          ;; Build keys from raw forms
          prv    (sign/raw-seed32->private-key seed)
          pub    (sign/raw-pub32->public-key  pubraw)
          msg    (byte-array 0)
          sig    (sign/sign msg prv)]
      ;; Signature must equal the vector signature and verify
      (is (= (bytes->hex sig) (bytes->hex sigexp)) "signature must match vector")
      (is (true? (sign/verify msg pub sig))))))

(deftest input-validation
  (testing "raw wrappers enforce 32-byte size"
    (is (thrown? IllegalArgumentException
                 (sign/raw-pub32->public-key (byte-array 31))))
    (is (thrown? IllegalArgumentException
                 (sign/raw-seed32->private-key (byte-array 33))))))
