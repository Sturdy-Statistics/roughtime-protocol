(ns roughtime-protocol.cert-test
  (:require
   [clojure.test            :refer [deftest is testing]]
   [roughtime-protocol.util :refer [bytes=]]
   [roughtime-protocol.cert :as cert]
   [roughtime-protocol.sign :as ed]
   [roughtime-protocol.tlv  :as tlv]
   [roughtime-protocol.endian :as e])
  (:import
   (java.security PrivateKey PublicKey
                  KeyPair KeyPairGenerator)))

(set! *warn-on-reflection* true)

(defn gen-ed25519 ^KeyPair []
  (let [kpg (doto (KeyPairGenerator/getInstance "Ed25519")
              (.initialize 255))]
    (.generateKeyPair kpg)))

(deftest build-and-verify-cert
  (testing "DELE + CERT build and verify"
    (let [^KeyPair    lt   (gen-ed25519)
          ^PrivateKey lt-prv (.getPrivate lt)
          ^PublicKey  lt-pub (.getPublic lt)

          online (gen-ed25519)
          online-pub (.getPublic online)
          online-raw32 (-> online-pub
                           ed/public-key->raw-pub32)
          mint  1700000000
          maxt  1700086400
          version 0x8000000c

          certb (cert/make-certificate
                 online-pub lt-prv {:mint-seconds mint :maxt-seconds maxt :version version})
          info  (cert/verify-cert? certb lt-pub {:version version})]
      (is info)
      (is (= mint (:mint info)))
      (is (= maxt (:maxt info)))
      (is (bytes= online-raw32 (:pubk info)))

      ;; Tamper with the DELE message (change the timestamp)
      (let [m (tlv/decode-rt-message certb)
            bad-dele (tlv/encode-rt-message (assoc (tlv/decode-rt-message (get m "DELE"))
                                                   "MAXT" (e/long->uint64-le (inc maxt))))
            bad-cert (tlv/encode-rt-message (assoc m "DELE" bad-dele))]
        (is (nil? (cert/verify-cert? bad-cert lt-pub {:version version})) "Tampered DELE must fail verification"))

      ;; Use the wrong Long-Term Public Key
      (let [wrong-lt (gen-ed25519)
            wrong-pub (.getPublic wrong-lt)]
        (is (nil? (cert/verify-cert? certb wrong-pub {:version version})) "Wrong LT key must fail verification")))))
