(ns roughtime-protocol.cert
  (:require
   [roughtime-protocol.util :as util :refer [now-seconds]]
   [roughtime-protocol.tlv :as tlv]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.sign :as ed]
   [roughtime-protocol.sig :as sig]
   [roughtime-protocol.time :refer [format-duration]]
   [taoensso.truss :refer [have]])
  (:import
   (java.security PrivateKey PublicKey)))

(set! *warn-on-reflection* true)

(defn dele-bytes
  "Build the DELE (delegation) TLV message."
  ^bytes [^bytes online-pub-raw32 ^long mint-seconds ^long maxt-seconds]
  (when-not (= 32 (alength online-pub-raw32))
    (throw (ex-info "PUBK must be 32 raw bytes" {:len (alength online-pub-raw32)})))
  (when-not (< mint-seconds maxt-seconds)
    (throw (ex-info "MAXT must be greater than MINT" {:maxt maxt-seconds :mint mint-seconds})))
  (tlv/encode-rt-message
   {"PUBK" online-pub-raw32
    "MINT" (e/long->uint64-le (have pos? mint-seconds))
    "MAXT" (e/long->uint64-le (have pos? maxt-seconds))}))

(defn cert-bytes
  "Build the CERT TLV message by signing a DELE message."
  ^bytes [^bytes dele ^PrivateKey longterm-prv {:keys [version]}]
  (let [sig (sig/sign-dele dele longterm-prv {:version (have integer? version)})]
    (tlv/encode-rt-message {"DELE" dele
                            "SIG"  sig})))

(defn make-certificate
  "Full flow to delegate a new online key."
  ^bytes [^PublicKey online-pub ^PrivateKey longterm-prv
          {:keys [mint-seconds maxt-seconds version]}]
  (let [online-pub-raw32 (-> online-pub
                             ed/public-key->raw-pub32)
        dele (dele-bytes online-pub-raw32 mint-seconds maxt-seconds)]
    (cert-bytes dele longterm-prv {:version (have integer? version)})))

(defn verify-cert?
  "Verify a CERT against a long-term public key.
   Returns a map {:pubk raw32 :mint BigInt :maxt BigInt} on success."
  [^bytes cert ^PublicKey longterm-pub {:keys [version]}]
  (let [v    (have integer? version)
        m    (tlv/decode-rt-message cert)
        dele (get m "DELE")
        sig  (get m "SIG")]

    (when (and dele sig
               (sig/verify-dele? dele longterm-pub sig {:version v}))
      (let [dm      (tlv/decode-rt-message dele)
            pubk    (get dm "PUBK")
            mint-bs (get dm "MINT")
            maxt-bs (get dm "MAXT")
            f       (if (= 0x00 version) (fn [x] (quot x (* 1000 1000))) identity)]
        (when (and pubk mint-bs maxt-bs (= 32 (alength ^bytes pubk)))
          {:pubk pubk
           :mint (f (e/uint64-le->bigint mint-bs))
           :maxt (f (e/uint64-le->bigint maxt-bs))})))))

(defn check-cert-expiration
  "Returns human-readable expiration info for a certificate."
  [^bytes cert]
  (let [m    (tlv/decode-rt-message cert)
        dele (get m "DELE")
        dm   (tlv/decode-rt-message dele)
        maxt (get dm "MAXT")
        t0   (now-seconds)]
    {:now t0
     :exp maxt
     :expires-in (format-duration (- (long maxt) t0))}))
