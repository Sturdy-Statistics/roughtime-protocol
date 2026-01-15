(ns roughtime-protocol.sig
  (:require
   [roughtime-protocol.config :refer [ctx-srep ctx-dele ctx-dele-google]]
   [roughtime-protocol.sign :as ed]
   [taoensso.truss :refer [have]])
  (:import
   (java.security PrivateKey PublicKey)))

(set! *warn-on-reflection* true)

(defn- get-ctx-dele [version]
  (cond
    (= 0 version)                      ctx-dele-google
    (<= 0x80000001 version 0x8000000b) ctx-dele-google
    (<= 0x8000000c version)            ctx-dele
    :else                              ctx-dele))

(defn sign-dele
  ^bytes [^bytes dele-bytes ^PrivateKey longterm-prv
          {:keys [version]}]
  (let [ctx (get-ctx-dele (have integer? version))]
    (ed/sign-with-context ctx dele-bytes longterm-prv)))

(defn sign-srep
  "Return 64-byte Ed25519 signature over ctx_srep || srep-bytes using ONLINE privkey."
  ^bytes [^bytes srep-bytes ^PrivateKey online-prv]
  (ed/sign-with-context ctx-srep srep-bytes online-prv))

(defn verify-srep?
  "Verify a SREP signature with the online public key."
  [^bytes srep-bytes ^PublicKey online-pub ^bytes signature]
  (ed/verify-with-context ctx-srep srep-bytes online-pub signature))

(defn verify-dele?
  "Verify a DELE signature with the long-term public key."
  [^bytes dele-bytes ^PublicKey lt-pub ^bytes signature
   & {:keys [version]}]
  (let [ctx (get-ctx-dele (have integer? version))]
   (ed/verify-with-context ctx dele-bytes lt-pub signature)))
