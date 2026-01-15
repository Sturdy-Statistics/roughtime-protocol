(ns roughtime-protocol.srv
  (:require
   [roughtime-protocol.util :refer [sha512-bytes]]))

(set! *warn-on-reflection* true)

(defn srv-value
  "Compute SRV = SHA512(0xff || public_key)[0:32],
   where public_key is the 32-byte Ed25519 long-term key."
  ^bytes [^bytes longterm-pubkey]
  (let [prefix (unchecked-byte 0xff)]
    (sha512-bytes 32 prefix longterm-pubkey)))
