(ns roughtime-protocol.srep
  (:require
   [roughtime-protocol.config :as config]
   [roughtime-protocol.util   :refer [now-seconds now-micros]]
   [roughtime-protocol.tlv    :as tlv]
   [roughtime-protocol.endian :as e]
   [taoensso.truss :refer [have]]))

(set! *warn-on-reflection* true)

(defn radi-seconds
  "The RADI tag value MUST be a uint32 representing the server's
  estimate of the accuracy of MIDP in seconds.  Servers that do not
  have any leap second information SHOULD set the value of RADI to
  at least 3."
  ^bytes []
  10)

;;; Google protocol and IETF v0

;; |--SREP
;; |  |-- ROOT
;; |  |-- MIDP
;; |  |-- RADI

(defn- build-google-response
  [{:keys [^bytes root
           ^bytes midp-bytes
           ^bytes radi-bytes]}]
  (tlv/encode-rt-message
   {"ROOT" (have some? root)
    "MIDP" (have some? midp-bytes)
    "RADI" (have some? radi-bytes)}))

;; IETF protocol, versions 1 & 2

;; |--SREP
;; |  |-- ROOT
;; |  |-- MIDP
;; |  |-- RADI
;; |  |-- NONC

(defn- build-ietf-pre-v3-response
  [{:keys [^bytes root
           ^bytes midp-bytes
           ^bytes radi-bytes
           ^bytes nonce]}]
  (tlv/encode-rt-message
   {"ROOT" (have some? root)
    "MIDP" (have some? midp-bytes)
    "RADI" (have some? radi-bytes)
    "NONC" (have some? nonce)}))

;; IETF protocol, versions 3-11

;; |--SREP
;; |  |--RADI
;; |  |--MIDP
;; |  |--ROOT

;;; note not identical to Google: google ROOT is 64 bytes; here 32
(defn- build-ietf-pre-v12-response
  [{:keys [^bytes root
           ^bytes midp-bytes
           ^bytes radi-bytes]}]
  (tlv/encode-rt-message
   {"ROOT" (have some? root)
    "MIDP" (have some? midp-bytes)
    "RADI" (have some? radi-bytes)}))

;; IETF protocol, versions 12-15

;; |--SREP
;; |  |--VER
;; |  |--RADI
;; |  |--MIDP
;; |  |--VERS
;; |  |--ROOT

(defn- build-current-ietf-response
  [{:keys [^bytes root
           ^bytes midp-bytes
           ^bytes radi-bytes
           ^bytes ver-bytes
           ^bytes vers-bytes]}]
  (tlv/encode-rt-message
   {"VER"  (have some? ver-bytes)
    "RADI" (have some? radi-bytes)
    "MIDP" (have some? midp-bytes)
    "VERS" (have some? vers-bytes)
    "ROOT" (have some? root)}))


(defn srep-bytes
  "Build SREP nested TLV per §5.2.5.

  Args:
    - root: 32-byte Merkle root (from merkle/compute-root)
    - options:
        :chosen-version - uint32 protocol version
        :midp           - uint64 midpoint time (defaults to now)
        :radi           - uint32 radius (defaults to 10)"
  ^bytes
  [^bytes root {:keys [^Integer version
                       ^Integer midp
                       ^Integer radi
                       ^bytes nonce]
                :or   {radi (radi-seconds)}}]

  (when-not (some #{(have some? version)} config/supported-versions)
    (throw (ex-info "VER must be included in VERS"
                    {:VER version :VERS config/supported-versions})))

  (when-not (pos? radi)
    (throw (ex-info "RADI must be non-zero" {:radi radi})))

  (let [midp (or midp
                 (if (= 0x00 version) (now-micros) (now-seconds)))
        args {:radi-bytes (e/long->uint32-le radi)
              :midp-bytes (e/long->uint64-le midp)
              :root (have bytes? root)}]

    (cond
      ;; Google Protocol
      (= version 0x00)
      (build-google-response args)

      ;; IETF (v1-v2)
      (<= 0x80000001 version 0x80000002)
      (build-ietf-pre-v3-response (assoc args
                                         :nonce (have bytes? nonce)))

      ;; IETF (v3-v11)
      (<= 0x80000003 version 0x8000000b)
      (build-ietf-pre-v12-response args)


      ;; Modern IETF (v3+)
      (<= 0x8000000c version)
      (build-current-ietf-response
       (assoc args
              :ver-bytes  (e/long->uint32-le version)
              :vers-bytes (e/u32-list->bytes config/supported-versions)))

      :else
      (throw (ex-info "Unsupported protocol version for response" {:version version})))))
