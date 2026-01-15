(ns roughtime-protocol.response
  (:require
   [roughtime-protocol.config :as config]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.tlv    :as tlv]
   [roughtime-protocol.srep   :as srep]
   [roughtime-protocol.sig    :as sig]
   [taoensso.truss :refer [have]])
  (:import
   (java.security PrivateKey)))

(set! *warn-on-reflection* true)

(def RESPONSE-TYPE
  "TYPE value for responses."
  (e/long->uint32-le 1))

;;; Google protocol and IETF v0

;; |--SREP
;; |  |-- ROOT
;; |  |-- MIDP
;; |  |-- RADI
;; |--SIG
;; |--INDX
;; |--PATH
;; |--CERT
;; |  |--SIG
;; |  |--DELE
;; |  |  |--MINT
;; |  |  |--MAXT
;; |  |  |--PUBK

(defn- build-google-response
  [{:keys [^bytes srep-bytes
           ^bytes signature
           ^bytes cert-bytes
           ^Integer index
           ^bytes path]}]
  (tlv/encode-rt-message
   {"SREP" (have some? srep-bytes)
    "SIG"  (have some? signature)
    "INDX" (e/long->uint32-le (have integer? index))
    "PATH" (have some? path)
    "CERT" (have some? cert-bytes)}))

;; IETF protocol, versions 1 & 2

;; |--SREP
;; |  |-- ROOT
;; |  |-- MIDP
;; |  |-- RADI
;; |  |-- NONC
;; |--SIG
;; |--VER
;; |--INDX
;; |--PATH
;; |--CERT
;; |  |--SIG
;; |  |--DELE
;; |  |  |--MINT
;; |  |  |--MAXT
;; |  |  |--PUBK

(defn- build-ietf-pre-v3-response
  [{:keys [^bytes srep-bytes
           ^Integer ver
           ^bytes signature
           ^bytes cert-bytes
           ^Integer index
           ^bytes path]}]
  (tlv/encode-rt-message
   {"SREP" (have some? srep-bytes)
    "SIG"  (have some? signature)
    "VER"  (e/long->uint32-le (have integer? ver))
    "CERT" (have some? cert-bytes)
    "INDX" (e/long->uint32-le (have integer? index))
    "PATH" (have some? path)}))

;; IETF protocol, versions 3-11

;; |--SIG
;; |--NONC
;; |--TYPE
;; |--PATH
;; |--VER
;; |--SREP
;; |  |--RADI
;; |  |--MIDP
;; |  |--ROOT
;; |--CERT
;; |  |--DELE
;; |  |  |--MINT
;; |  |  |--MAXT
;; |  |  |--PUBK
;; |  |--SIG
;; |--INDX

(defn- build-ietf-pre-v12-response
  [{:keys [^bytes srep-bytes
           ^bytes nonce
           ^bytes signature
           ^bytes cert-bytes
           ^Integer index
           ^bytes path
           ^Integer ver]}]
  (tlv/encode-rt-message
   {"SIG"  (have some? signature)
    "NONC" (have some? nonce)
    "TYPE" (have some? RESPONSE-TYPE)
    "PATH" (have some? path)
    "VER"  (e/long->uint32-le (have integer? ver))
    "SREP" (have some? srep-bytes)
    "CERT" (have some? cert-bytes)
    "INDX" (e/long->uint32-le (have integer? index))}))

;; IETF protocol, versions 12-15

;; |--SIG
;; |--NONC
;; |--TYPE
;; |--PATH
;; |--SREP
;; |  |--VER
;; |  |--RADI
;; |  |--MIDP
;; |  |--VERS
;; |  |--ROOT
;; |--CERT
;; |  |--DELE
;; |  |  |--MINT
;; |  |  |--MAXT
;; |  |  |--PUBK
;; |  |--SIG
;; |--INDX

(defn- build-current-ietf-response
  [{:keys [^bytes srep-bytes
           ^bytes nonce
           ^bytes signature
           ^bytes cert-bytes
           ^Integer index
           ^bytes path]}]
  (tlv/encode-rt-message
   {"SIG"  (have some? signature)
    "NONC" (have some? nonce)
    "TYPE" (have some? RESPONSE-TYPE)
    "PATH" (have some? path)
    "SREP" (have some? srep-bytes)
    "CERT" (have some? cert-bytes)
    "INDX" (e/long->uint32-le (have integer? index))}))

;; --- Main Entry Point ---

(defn response-bytes
  "Dispatches response construction based on the negotiated version."
  ^bytes
  [{:keys [^bytes request-packet
           ^Integer chosen-version
           ^bytes nonce
           ^bytes srep-bytes
           ^PrivateKey online-prv
           ^bytes cert-bytes
           ^Integer index
           ^bytes path
           ^bytes signature]
    :or   {index 0
           chosen-version config/fiducial-version
           path (byte-array 0)}}]
  (let [srep-bytes (or srep-bytes
                       (srep/srep-bytes request-packet
                                        {:version chosen-version
                                         :nonce nonce}))
        signature  (or signature
                       (sig/sign-srep srep-bytes online-prv))
        common-args {:srep-bytes srep-bytes
                     :signature signature
                     :cert-bytes cert-bytes
                     :index index
                     :path path}]
    (cond
      ;; Google Protocol
      (= chosen-version 0x00)
      (build-google-response common-args)

      ;; IETF (v1-v2)
      (<= 0x80000001 chosen-version 0x80000002)
      (build-ietf-pre-v3-response (assoc common-args
                                         :ver chosen-version))

      ;; IETF (v3-v11)
      (<= 0x80000003 chosen-version 0x8000000b)
      (build-ietf-pre-v12-response (assoc common-args
                                          :ver chosen-version
                                          :nonce nonce))

      ;; Modern IETF (v12+)
      (<= 0x8000000c chosen-version)
      (build-current-ietf-response (assoc common-args
                                          :nonce nonce))

      :else
      (throw (ex-info "Unsupported protocol version for response" {:version chosen-version})))))
