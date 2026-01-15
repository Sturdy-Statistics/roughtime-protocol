(ns roughtime-protocol.single-request-test
  (:require
   [clojure.test :refer [deftest is testing are]]
   [clojure.edn :as edn]
   [clojure.pprint :refer [pprint]]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.tlv :as tlv]
   [roughtime-protocol.srv :as srv]
   [roughtime-protocol.packet :as packet]
   [roughtime-protocol.request :as rq]
   [roughtime-protocol.client :as c]))

(set! *warn-on-reflection* true)

;;; Helpers

(defn- wrap-response
  [^bytes request-bytes ^bytes response-bytes ^bytes lt-pub]
  (let [resp (-> response-bytes
                 (packet/decode-packet {:min-size-bytes 0})
                 :message
                 tlv/decode-rt-message-recursive)
        req  (-> request-bytes
                 (packet/decode-packet {:min-size-bytes 0})
                 :message
                 tlv/decode-rt-message-recursive)]
    {:parsed        resp
     :resp-bytes    {:bytes response-bytes}
     :request       req
     :request-bytes request-bytes
     :server-map    {:public-key (u/bytes->b64 lt-pub)}
     :now           nil}))

(defn pprint-packet
  [^bytes packet-bytes]
  (pprint
   (-> packet-bytes
       (packet/decode-packet {:min-size-bytes 0})
       :message
       tlv/decode-rt-message-recursive
       tlv/print-rt-message-recursive)))

;;; Core Assertion Logic

(defn check-request-logic
  "Substitutes the original check-request using clojure.test assertions."
  [lt-pub request-bytes request-nonce ver]
  (let [{:keys [nonce version client-vers message]}
        (rq/parse-request request-bytes {:min-size-bytes 1012})

        expected-ver-val (or ver 0)]

    (testing "Request Headers"
      (is (u/bytes= nonce request-nonce) "NONC tag must match the generated nonce")
      (is (= (first client-vers) expected-ver-val) "VER list mismatch")
      (is (= version expected-ver-val) "Header version field mismatch"))

    (testing "Request Payload (TLV)"
      (let [decoded-req (tlv/decode-rt-message-recursive message)
            srv-found   (get decoded-req "SRV")
            srv-expected (srv/srv-value lt-pub)]
        (when srv-found
          (is (u/bytes= srv-expected srv-found) "SRV tag mismatch in request body"))))))

;;; Test Definitions

(deftest request-packet-generation-test
  (testing "Round-trip generation and parsing for specific versions"
    (are [fname version]
      (let [{:keys [lt-pub nonce request msg-len]} (edn/read-string (slurp fname))
            request-bytes (u/hex-string->bytes (first request))
            nonce-bytes   (u/hex-string->bytes nonce)
            lt-pub-bytes   (u/hex-string->bytes lt-pub)

            ;; 1. Check if parsing matches expectations
            _ (check-request-logic lt-pub-bytes request-bytes nonce-bytes version)

            ;; 2. Check if regenerating the packet yields identical bytes
            ver-param (if version [version] [0])
            gen-req   (rq/make-request
                        {:ver         ver-param
                         :msg-size    msg-len
                         :nonce       nonce-bytes
                         :public-key  (if (= fname "test-resources/single-request/roughtime_ietf_draft14_001.edn")
                                        nil
                                        lt-pub-bytes)})]

        ;; (when-not (u/bytes= gen-req request-bytes)
        ;;   (println "actual:")
        ;;   (pprint-packet request-bytes)
        ;;   (println)
        ;;   (println "gen:")
        ;;   (pprint-packet gen-req)
        ;;   (println))

        (is (u/bytes= gen-req request-bytes)
            (str "Regenerated request bytes for " fname " should match test vector")))

      "test-resources/single-request/roughtime_ietf_draft14_001.edn" 0x8000000c
      "test-resources/single-request/roughtime_ietf_draft11_001.edn" 0x8000000b
      "test-resources/single-request/roughtime_ietf_draft08_001.edn" 0x80000008
      "test-resources/single-request/roughtime_google_001.edn"       nil       )))

(deftest response-validation-test
  (testing "Full Merkle and Signature validation for single-request responses"
    (doseq [fname ["test-resources/single-request/roughtime_ietf_draft08_001.edn"
                   "test-resources/single-request/roughtime_ietf_draft11_001.edn"
                   "test-resources/single-request/roughtime_ietf_draft14_001.edn"
                   ;;"test-resources/single-request/draft14_path8_indx2.edn"
                   "test-resources/single-request/roughtime_google_001.edn"]]
      (let [{:keys [lt-pub request replies]} (edn/read-string (slurp fname))
            request-bytes  (u/hex-string->bytes (first request))
            response-bytes (u/hex-string->bytes (first replies))
            lt-pub-bytes   (u/hex-string->bytes lt-pub)
            wrapped        (wrap-response request-bytes response-bytes lt-pub-bytes)]

        (testing (str "File: " fname)
          (is (= :ok (c/validate-response wrapped))
              "Response validation should complete successfully without throwing"))))))


;;; TODO: test responses
;;; for v0, v8, and v11 we have the LT private key
;;; make a CERT
;;; make response
