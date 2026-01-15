(ns roughtime-protocol.batched-response-test
  (:require
   [clojure.test :refer [deftest is testing are]]
   [clojure.edn :as edn]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.tlv :as tlv]
   [roughtime-protocol.merkle :as m]
   [roughtime-protocol.packet :as packet]
   [roughtime-protocol.client :as c]))

(set! *warn-on-reflection* true)

;; Helpers

(defn- wrap-response
  "Wraps a specific reply from a batch for the validator."
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

(defn- reconstruct-root-wrong
  [exchange]
  (let [index      (get-in exchange [:parsed "INDX"])
        path-bytes (get-in exchange [:parsed "PATH"])
        ;; NOTE: this is not correct for all versions!
        leaf-data  (get-in exchange [:parsed "NONC"])
        root-data  (get-in exchange [:parsed "SREP" "ROOT"])

        bad-root (m/reconstruct-root {:leaf-data leaf-data
                                      :path-bytes path-bytes
                                      :index (bit-xor index 1)}
                                     ;; NOTE: this is not correct for all versions!
                                     {:hash-size 32
                                      :tree-order :natural})]
    (is (not (u/bytes= bad-root root-data))
        "PATH should NOT validate without the correct index")))

(defn- run-vector-test
  "Executes the validation logic for a specific test vector file."
  [{:keys [fname version batch-size overrides]}]
  (let [{:keys [lt-pub request replies]} (-> fname slurp edn/read-string)
        lt-pub-bytes (u/hex-string->bytes lt-pub)]

    (testing (format "File: %s (Draft: %s, Batch: %d)"
                     fname (or version "Google") batch-size)

      (is (= (count request) (count replies))
          "Test vector should have a reply for every request")

      (doseq [idx (range (count request))]
        (let [req-bytes  (u/hex-string->bytes (nth request idx))
              resp-bytes (u/hex-string->bytes (nth replies idx))
              wrapped    (wrap-response req-bytes resp-bytes lt-pub-bytes)]
          ;; Using nested testing labels helps identify which leaf failed
          (testing (str "leaf index: " idx)
            (is (= :ok (c/validate-response wrapped (when overrides
                                                      {:overrides overrides})))
                (str "Failed to validate batch leaf at index " idx))

            (when (contains? #{8 11 0x80000008 0x8000000b} version)
              (reconstruct-root-wrong wrapped)))))))
  :ok)

;; Test Definition

(deftest batched-verification-test
  (testing "IETF Draft 08"
    (are [fname ver b-size] (run-vector-test {:fname fname :version ver :batch-size b-size})
      "test-resources/batch-request/roughtime_ietf_draft08_010.edn" 8 10
      "test-resources/batch-request/roughtime_ietf_draft08_100.edn" 8 100))

  (testing "IETF Draft 11"
    (are [fname ver b-size] (run-vector-test {:fname fname :version ver :batch-size b-size})
      "test-resources/batch-request/roughtime_ietf_draft11_010.edn" 11 10
      "test-resources/batch-request/roughtime_ietf_draft11_100.edn" 11 100))

  (testing "Google Legacy"
      (are [fname ver b-size] (run-vector-test {:fname fname :version ver :batch-size b-size
                                                :overrides {:tree-order :natural}})
        "test-resources/batch-request/roughtime_google_010.edn" nil 10
        "test-resources/batch-request/roughtime_google_100.edn" nil 100)))
