(ns roughtime-protocol.core-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [roughtime-protocol.config :as config]
   [roughtime-protocol.sign :as sign]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.request :as rq]
   [roughtime-protocol.server :as server]
   [roughtime-protocol.client :as client]))

(set! *warn-on-reflection* true)

(defn- assert-not-throws!
  "Asserts that (f) does not throw; returns f's value."
  [msg f]
  (try
    (f)
    (catch Throwable t
      (is false (str msg "\nThrew: " (.getClass t) "\n" (.getMessage t)))
      ::threw)))

(deftest end-to-end-roundtrip-test
  (testing "RoughTime end-to-end request/response/validation across supported versions"
    (let [lt!!     (sign/gen-ed25519-kp)
          lt-pub   (.getPublic lt!!)
          lt-prv!! (.getPrivate lt!!)

          public-key (-> lt-pub sign/public-key->raw-pub32)

          cert-map   (server/mint-new-certificate-map lt-prv!!)]

      (doseq [ver config/supported-versions]
        (testing (format "ver=0x%08x" ver)
          (let [req-bytes (rq/make-request
                           {:ver [ver]
                            :msg-size 1024
                            :public-key public-key})

                rsp-bytes (server/respond {:request-bytes req-bytes
                                           :cert-map cert-map})

                exchange  (client/response->exchange
                           {:request-bytes   req-bytes
                            :response-bytes  {:bytes rsp-bytes}
                            :server-map      {:public-key (u/bytes->b64 public-key)}})]

            ;; validate-response throws on failure, so assert it doesn't throw
            (assert-not-throws! "Response validation should not throw"
                                #(client/validate-response exchange))
            (is (map? (client/process-time exchange)))))))))
