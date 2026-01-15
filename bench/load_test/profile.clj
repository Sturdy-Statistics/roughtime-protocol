(ns load-test.profile
  (:require
   [roughtime-protocol.sign :as sign]
   [roughtime-protocol.util :as u]

   [roughtime-protocol.request :as rq]
   [roughtime-protocol.server :as server]
   [roughtime-protocol.client :as client]

   [clj-async-profiler.core :as prof]))

(set! *warn-on-reflection* true)

(defn- nanos->micros ^long [^long nanos]
  (quot nanos 1000))

(defn runme-batched []
  (let [lt!!     (sign/gen-ed25519-kp)
        lt-pub   (.getPublic lt!!)
        lt-prv!! (.getPrivate lt!!)

        public-key (-> lt-pub sign/public-key->raw-pub32)

        cert-map   (server/mint-new-certificate-map lt-prv!!)

        ver        0x8000000c]

    (letfn [(req [_]
              (rq/make-request
               {:ver [ver] :msg-size 1024 :public-key public-key}))

            (parse [^bytes request-bytes]
              (rq/parse-request request-bytes
                                {:min-size-bytes 1024}))

            (exch [^bytes request-bytes ^bytes response-bytes]
              (client/response->exchange
               {:request-bytes   request-bytes
                :response-bytes  {:bytes response-bytes}
                :server-map      {:public-key (u/bytes->b64 public-key)}}))]

      (let [batch-size    128
            request-batch (mapv req (range batch-size))

            parsed-batch  (mapv parse request-batch)

            n         100
            t0        (System/nanoTime)
            _         (dotimes [_ (dec n)] (server/batch-respond--single-version
                                            ver parsed-batch cert-map))
            resp-batch    (server/batch-respond--single-version
                           ver parsed-batch cert-map)
            t1        (System/nanoTime)
            respond-us (nanos->micros (quot (- t1 t0) (* n batch-size)))

            exch-batch    (mapv exch request-batch resp-batch)  ]

        (doseq [exchange exch-batch]
          (client/validate-response exchange))
        {:response-time-us respond-us}))))

(def ^bytes dummy-sig
  ;; 64-byte constant signature (Ed25519 signatures are 64 bytes)
  (byte-array 64 (byte 0x42)))

(defn run
  "Entry point for load testing: compile, check status, and download files."
  [_]

  (if false ;; whether to include or stub signatures

    ;; include signatures
    (do
      (runme-batched)

      (prof/profile
       (dotimes [_ 5]
         (runme-batched))))

    ;; stub out signatures
    (do
      (with-redefs [sign/sign-with-context   (fn ^bytes [_ctx _content _prv] dummy-sig)
                    sign/verify-with-context (fn [_ctx _content _pub _sig] true)]
        (runme-batched))

      (prof/profile
       (dotimes [_ 5]
         (with-redefs [sign/sign-with-context   (fn ^bytes [_ctx _content _prv] dummy-sig)
                       sign/verify-with-context (fn [_ctx _content _pub _sig] true)]
           (runme-batched))))))

  (prof/serve-ui 8080))
