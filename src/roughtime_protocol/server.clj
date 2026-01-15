(ns roughtime-protocol.server
  (:require
   [roughtime-protocol.srep :as srep]
   [roughtime-protocol.compat :as compat]
   [roughtime-protocol.merkle :as merkle]

   [roughtime-protocol.config :as config]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.sign :as sign]
   [roughtime-protocol.sig  :as sig]
   [roughtime-protocol.cert :as cert]

   [roughtime-protocol.request :as rq]
   [roughtime-protocol.response :as rsp]

   [taoensso.truss :refer [have]])
  (:import
   (java.security PrivateKey)))

(set! *warn-on-reflection* true)

(defn mint-new-certificate-map
  "Makes a new online keypair and mints DELE certificates compatible with
  different versions of the protocol.  Returns a map with keys
    `:online-prv!!` ↦ online private key
    {every supported version} ↦ DELE cert compatible with that version"
  [^PrivateKey lt-prv!! & {:keys [expires-in-seconds]
                           :or {expires-in-seconds 3600}}]
  (let [online-key (sign/gen-ed25519-kp)

        ;; Google protocol specifies time in microseconds; all other
        ;; protocols specify time in seconds.
        t0         (u/now-seconds)
        t0-goog    (u/now-micros)

        expires-in-us (* 1000 1000 expires-in-seconds)

        ;; version 0 certificate: old dele context, time in micros
        cert-v0    (cert/make-certificate
                    (.getPublic online-key)
                    lt-prv!!
                    {:mint-seconds t0-goog
                     :maxt-seconds (+ t0-goog expires-in-us)
                     :version 0x00})

        ;; version 1 certificate (IETF draft v1-v11): old dele context
        cert-v1    (cert/make-certificate
                    (.getPublic online-key)
                    lt-prv!!
                    {:mint-seconds t0
                     :maxt-seconds (+ t0 expires-in-seconds)
                     :version 0x8000000b}) ;any version from 1 - 11 is OK

        ;; version 12 certificate (IETF draft 12): new dele context
        cert-v12   (cert/make-certificate
                    (.getPublic online-key)
                    lt-prv!!
                    {:mint-seconds t0
                     :maxt-seconds (+ t0 expires-in-seconds)
                     :version 0x8000000c})]

    (letfn [(f [v] (cond
                     (= 0x00 v) cert-v0
                     (<= 0x80000001 v 0x8000000b) cert-v1
                     (<= 0x8000000c v)            cert-v12))]
      (into {:online-prv!! (.getPrivate online-key)}
            (for [v config/supported-versions]
              [v (f v)])))))

(defn respond
  "Respond to a single RoughTime request.

   Depending on the version, this is either a full Roughtime **packet**
   (with ROUGHTIM header), or a bare RoughTime **message**.

   ARGS

    :request-bytes - the full request (packet or message, depending on version).
    :cert-map - a map containing:
      - `:online-prv!!` ↦ online private key
      - {every supported version} ↦ DELE cert compatible with that version

   Returns bytes on success; otherwise throws."
  [{:keys [^bytes request-bytes
           cert-map
           ^long min-size-bytes]
    :or {min-size-bytes config/min-msg-size}}]
  (let [{:keys [nonce version _client-vers _message]}
        (rq/parse-request request-bytes {:min-size-bytes min-size-bytes})

        ;; hard-code for a single response
        index          0
        leaves         [(compat/merkle-leaf-data version nonce request-bytes)]

        ;; merkle tree
        opts           (compat/merkle-opts version)
        root           (merkle/compute-root leaves opts)
        path-bytes     (merkle/build-path leaves index opts)

        ;; signed response
        srep-bytes     (srep/srep-bytes root {:nonce nonce :version version})

        cert-bytes     (get cert-map version)]

    (rsp/response-bytes
     {:request-packet request-bytes
      :chosen-version version
      :nonce nonce
      :srep-bytes srep-bytes
      :online-prv (have some? (:online-prv!! cert-map))
      :cert-bytes (have bytes? cert-bytes)
      :index index
      :path path-bytes})))

(defn batch-respond--single-version
  [version parsed-request-batch cert-map]

  (when (contains? #{0x80000001 0x80000002} version)
    (throw (ex-info "Cannot batch draft versions 1 or 2 since SREP contains NONC"
                    {:version version})))

  (let [vs (mapv :version parsed-request-batch)]
    (when-not (apply = vs)
      (throw (ex-info "Batched requests must have consistent version."
                      {:expected-versions version
                       :versions vs}))))

  (letfn [;; data for leaf node based on version
          (leaf-data [parsed-req] (let [v  (:version       parsed-req)
                                        nc (:nonce         parsed-req)
                                        rb (:request-bytes parsed-req)]
                                    (compat/merkle-leaf-data v nc rb)))]

    (let [bytes-batch  (mapv :request-bytes parsed-request-batch)
          leaves       (mapv leaf-data parsed-request-batch)
          index-batch  (vec (range (count parsed-request-batch)))
          nonce-batch  (mapv :nonce parsed-request-batch)

          opts         (compat/merkle-opts version)

          {:keys [root paths]} (merkle/build-all leaves opts)
          path-batch   paths

          ;;root         (merkle/compute-root leaves opts)
          srep-bytes   (srep/srep-bytes root {:version version})
          cert-bytes   (get cert-map version)

          online-prv   (have some? (:online-prv!! cert-map))
          signature    (sig/sign-srep srep-bytes online-prv)]

      (mapv
       #(rsp/response-bytes
         {:request-packet (have bytes? %1)
          :chosen-version version
          :nonce (have bytes? %2)
          :srep-bytes srep-bytes
          :online-prv nil
          :signature signature
          :cert-bytes (have bytes? cert-bytes)
          :index %3
          :path %4})

       bytes-batch
       nonce-batch
       index-batch
       path-batch))))

(defn- batch-respond--helper
  [respond groups]
  (->>
   ;; loop over versions in the batch
   (for [[version sub-batch] groups]
     (let [pos-vals (mapv :pos sub-batch)]
       (if version
         ;; parse succeeded → process batch
         (let [resp-batch (respond version sub-batch)]
           (zipmap pos-vals resp-batch))
         ;; parse failed → return nil for each request
         (zipmap pos-vals (repeat nil)))))

   ;; map of pos → response-bytes for the entire batch sorted by pos
   (into (sorted-map))))

(defn batch-respond
  "Respond to a batch of RoughTime requests, which may ask for different versions.

   ARGS

    * `request-batch` - vec of full request bytes (packet or message, depending on version).
    * :cert-map - a map containing:
      - `:online-prv!!` ↦ online private key
      - {every supported version} ↦ DELE cert compatible with that version

   Returns a vec of responses matching the order of requests.  Invalid or unsupported
   requests receive a `nil` response.

   NOTE: versions 1 & 2 of the IETF protocal cannot be batched.  They receive nil responses
   from this function."
  [request-batch cert-map & {:keys [min-size-bytes]
                             :or {min-size-bytes config/min-msg-size}}]
  (letfn [ ;; returns {:keys [:nonce :request-bytes :version :client-vers :message :message-len]}
          (parse [^bytes request-bytes]
            (try
              (rq/parse-request request-bytes
                                {:min-size-bytes min-size-bytes})
              (catch Throwable _
                nil)))

          (add-order [batch] (mapv #(assoc %1 :pos %2) batch (range (count batch))))

          (respond [version sub-batch]
            (try
              (batch-respond--single-version version sub-batch cert-map)
              (catch Throwable _
                (vec (repeat (count sub-batch) nil)))))]

    (let [;; parse all.  parse failures → nil
          parsed-batch' (mapv parse request-batch)

          ;; add a :pos indexing original order
          parsed-batch  (add-order parsed-batch')

          ;; group by version.
          ;; map of version ↦ [parsed-batch]
          ;; failed parses end up under the `nil` key
          groups       (group-by :version parsed-batch)

          responses    (batch-respond--helper respond groups)]

      ;; every response should be present (even if nil) and sorted
      (assert (= (range (count request-batch))
                 (keys responses)))

      ;; return the response values
      (vec (vals responses)))))
