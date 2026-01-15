(ns roughtime-protocol.client
  (:require
   [roughtime-protocol.util       :as util]
   [roughtime-protocol.time       :refer [format-duration]]
   [roughtime-protocol.tlv        :as tlv]
   [roughtime-protocol.compat     :as compat]
   [roughtime-protocol.merkle     :as merkle]
   [roughtime-protocol.packet     :as packet]
   [roughtime-protocol.request    :as request]
   [roughtime-protocol.client-udp :as udp]
   [roughtime-protocol.sig        :as sig]
   [roughtime-protocol.sign       :as sign]))

(set! *warn-on-reflection* true)

(defn build-request-packet
  ^bytes [server-map ^bytes nonce]
  (let [public-key (-> server-map :public-key util/b64->bytes)
        version-no (-> server-map :version-no)]
    (request/make-request
     {:public-key public-key
      :ver [version-no]
      :msg-size (:msg-size server-map)
      :nonce nonce})))

(defn response->exchange
  [{:keys [^bytes request-bytes
           ^bytes response-bytes
           server-map]}]
  (let [resp (-> (:bytes response-bytes)
                 (packet/decode-packet {:min-size-bytes 0})
                 :message
                 tlv/decode-rt-message-recursive)
        req  (-> request-bytes
                 (packet/decode-packet {:min-size-bytes 0})
                 :message
                 tlv/decode-rt-message-recursive)]
    {:parsed        resp
     :resp-bytes    response-bytes
     :request       req
     :request-bytes request-bytes
     :server-map    server-map
     :now           (util/now-seconds)}))

(defn make-request
  [server-map & {:keys [nonce]}]
  (let [req-raw   (build-request-packet server-map nonce)
        opts      {:timeout-ms 1000 :retries 2 :verify-src? true}
        resp-raw  (udp/send-udp server-map req-raw opts)]

    (response->exchange {:request-bytes req-raw
                         :response-bytes resp-raw
                         :server-map server-map})))

(defn- get-nonces-helper
  [exchange]
  (let [ ;;IETF v1-v2: inside SREP
        v1 (get-in exchange [:parsed "SREP" "NONC"])
        ;; IETF v3-v15: top-level
        v2 (get-in exchange [:parsed "NONC"])]
    (cond
      ;; prefer later
      (some? v2) v2
      ;; legacy IETF
      (some? v1) v1
      ;; google version doesn't have it
      :else nil)))

(defn- get-nonces
  [exchange]
  (let [;; NONC location in response changes with version
        returned  (get-nonces-helper exchange)
        ;; request always has NONC at top level
        original  (get-in exchange [:request "NONC"])]
    {:nonce-orig original
     :nonce-returned returned}))

(defn- get-version
  [exchange]
  (let [;;IETF v1-v11: top-level
        v1 (get-in exchange [:parsed "VER"])
        ;; IETF v12-v15: inside SREP
        v2 (get-in exchange [:parsed "SREP" "VER"])]
    (cond
      ;; prefer later
      (some? v2) v2
      ;; legacy ITEF
      (some? v1) v1
      ;; google version implicit
      :else 0x00)))

(defn- get-signed-data
  "Don't use :parsed here because we need the raw, original, bytes
  in order to check the signature."
  [exchange]
  (let [tmp       (-> (:resp-bytes exchange)
                      :bytes
                      (packet/decode-packet {:min-size-bytes 0})
                      :message)
        srep-raw  (get tmp "SREP") ; signed with top-level sig and dele pubk
        cert      (tlv/decode-rt-message (get tmp "CERT"))
        dele-raw  (get cert "DELE")]
    {:srep-bytes srep-raw
     :dele-bytes dele-raw}))

(defn- get-public-keys
  [exchange]
  (let [online-pub  (-> (get-in exchange [:parsed "CERT" "DELE" "PUBK"])
                        sign/raw-pub32->public-key)
        lt-pub      (-> (get-in exchange [:server-map :public-key])
                        util/b64->bytes
                        sign/raw-pub32->public-key)]
    {:online-pub online-pub
     :lt-pub lt-pub}))

(defn- get-timestamps
  [exchange]
  (let [midp  (get-in exchange [:parsed "SREP" "MIDP"])
        mint  (get-in exchange [:parsed "CERT" "DELE" "MINT"])
        maxt  (get-in exchange [:parsed "CERT" "DELE" "MAXT"])]
    {:mint mint :midp midp :maxt maxt}))

(defn- validate-root
  [exchange & {:keys [chosen-version overrides]}]

  (let [ ;; INDX and PATH always top-level
        index         (get-in exchange [:parsed "INDX"])
        path          (get-in exchange [:parsed "PATH"])
        ;; ROOT always inside SREP
        root-returned (get-in exchange [:parsed "SREP" "ROOT"])

        ;; NONC location depends on version
        {:keys [nonce-orig nonce-returned]} (get-nonces exchange)

        ;; Merkle leaf data depends on version
        leaf-data     (compat/merkle-leaf-data chosen-version
                                               nonce-orig
                                               (:request-bytes exchange))

        opts          (merge (compat/merkle-opts chosen-version)
                             overrides)

        root-ok?      (merkle/valid-proof? {:leaf-data leaf-data
                                            :index index
                                            :path-bytes path
                                            :root root-returned}
                                           opts)]

    (when (and nonce-returned          ;not all versions return a NONC
               (not (util/bytes= nonce-orig nonce-returned)))
      (throw (ex-info "Invalid nonce"
                      {:orig (util/bytes->hex-string nonce-orig)
                       :returned (util/bytes->hex-string nonce-returned)})))

    (when-not (:ok root-ok?)
      (throw (ex-info "Failed ROOT check"
                      {:returned (util/bytes->hex-string root-returned)
                       ;; returns the reconstruct-root on error
                       :reconstructed (util/bytes->hex-string (:root-reconst root-ok?))}))))
  :ok)

(defn validate-response
  [exchange & {:keys [overrides]}]
  (let [ ;; signed data (bytes)
        {:keys [srep-bytes dele-bytes]} (get-signed-data exchange)
        ;; version
        ver          (get-version exchange)
        ;; signatures
        dele-sig     (get-in exchange [:parsed "CERT" "SIG"])
        srep-sig     (get-in exchange [:parsed "SIG"])
        ;; signing keys
        {:keys [online-pub lt-pub]} (get-public-keys exchange)
        ;; timestamps
        {:keys [mint midp maxt]} (get-timestamps exchange)

        ;; tests
        srep-ok      (sig/verify-srep? srep-bytes online-pub srep-sig)
        dele-ok      (sig/verify-dele? dele-bytes lt-pub     dele-sig {:version ver})
        ;; NB validate-root throws on validation failure
        _root-ok     (validate-root exchange {:chosen-version ver
                                              :overrides overrides})
        time-ok      (<= mint midp maxt)
        ;;
        hx util/bytes->hex-string]

    (when-not dele-ok (throw (ex-info "Invalid delegation signature"
                                      {:dele-bytes    (hx dele-bytes)
                                       :dele          (-> exchange
                                                          (get-in [:parsed "CERT" "DELE"])
                                                          (tlv/print-rt-message-recursive))
                                       :lt-public-key (get-in exchange [:server-map :public-key])
                                       :dele-sig      (hx dele-sig)})))
    (when-not time-ok (throw (ex-info "Expired delegation signature"
                                      {:mint mint
                                       :maxt maxt
                                       :midp midp
                                       :expired-at (format-duration (- midp maxt))})))
    (when-not srep-ok (throw (ex-info "Invalid exchange signature"
                                      {:srep-bytes        (hx srep-bytes)
                                       :online-public-key (hx (get-in exchange [:parsed "CERT" "DELE" "PUBK"]))
                                       :srep-sig          (hx srep-sig)})))

    :ok))

(defn process-time [exchange]
  (let [{:keys [_mint maxt midp]} (get-timestamps exchange)
        version    (get-version exchange)
        f          (if (= 0x00 version) (fn [x] (quot x (* 1000 1000))) identity)

        local-time (:now exchange)
        skew       (long (- local-time (f midp)))
        exp        (- maxt midp)]
    {:skew skew
     :online-key-expires-in (format-duration (f exp))
     :maxt (f maxt)
     :midp (f midp)
     :local-time local-time}))
