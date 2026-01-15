(ns roughtime-protocol.compat
  (:require
   [clojure.set :as cset]
   [roughtime-protocol.config :as config]
   [roughtime-protocol.util :as u]
   [roughtime-protocol.endian :as e]))

(set! *warn-on-reflection* true)

(defn pad-tag
  "Returns the appropriate padding tag (as a string or 4-byte array)
   based on the protocol version."
  [ver]
  (cond
    ;; Google protocol: "PAD" + 0xFF
    (or (nil? ver) (zero? ver))
    (byte-array [(byte \P) (byte \A) (byte \D) (unchecked-byte 0xff)])

    ;; 0x80000008 introduced "ZZZZ"
    (<= 0x80000008 ver 0x8000000c)
    "ZZZZ"

    ;; Versions 1 through 7: "PAD" + 0x00 (null padded)
    ;; tag/str->bytes pads "PAD" to "PAD\0"
    (<= 0x80000001 ver 0x80000007)
    "PAD"

    :else
    (throw (ex-info "Unknown VER tag for padding" {:version ver}))))

(defn choose-version [client-vers]
  (let [overlap (cset/intersection
                 (set client-vers)
                 config/supported-versions-set)]
    (cond
      ;; client vers nil or empty → google protocol
      (or (nil? client-vers) (empty? client-vers))
      0x00

      ;; empty overlap → we choose (§ 5.1.1)
      ;; https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15#section-5.1.1
      (empty? overlap)
      config/fiducial-version

      ;; v1 supercedes 0x8... series
      (contains? overlap 1)
      1

      ;; else, select the latest version in the overlap
      :else
      (apply max overlap))))

(defn required-nonce-length
  [^long ver]
  (cond
    ;; google protocol
    (or (nil? ver) (zero? ver))
    64

    ;; version 1 not released yet.  placeholder for logic
    (= 1 ver)
    (throw (ex-info "Unknown VER tag" {:ver ver}))

    ;; NONC changed to 32 bytes at version 0x80000005
    (<= 0x80000005 ver 0x8000000c)
    32

    ;; early IETF protocols had 64 byte nonces
    (<= 0x80000001 ver 0x80000004)
    64

    :else
    (throw (ex-info "Unknown VER tag" {:version (u/long->hex ver)}))))

(defn validate-nonce
  "Validates nonce length based on version.  Throws on error; returns
  :ok on success"
  [^long ver ^bytes nonce]

  ;; nonce must be present in all versions
  (when (nil? nonce)
    (throw (ex-info "Missing NONC" {})))

  ;; required length varies with version number
  (let [len (alength ^bytes nonce)
        req (required-nonce-length ver)]
    (when-not (= len req)
      (throw (ex-info "NONC has incorrect length"
                      {:nonce-length len
                       :version (u/long->hex ver)
                       :required-length req}))))
  :ok)

(defn validate-type
  "Validates nonce length based on version.  Throws on error; returns
  :ok on success"
  [^long ver ^bytes tp]
  (let [type_ (when tp (e/uint32-le->long tp))]
    (cond
      ;; version 1 not released yet.  placeholder for logic
      (= 1 ver)
      (throw (ex-info "Unknown VER tag" {:ver ver}))

      ;; 0x8000000c introduced required TYPE for requests
      (= ver 0x8000000c)
      (when-not (= type_ 0)
        (throw (ex-info "TYPE must be 0 in a request"
                        {:TYPE type_})))

      ;; earlier versions do not require a TYPE
      :else
      :ok))
  :ok)

(defn- validate-vers-helper
  "Validates request VER contents must be non-repeating, sorted asc, and
  limited to 32 values.  Throws on error; returns :ok on success."
  [client-vers]

  ;; number of versions
  (when (or (empty? client-vers) (> (count client-vers) 32))
    (throw (ex-info "VER must contain 1..32 uint32 entries"
                    {:vers client-vers
                     :count (count client-vers)})))

  ;; strictly ascending
  (when-not (apply < client-vers)
    (throw (ex-info "VER must be strictly ascending (no duplicates)"
                    {:VER client-vers})))

  :ok)

(defn validate-and-return-vers
  "Validates VER contents, accounting for different drafts of the
  protocol.  Throws on error, or returns a map with
  keys :client-vers :chosen-ver on success."
  [^bytes vrs]
  (let [client-vers (when vrs (e/bytes->u32-list vrs))
        chosen-ver  (choose-version client-vers)]
    (cond
      ;; google protocol & IETF v0 have no VER
      (nil? vrs)
      {:client-vers [0]
       :chosen-ver chosen-ver}

      ;; version 1 not released yet.  placeholder for logic
      (= 1 chosen-ver)
      (throw (ex-info "Unknown VER tag" {:VER client-vers
                                         :chosen-ver chosen-ver}))

      ;; 0x8000000c requires VER sorted ASC and <= 32 values
      (= chosen-ver 0x8000000c)
      (when (validate-vers-helper client-vers)
        {:client-vers client-vers
         :chosen-ver chosen-ver})

      ;; earlier versions don't place any constraints on VER
      :else
      {:client-vers client-vers
       :chosen-ver chosen-ver})))

(defn merkle-leaf-data
  [version nonce request-bytes]
  (cond
    (= 0x00 version)                    nonce
    (<= 0x80000001 version 0x8000000b)  nonce
    (<= 0x8000000c version)             request-bytes
    :else (throw (ex-info "unrecognized version" {:version version}))))

(defn merkle-opts
  [version]
  (cond
    (= 0x00 version) {:hash-size 64 :tree-order :natural}
    :else            {:hash-size 32 :tree-order :natural}))
