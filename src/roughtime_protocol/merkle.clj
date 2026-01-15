(ns roughtime-protocol.merkle
  (:require
   [roughtime-protocol.util :as util :refer [sha512-bytes slice bytes=]]
   [taoensso.truss :refer [have]]))

(set! *warn-on-reflection* true)

;;; Constants
(def ^:private LEAF-PREFIX (byte 0x00))
(def ^:private NODE-PREFIX (byte 0x01))

;;; Primitives

(defn hash-leaf
  "H(0x00 || data)"
  ^bytes [^long hash-size ^bytes data]
  (sha512-bytes hash-size LEAF-PREFIX data))

(defn hash-node
  "H(0x01 || left || right)"
  ^bytes [^long hash-size ^bytes left ^bytes right]
  (sha512-bytes hash-size NODE-PREFIX left right))

;;; Generation

(defn- next-level
  "Computes the next level of the tree."
  [nodes {:keys [hash-size tree-order]}]
  (let [pairs (partition 2 2 [nil] nodes)
        h     (fn [a b] (hash-node hash-size a b))]
    (mapv (fn [[l r]]
            (if-not r
              ;; no sibling → hash with self
              (h l l)
              ;; hash with sibling; tree shape determines order
              (case tree-order
                :natural  (h l r)
                :mirrored (h r l))))
          pairs)))

(defn- chop-path
  "slice a PATH byte[] into nodes of size `hash-size`"
  [^bytes path-bytes ^long hash-size]
  (let [_          (have bytes? path-bytes)
        n          (alength ^bytes path-bytes)
        path-count (quot n hash-size)]

    (when-not (= n (* hash-size path-count))
      (throw (ex-info "path-bytes must be an integer multiple of hash-size"
                      {:hash-size hash-size
                       :path-bytes-len n})))

    (letfn [(idx  [i] (long (* hash-size i)))
            (node [i] (slice path-bytes (idx i) (idx (inc i))))]

      (let [nodes (mapv node (range path-count))]
        nodes))))

;;; Public API

(defn compute-root
  "Computes the root of a tree given a list of leaf data byte arrays."
  ^bytes [leaves {:keys [hash-size tree-order] :as opts}]

  (when (empty? leaves)
    (throw (ex-info "Cannot compute Merkle root of empty leaf set" {})))
  (when-not (contains? #{32 64} hash-size)
    (throw (ex-info "Invalid hash size" {:hash-size hash-size})))
  (when-not (contains? #{:natural :mirrored} tree-order)
    (throw (ex-info "Invalid tree order" {:tree-order tree-order})))

  (letfn [(hl [leaf] (hash-leaf hash-size (have bytes? leaf)))]
    (loop [hashes (mapv hl leaves)]
      (if (= 1 (count hashes))
        (first hashes)
        (recur (next-level hashes opts))))))

(defn reconstruct-root
  "Computes the root of a tree given a leaf, index, and path"
  ^bytes [{:keys [^bytes leaf-data
                  ^bytes path-bytes
                  ^long index]}
          {:keys [hash-size tree-order]}]

  (when-not (contains? #{32 64} hash-size)
    (throw (ex-info "Invalid hash size" {:hash-size hash-size})))
  (when-not (contains? #{:natural :mirrored} tree-order)
    (throw (ex-info "Invalid tree order" {:tree-order tree-order})))
  (when-not (and (integer? index) (<= 0 index))
    (throw (ex-info "Invalid index" {:index index})))

  (let [nodes        (chop-path path-bytes (long hash-size))
        path-count   (count nodes)
        initial-hash (hash-leaf hash-size (have bytes? leaf-data))

        pairs (case tree-order
                :natural  (fn [even-bit? self sibling]
                            (if even-bit? [self sibling] [sibling self]))
                :mirrored (fn [even-bit? self sibling]
                            (if even-bit? [sibling self] [self sibling])))]

    (loop [i 0
           current initial-hash]

      (if (< i path-count)
        ;; consume next sibling and move up the tree
        (let [sibling    (nth nodes i)
              even-bit?  (not (bit-test index i)) ; true for even index bit

              [left right] (pairs even-bit? current sibling)
              next-hash    (hash-node hash-size left right)]
          (recur (inc i) next-hash))

        ;; at the root; finished
        (do
          (when-not (zero? (bit-shift-right index path-count))
            (throw (ex-info "INDEX has remaining nonzero bites after PATH exhausted"
                            {:index index :path-count path-count})))

          current)))))

(defn build-path
  "Builds the PATH bytes for leaf at `index`."
  ^bytes [leaves index {:keys [hash-size tree-order] :as opts}]

  (when-not (contains? #{32 64} hash-size)
    (throw (ex-info "Invalid hash size" {:hash-size hash-size})))
  (when-not (contains? #{:natural :mirrored} tree-order)
    (throw (ex-info "Invalid tree order" {:tree-order tree-order})))

  (letfn [(hl [leaf] (hash-leaf hash-size leaf))]

    (loop [level (mapv hl leaves)
           idx   (long index)
           acc   (transient [])]

      (if (= 1 (count level))

        ;; at the root; return
        (util/concat-bytes (persistent! acc))

        ;; climb to the next level
        (let [n (count level)
              has-sibling? (not (and (odd? n) (= idx (dec n))))
              sib-idx      (bit-xor idx 1)
              acc'         (if has-sibling?
                             (conj! acc (nth level sib-idx))
                             (conj! acc (nth level idx)))
              next-idx     (bit-shift-right idx 1)
              next-level   (next-level level opts)]

          (recur next-level next-idx acc'))))))

(defn valid-proof?
  "Checks the server proof (PATH + INDX + leaf data) against the server ROOT value.

  PATH, INDX, and ROOT come from the response; `leaf-data` must be supplied by
  the client.  Depending on the protocol version, it is either the NONC or the
  entire request packet, including header and padding bytes."
  [{:keys [root _path-bytes _index _leaf-data] :as args}
   {:keys [_hash-size _tree-order] :as opts}]

  (let [_ (have bytes? root)
        root' (reconstruct-root args opts)]
    (if (bytes= root' root)
      {:ok true}
      {:ok false :root-reconst root'})))


;;; more performant: build the tree once and compute results

(defn- build-tree-levels
  "Builds all levels of the tree from leaves up to the root.
   Returns a vector of levels, where each level is a vector of hashes."
  [leaves {:keys [hash-size] :as opts}]
  (let [leaf-hashes (mapv #(hash-leaf hash-size %) leaves)]
    (loop [levels [leaf-hashes]]
      (let [current-level (peek levels)]
        (if (= 1 (count current-level))
          levels
          (recur (conj levels (next-level current-level opts))))))))

(defn- extract-path
  "Extracts the sibling path for a specific leaf index from the pre-computed tree."
  [levels index]
  (let [leaf-to-root-levels (pop levels)] ;; root level has no sibling
    (loop [idx index
           lvls leaf-to-root-levels
           path (transient [])]
      (if (empty? lvls)
        (util/concat-bytes (persistent! path))
        (let [current-level (first lvls)
              n (count current-level)
              ;; sibling is idx XOR 1
              sib-idx (bit-xor idx 1)
              ;; if sib-idx is out of bounds, hash with self
              sibling (if (< sib-idx n)
                        (nth current-level sib-idx)
                        (nth current-level idx))]
          (recur (bit-shift-right idx 1)
                 (rest lvls)
                 (conj! path sibling)))))))

(defn build-all
  "Constructs the tree once and returns a map containing the root
   and a vector of paths for all leaves."
  [leaves {:keys [hash-size tree-order] :as opts}]
  (when (empty? leaves)
    (throw (ex-info "Cannot compute Merkle data for empty leaf set" {})))
  (when-not (contains? #{32 64} hash-size)
    (throw (ex-info "Invalid hash size" {:hash-size hash-size})))
  (when-not (contains? #{:natural :mirrored} tree-order)
    (throw (ex-info "Invalid tree order" {:tree-order tree-order})))

  (let [levels (build-tree-levels leaves opts)
        root (first (peek levels))
        num-leaves (count leaves)]
    {:root  root
     :paths (mapv #(extract-path levels %) (range num-leaves))}))
