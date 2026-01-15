(ns roughtime-protocol.tlv
  (:require
   ;;[clojure.string            :as string]
   [roughtime-protocol.util   :as util :refer [slice le-buffer]]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.tag    :as tag])
  (:import
   (java.util Map)))

(set! *warn-on-reflection* true)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; encode

(defn- sort-tags
  "Sorts a map of {tag value} by the numeric LE value of the tags."
  [msg-map]
  (sort-by #(e/uint32-le->long (tag/tag->bytes (key %))) msg-map))

(defn encode-rt-message
  "encode a roughtime message

  Args:
    - msg-map: map {\"tag\" bytes}

  Format:

    uint32 num_tags
    uint32 offsets[max(0, num_tags-1)]
    uint32 tags[num_tags]
    byte-string-values

    tags sorted by numeric value, and offsets appear in the same order
    as tags.  tags must contain only A-Z or the padding byte 0x00

  (see §4 of the spec.)"
  ^bytes [^Map msg-map]
  (let [sorted-entries (sort-tags msg-map)
        n              (count sorted-entries)
        tag-bytes      (mapv #(tag/tag->bytes (key %)) sorted-entries)
        val-bytes      (mapv #(tag/pad4 (val %)) sorted-entries)

        ;; Calculate lengths and offsets
        ;; NB this one change for `val-lens` lowered response time from 31us to 4us!
        ;; val-lens       (mapv alength val-bytes)
        val-lens       (mapv (fn [^bytes v] (alength v)) val-bytes)
        payload-len    (reduce + val-lens)
        ;; Offsets for tags 1..N-1
        offsets        (if (<= n 1) [] (subvec (vec (reductions + 0 val-lens)) 1 n))

        ;; Header math: num_tags(4) + offsets(4*(n-1)) + tags(4*n)
        header-len     (if (zero? n) 4 (* 8 n))
        total-len      (+ header-len payload-len)

        result         (byte-array total-len)
        bb             (le-buffer result)]

    ;; 1. Write num_tags
    (.putInt bb n)
    ;; 2. Write offsets
    (doseq [o offsets] (.putInt bb (unchecked-int o)))
    ;; 3. Write tags
    (doseq [^bytes t tag-bytes] (.put bb t))
    ;; 4. Write data
    (doseq [^bytes v val-bytes] (.put bb v))

    result))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; decode

(defn decode-rt-message
  "Decode a raw byte array into a map of {tag bytes}."
  [^bytes ba]
  (let [len (alength ba)]
    (when (< len 4) (throw (ex-info "Truncated message" {})))
    (let [bb       (le-buffer ba)
          num-tags (.getInt bb)]
      (when (neg? num-tags) (throw (ex-info "Negative tags count" {})))
      (when (> num-tags 1024) (throw (ex-info "Too many tags" {:count num-tags})))

      (let [header-len    (if (zero? num-tags) 4 (* num-tags 8))]
        (when (< len header-len)
          (throw (ex-info "Truncated header"
                          {:header-len header-len :msg-len len}))))

      (let [off-count (max 0 (dec num-tags))
            offsets   (doall (repeatedly off-count #(.getInt bb)))
            tags      (doall (repeatedly num-tags #(let [t (byte-array 4)] (.get bb t) (tag/bytes->tag t))))
            payload-base (.position bb)
            payload-len  (- len payload-base)
            ;; Implicit first offset 0, then provided offsets, ending with payload-len
            boundaries (vec (concat [0] offsets [payload-len]))]

        ;; Validation
        (when-not (apply <= boundaries) (throw (ex-info "Non-monotonic offsets" {:offsets offsets})))
        (when-not (every? #(zero? (mod % 4)) boundaries) (throw (ex-info "Misaligned offsets" {})))
        (when-not (every? pos? offsets) (throw (ex-info "Offset may not be zero" {:offsets offsets})))
        (when (and (seq tags) (not (apply < (map #(e/uint32-le->long (tag/tag->bytes %)) tags))))
          (throw (ex-info "Tags must be strictly increasing" {:tags tags
                                                              :tags-as-ints (map #(e/uint32-le->long (tag/tag->bytes %)) tags)})))

        (into {}
              (for [i (range num-tags)]
                [(nth tags i)
                 (slice ba (+ payload-base (nth boundaries i))
                        (+ payload-base (nth boundaries (inc i))))]))))))

(def ^:private google-pad-tag
  (byte-array [(byte \P) (byte \A) (byte \D) (unchecked-byte 0xff)]))

(defn- fix-key
  "Google PAD key is a byte-array.  Make a string for it"
  [k]
  (cond
    (string? k) k

    (and (bytes? k)
         (util/bytes= k google-pad-tag))
    "PADxff"

    :else (str k)))

(def ^:private decoders
  "functions for decoding raw byte-array values into Clojure objects"
  {"SIG"    identity
   "NONC"   identity
   "PATH"   identity
   "PUBK"   identity
   "ROOT"   identity
   "SRV"    identity
   "PAD"    identity
   "PADxff" identity
   "ZZZZ"   identity
   "SREP"   decode-rt-message
   "CERT"   decode-rt-message
   "DELE"   decode-rt-message
   "VER"    e/uint32-le->long
   "RADI"   e/uint32-le->long
   "TYPE"   e/uint32-le->long
   "INDX"   e/uint32-le->long
   "MIDP"   e/uint64-le->bigint
   "MINT"   e/uint64-le->bigint
   "MAXT"   e/uint64-le->bigint
   "VERS"   e/bytes->u32-list})

(def ^:private recursive-tags
  "tags which contain nested TLV messages"
  #{"SREP" "CERT" "DELE"})

(defn decode-rt-message-recursive
  "takes a partially-decoded message from `decode-rt-message` and fully
  decodes it.  translates values into clojure objects, including
  nested TLV messages."
  [msg]
  (into {}
        (map
         (fn [[k v]] (let [k' (fix-key k)
                           f (get decoders k')
                           v' (f v) ;;(try (f v) (catch Exception _ nil))
                           ]
                       (if (recursive-tags k)
                         [k (decode-rt-message-recursive v')]
                         [k v'])))
         msg)))

(defn- uint->int-or-hex
  [x]
  (if (< x 32)
    (format "%d" x)
    (format "0x%08x" x)))

(defn- pretty-hex
  [^bytes ba]
  (-> ba
      util/bytes->hex-string
      util/hex-str->blocks))

(defn- pretty-pad
  [^bytes ba]
  (if (and (some? ba) (bytes? ba))
    (format "0{%d}" (alength ^bytes ba))
    "<padding>"))

(def ^:private formatters
  "functions to pretty-print decoded values.  these operate on clojure
  objects, not raw byte arrays."
  {"SIG"    pretty-hex
   "NONC"   pretty-hex
   "PATH"   pretty-hex
   "PUBK"   pretty-hex
   "ROOT"   pretty-hex
   "SRV"    pretty-hex
   "PAD"    pretty-pad
   "PADxff" pretty-pad
   "ZZZZ"   pretty-pad
   "SREP"   identity
   "CERT"   identity
   "DELE"   identity
   "VER"    uint->int-or-hex
   "RADI"   identity
   "TYPE"   identity
   "INDX"   identity
   "MIDP"   identity ;; todo: time formatter
   "MINT"   identity ;; todo: time formatter
   "MAXT"   identity ;; todo: time formatter
   "VERS"   #(map uint->int-or-hex %)})

(defn print-rt-message-recursive
  "print a decoded message in human-readable form.  this operates on a
  fully decoded message from `decode-rt-message-recursive`."
  [decoded-msg]
  (into {}
        (map
         (fn [[k v]] (let [k' (fix-key k)
                           f (get formatters k')
                           v' (f v) ;;(try (f v) (catch Exception _ nil))
                           ]
                       (if (recursive-tags k')
                         [k' (print-rt-message-recursive v')]
                         [k' v'])))
         decoded-msg)))

;; Local Variables:
;; fill-column: 100000
;; End:
