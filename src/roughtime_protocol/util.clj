(ns roughtime-protocol.util
  (:require
   [clojure.string :as string]
   [taoensso.encore :as enc])
  (:import
   (java.util Arrays Base64 HexFormat)
   (java.time Instant)
   (java.security MessageDigest SecureRandom)
   (java.nio ByteBuffer ByteOrder)))

(set! *warn-on-reflection* true)

;;; Performance Primitives

(defn concat-bytes
  "Efficiently concatenate multiple byte arrays into one."
  ^bytes [coll]
  (let [total-size (reduce + (map count coll))
        result (byte-array total-size)]
    (loop [offset 0
           [^bytes ba & more] coll]
      (if ba
        (let [len (alength ba)]
          (System/arraycopy ba 0 result offset len)
          (recur (+ offset len) more))
        result))))

(defn slice
  "Returns a sub-section of a byte array."
  ^bytes [^bytes bs ^long start ^long end]
  (Arrays/copyOfRange bs start end))

(defn bytes= [a b]
  (Arrays/equals ^bytes a ^bytes b))

;;; Endian

;; Helper to create a LE buffer
(defn le-buffer ^ByteBuffer [^bytes ba]
  (.order (ByteBuffer/wrap ba) ByteOrder/LITTLE_ENDIAN))

;;; Unsigned/Byte Helpers

(defn u8 [b] (unchecked-byte (bit-and (int b) 0xff)))

(defn u8-ba ^bytes [& xs] (byte-array (map u8 xs)))

(defn u8-vec [^bytes ba] (mapv #(bit-and (int %) 0xff) ba))

;;; Hex & Base64

(def ^:private ^HexFormat hex-format (HexFormat/of))

(defn long->hex ^String [^long x]
  (format "0x%08x" x))

(defn bytes->hex-string ^String [^bytes bs]
  (.formatHex hex-format bs))

(defn hex-string->bytes ^bytes [^String s]
  (.parseHex hex-format s))

(defn b64->bytes ^bytes [^String s]
  (.decode (Base64/getDecoder) s))

(defn bytes->b64 ^String [^bytes ba]
  (.encodeToString (Base64/getEncoder) ba))

;;; Crypto

(def ^:private ^SecureRandom secure-rng
  "SecureRandom objects are stateful and not thread-save; use enc/thread-local"
  (enc/thread-local (SecureRandom.)))

(defn gen-nonce
  "Generate a 32-byte cryptographic nonce."
  ^bytes [& {:keys [len] :or {len 32}}]
  (let [ba (byte-array len)]
    (.nextBytes ^SecureRandom @secure-rng ^bytes ba)
    ba))

(defn sha512-bytes
  "Computes SHA-512 over an optional prefix byte and one or more byte arrays,
   returning the first `n` bytes of the digest.

   Examples:
     (sha512-bytes 32 ba)
     (sha512-bytes 32 prefix ba)
     (sha512-bytes 32 prefix ba1 ba2 ba3)
     (sha512-bytes 64 ba1 ba2)"
  (^bytes
   [^long n ^bytes ba]
   (let [md (MessageDigest/getInstance "SHA-512")]
     (.update md ba)
     (slice (.digest md) 0 n)))

  (^bytes
   [^long n prefix-byte ^bytes ba]
   (let [md (MessageDigest/getInstance "SHA-512")]
     (.update md (byte prefix-byte))
     (.update md ba)
     (slice (.digest md) 0 n)))

  (^bytes
   [^Integer n prefix-byte ^bytes ba & more]
   (let [md (MessageDigest/getInstance "SHA-512")]
     (.update md (byte prefix-byte))
     (.update md ba)
     (doseq [^bytes x more]
       (.update md x))
     (slice (.digest md) 0 n))))


;;; Time

(defn now-seconds ^long []
  (.getEpochSecond (Instant/now)))

(defn now-micros ^long []
  (let [^Instant now (Instant/now)]
    (+ (* (.getEpochSecond now) 1000 1000)
       (quot (.getNano now) 1000))))

;;; Formatting

(defn hex-str->blocks
  "Formats hex string into 8-char blocks for readability."
  [h]
  (->> (partition-all 8 h)
       (map #(apply str %))
       (partition-all 4)
       (map #(string/join " " %))
       vec))
