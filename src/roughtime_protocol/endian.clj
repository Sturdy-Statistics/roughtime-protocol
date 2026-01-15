(ns roughtime-protocol.endian
  (:require
   [roughtime-protocol.util :refer [le-buffer]])
  (:import
   (java.util List)))

(set! *warn-on-reflection* true)

(defn long->uint32-le
  "Encode an unsigned 32-bit x into 4 little-endian bytes."
  ^bytes [^long x]
  (let [ba (byte-array 4)]
    (.putInt (le-buffer ba) (unchecked-int x))
    ba))

(defn long->uint64-le
  "Encode an unsigned 64-bit x into 8 little-endian bytes."
  ^bytes [^long x]
  (let [ba (byte-array 8)]
    (.putLong (le-buffer ba) x)
    ba))

(defn uint32-le->long
  "Decode 4 LE bytes to a Java long [0, 2^32-1]."
  ^long [^bytes ba]
  (when (not= 4 (alength ba))
    (throw (ex-info "uint32-le->long requires exactly 4 bytes" {:actual (alength ba)})))
  (Integer/toUnsignedLong (.getInt (le-buffer ba))))

(defn uint64-le->bigint
  "Decode 8 LE bytes to an unsigned 64-bit BigInteger [0, 2^64-1]."
  ^BigInteger [^bytes ba]
  (when (not= 8 (alength ba))
    (throw (ex-info "uint64-le->bigint requires exactly 8 bytes" {:actual (alength ba)})))
  ;; BigInteger(signum, magnitude) where magnitude is BIG-ENDIAN.
  ;; reverse the LE array to get BE. 1 = positive.
  (BigInteger. 1 (byte-array (reverse ba))))

(defn bytes->u32-list
  "Interpret a byte[] as a list of little-endian uint32 words."
  ^List [^bytes ba]
  (let [n (alength ba)]
    (when (pos? (mod n 4))
      (throw (ex-info "list must be a multiple of 4 bytes" {:len n})))
    (let [bb (le-buffer ba)
          word-count (/ n 4)]
      (vec (repeatedly word-count #(Integer/toUnsignedLong (.getInt bb)))))))

(defn u32-list->bytes
  "Concatenate a list of uint32s into a single little-endian byte[]."
  ^bytes [^List nums]
  (let [ba (byte-array (* 4 (count nums)))
        bb (le-buffer ba)]
    (doseq [n nums]
      (.putInt bb (unchecked-int n)))
    ba))
