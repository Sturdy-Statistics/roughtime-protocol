(ns roughtime-protocol.tag
  (:require
   [clojure.string :as string])
  (:import
   (java.util Arrays)
   (java.nio.charset StandardCharsets)))

(set! *warn-on-reflection* true)

(defn pad4
  "Pad `ba` with trailing zero bytes to a multiple of 4."
  ^bytes [^bytes ba]
  (let [len (alength ba)
        r (mod len 4)]
    (if (zero? r)
      ba
      (let [pad (- 4 r)]
       (Arrays/copyOf ba (long (+ len pad)))))))

(defn- fix-length ^bytes [^bytes ba ^long target-len]
  (if (= (alength ba) target-len)
    ba
    (Arrays/copyOf ba target-len)))

(defn str->bytes
  "Converts a string to ASCII bytes, ensuring it is exactly 4 bytes (padded with nulls)."
  ^bytes [^String s]
  (fix-length (.getBytes s StandardCharsets/US_ASCII) 4))

(defn bytes->str
  "Converts bytes to an ASCII string, stripping trailing nulls."
  ^String [^bytes ba]
  ;; We trim \null characters specifically to avoid issues with whitespace
  (let [s (String. ba StandardCharsets/US_ASCII)]
    (string/trimr (string/replace s "\0" " "))))

(defn- printable-ascii? [^bytes ba]
  (every? #(or (<= 32 % 126) (= 0 %)) ba))

;; Protocol Specifics

(defn tag->bytes ^bytes [tag]
  (cond
    (string? tag) (str->bytes tag)
    (bytes? tag)  (fix-length tag 4)
    :else (throw (ex-info "Tag must be string or bytes" {:tag tag}))))

(defn bytes->tag ^String [^bytes ba]
  (if (printable-ascii? ba)
    (bytes->str ba)
    ;; return the straight byte array for Google's PAD\xff
    ba))

;; For the "ROUGHTIM" magic string
(defn str->bytes8 ^bytes [^String s]
  (fix-length (.getBytes s StandardCharsets/US_ASCII) 8))
