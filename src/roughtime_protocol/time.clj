(ns roughtime-protocol.time
  (:require
   [clojure.string :as string])
  (:import
   (java.lang Math)))

(set! *warn-on-reflection* true)

;; Nominal civil durations:
(def SECS-PER-SEC     1)
(def SECS-PER-MIN    60)
(def SECS-PER-HOUR   (* 60 SECS-PER-MIN))
(def SECS-PER-DAY    (* 24 SECS-PER-HOUR))

;; Use Gregorian mean year (365.2425 d) so month = year/12.
(def SECS-PER-YEAR  (long (Math/round (* 365.2425 SECS-PER-DAY))))
(def SECS-PER-MONTH (quot SECS-PER-YEAR 12))
(def SECS-PER-CENTURY (* 100 SECS-PER-YEAR))
(def SECS-PER-MILLENNIUM (* 1000 SECS-PER-YEAR))

(def ^:private units
  ;; largest → smallest
  ;;  - millennia: "ka" (kilo-annum)
  ;;  - centuries: "c"
  ;;  - years:     "y"
  ;;  - months:    "mo"
  ;;  - days:      "d"
  ;;  - hours:     "h"
  ;;  - minutes:   "m"
  ;;  - seconds:   "s"
  [[SECS-PER-MILLENNIUM "ka"]
   [SECS-PER-CENTURY    "c"]
   [SECS-PER-YEAR       "y"]
   [SECS-PER-MONTH      "mo"]
   [SECS-PER-DAY        "d"]
   [SECS-PER-HOUR       "h"]
   [SECS-PER-MIN        "m"]
   [SECS-PER-SEC        "s"]])

(defn format-duration
  "Compact human duration. Examples:
   \"2d 3h\", \"3h 5m\", \"5m\", \"45s\", \"3y 2mo\", \"1c 4y\", \"12ka 3c\".
   Uses nominal Gregorian averages (365.2425d/yr; month = year/12)."
  ^String [secs0]
  (if (> secs0 Long/MAX_VALUE)
    "∞"
    (let [neg? (neg? secs0)
          ;; avoid Math/abs overflow for Long/MIN_VALUE
          secs (if neg? (unchecked-negate secs0) secs0)]
      (if (zero? secs)
        "0s"
        (let [parts
              (loop [s secs
                     [[unit lbl] & more] units
                     acc []]
                (if unit
                  (let [q (quot s unit)]
                    (if (pos? q)
                      ;; take at most two parts for compactness
                      (let [acc' (conj acc (str q lbl))
                            s'   (mod s unit)]
                        (if (>= (count acc') 2)
                          acc'
                          (recur s' more acc')))
                      (recur s more acc)))
                  acc))]
          (str (when neg? "-") (string/join " " (if (seq parts) parts ["0s"]))))))))
