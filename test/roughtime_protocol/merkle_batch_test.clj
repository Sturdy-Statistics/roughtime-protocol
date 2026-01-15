(ns roughtime-protocol.merkle-batch-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [roughtime-protocol.merkle :as m]
   [roughtime-protocol.util :refer [bytes=]]))

(set! *warn-on-reflection* true)

(defn- generate-dummy-leaves
  "Generates n leaves, each being a byte-array of size hash-size."
  [n hash-size]
  (mapv (fn [i]
          (let [ba (byte-array hash-size)]
            ;; Fill the first byte with the index so the leaves are unique
            (aset ba 0 (byte i))
            ba))
        (range n)))

(deftest build-all-compatibility-test
  (let [opts {:hash-size 32 :tree-order :natural}]
    (testing "Compatibility with legacy implementation across different batch sizes"
      (doseq [n (range 1 33)] ;; Test tree sizes from 1 to 32
        (let [leaves (generate-dummy-leaves n (:hash-size opts))
              ;; 1. Get "trusted" values from old functions
              expected-root (m/compute-root leaves opts)
              expected-paths (mapv #(m/build-path leaves % opts) (range n))

              ;; 2. Get values from new optimized function
              {:keys [root paths]} (m/build-all leaves opts)]

          (is (bytes= expected-root root)
              (str "Root mismatch at size " n))

          (is (= (count expected-paths) (count paths))
              (str "Path count mismatch at size " n))

          (doseq [i (range n)]
            (is (bytes= (nth expected-paths i) (nth paths i))
                (str "Path mismatch for leaf " i " at tree size " n))))))))

(deftest edge-case-test
  (let [opts {:hash-size 64 :tree-order :mirrored}]
    (testing "Handles mirrored tree order and 64-byte hashes"
      (let [leaves (generate-dummy-leaves 5 32)
            {:keys [root paths]} (m/build-all leaves opts)]
        (is (bytes= (m/compute-root leaves opts) root))
        (is (bytes= (m/build-path leaves 0 opts) (first paths)))))))
