(ns roughtime-protocol.merkle-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [roughtime-protocol.merkle :as merkle]
   [roughtime-protocol.util :as util :refer [u8-ba bytes=]]))

(set! *warn-on-reflection* true)

(deftest leaf-and-node-hashing
  (testing "Leaf hash uses 0x00 prefix"
    (let [data (u8-ba 0x11 0x22)
          ;; Manual calculation: H(0x00 || 0x11 0x22)
          expected (util/sha512-bytes 32 (util/concat-bytes [(u8-ba 0x00) data]))
          actual (merkle/hash-leaf 32 data)]
      (is (bytes= expected actual))))

  (testing "Node hash uses 0x01 prefix"
    (let [left (byte-array 32 (unchecked-byte 0xaa))
          right (byte-array 32 (unchecked-byte 0xbb))
          ;; Manual calculation: H(0x01 || left || right)
          expected (util/sha512-bytes 32 (util/concat-bytes [(u8-ba 0x01) left right]))
          actual (merkle/hash-node 32 left right)]
      (is (bytes= expected actual)))))

(deftest compute-root-logic-natural-32
  (let [hash-size 32
        opts      {:tree-order :natural
                   :hash-size hash-size}]

    (letfn [(hl [x]   (merkle/hash-leaf hash-size x))
            (hn [l r] (merkle/hash-node hash-size l r))]

      (let [l1 (u8-ba 0x01)
            l2 (u8-ba 0x02)
            l3 (u8-ba 0x03)
            l4 (u8-ba 0x04)
            h1 (hl l1)
            h2 (hl l2)
            h3 (hl l3)
            h4 (hl l4)]

        (testing "Single leaf tree root is just the leaf hash"
          (is (bytes= h1 (merkle/compute-root [l1] opts))))

        (testing "Two leaf tree root: H(0x01 || h1 || h2)"
          (is (bytes= (hn h1 h2) (merkle/compute-root [l1 l2] opts))))

        (testing "Three leaf tree (Unbalanced): H(0x01 || H(0x01 || h1 || h2) || h3)"
          ;; In Roughtime, the 'lone' node (h3) is cloned
          (let [level1-left (hn h1 h2)
                level1-right (hn h3 h3)
                expected (hn level1-left level1-right)]
            (is (bytes= expected (merkle/compute-root [l1 l2 l3] opts)))))

        (testing "Four leaf tree: H(0x01 || H(0x01 || h1 || h2) || H(0x01 || h3 || h4))"
          (let [level1-left (hn h1 h2)
                level1-right (hn h3 h4)
                expected (hn level1-left level1-right)]
            (is (bytes= expected (merkle/compute-root [l1 l2 l3 l4] opts)))))))))

(deftest compute-root-logic-mirrored-64
  (let [hash-size 64
        opts      {:tree-order :mirrored
                   :hash-size  hash-size}]

    (letfn [(hl [x]   (merkle/hash-leaf hash-size x))
            (hn [l r] (merkle/hash-node hash-size l r))]

      (let [l1 (u8-ba 0xaa)
            l2 (u8-ba 0xab)
            l3 (u8-ba 0xac)
            l4 (u8-ba 0xad)
            h1 (hl l1)
            h2 (hl l2)
            h3 (hl l3)
            h4 (hl l4)]

        (testing "Single leaf tree root is just the leaf hash"
          (is (bytes= h1 (merkle/compute-root [l1] opts))))

        (testing "Two leaf tree root: H(0x01 || h2 || h1)"
          (is (bytes= (hn h2 h1) (merkle/compute-root [l1 l2] opts))))

        (testing "Three leaf tree (Unbalanced): H(0x01 || h3 || H(0x01 || h2 || h1))"
          ;; In Roughtime, the 'lone' node (h3) is cloned
          (let [level1-left (hn h2 h1)
                level1-right (hn h3 h3 )
                expected (hn level1-right level1-left)]
            (is (bytes= expected (merkle/compute-root [l1 l2 l3] opts)))))

        (testing "Four leaf tree: H(0x01 || H(0x01 || h4 || h3) || H(0x01 || h2 || h1))"
          (let [level1-left (hn h2 h1)
                level1-right (hn h4 h3)
                expected (hn level1-right level1-left)]
            (is (bytes= expected (merkle/compute-root [l1 l2 l3 l4] opts)))))))))

(deftest verify-proof-manual-path
  (testing "Climbing a manual 2-level path"
    (let [hash-size 32
          opts      {:tree-order :natural
                     :hash-size  hash-size}]

      (letfn [(hl [x]   (merkle/hash-leaf hash-size x))
              (hn [l r] (merkle/hash-node hash-size l r))]

        (let [leaf   (u8-ba 0xde 0xad)
              h-leaf (hl leaf)

              sibling1 (byte-array hash-size (byte 0x01))
              sibling2 (byte-array hash-size (byte 0x02))

              ;; Path: [sibling1, sibling2]
              path (util/concat-bytes [sibling1 sibling2])]

          (testing "Index 0"
            ;; Level 0: bit0=0 → H(0x01 || h-leaf || sibling1) = parent
            ;; Level 1: bit0=0 → H(0x01 || parent || sibling2) = root
            (let [p (hn h-leaf sibling1)
                  expected (hn p sibling2)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 0
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 1"
            ;; Level 0: bit0=1 → H(0x01 || sibling1 || h-leaf) = parent
            ;; Level 1: bit1=0 → H(0x01 || parent   || sibling2) = root
            (let [p        (hn sibling1 h-leaf)
                  expected (hn p sibling2)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 1
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 2"
            ;; Level 0: bit0=0 → H(0x01 || h-leaf   || sibling1) = parent
            ;; Level 1: bit1=1 → H(0x01 || sibling2 || parent)   = root
            (let [p        (hn h-leaf sibling1)
                  expected (hn sibling2 p)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 2
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 3"
            ;; Level 0: bit0=1 → H(0x01 || sibling1 || h-leaf) = parent
            ;; Level 1: bit1=1 → H(0x01 || sibling2 || parent) = root
            (let [p (hn sibling1 h-leaf)
                  expected (hn sibling2 p)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 3
                                     :path-bytes path}
                                    opts))))))))))

(deftest verify-proof-manual-path-mirrored-64
  (testing "Climbing a manual 2-level path"
    (let [hash-size 64
          opts      {:tree-order :mirrored
                     :hash-size  hash-size}]

      (letfn [(hl [x]   (merkle/hash-leaf hash-size x))
              (hn [l r] (merkle/hash-node hash-size l r))]

        (let [leaf   (u8-ba 0xde 0xad)
              h-leaf (hl leaf)

              sibling1 (byte-array hash-size (byte 0x01))
              sibling2 (byte-array hash-size (byte 0x02))

              ;; Path: [sibling1, sibling2]
              path (util/concat-bytes [sibling1 sibling2])]

          (testing "Index 0"
            ;; Level 0: bit0=0 → H(0x01 || sibling1 || h-leaf) = parent
            ;; Level 1: bit0=0 → H(0x01 || sibling2 || parent) = root
            (let [p (hn sibling1 h-leaf)
                  expected (hn sibling2 p)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 0
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 1"
            ;; Level 0: bit0=1 → H(0x01 || h-leaf   || sibling1) = parent
            ;; Level 1: bit1=0 → H(0x01 || sibling2 || parent)   = root
            (let [p        (hn h-leaf sibling1)
                  expected (hn sibling2 p)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 1
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 2"
            ;; Level 0: bit0=0 → H(0x01 || sibling1 || h-leaf) = parent
            ;; Level 1: bit1=1 → H(0x01 || parent || sibling2) = root
            (let [p        (hn sibling1 h-leaf)
                  expected (hn p sibling2)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 2
                                     :path-bytes path}
                                    opts)))))

          (testing "Index 3"
            ;; Level 0: bit0=1 → H(0x01 || h-leaf || sibling1) = parent
            ;; Level 1: bit1=1 → H(0x01 || parent || sibling2) = root
            (let [p (hn h-leaf sibling1)
                  expected (hn p sibling2)]
              (is (bytes= expected (merkle/reconstruct-root
                                    {:leaf-data leaf
                                     :index 3
                                     :path-bytes path}
                                    opts))))))))))

(deftest verify-proof-roundtrip
  (testing "Roundtrip with full trees"
   (let [hash-size 32
         opts      {:hash-size  hash-size
                    :tree-order :natural}]
     (doseq [num-leaves [1 2 4 8 16 32 64]]

       (let [leaves (mapv #(u8-ba %) (range num-leaves))
             root   (merkle/compute-root leaves opts)]

         (doseq [idx (range num-leaves)]
           (let [path (merkle/build-path leaves idx opts)]
             (is (bytes= root
                         (merkle/reconstruct-root
                          {:leaf-data (nth leaves idx)
                           :index idx
                           :path-bytes path}
                          opts))
                 (str "roundtrip failed num-leaves=" num-leaves " idx=" idx)))))))))


(deftest verify-proof-roundtrip-non-full-trees
  (testing "Roundtrip with non-full trees"
    (let [hash-size 32
          opts      {:hash-size  hash-size
                     :tree-order :natural}]
      (doseq [num-leaves (range 11 31)]

        (let [leaves (mapv #(u8-ba %) (range num-leaves))
              root   (merkle/compute-root leaves opts)]

          (doseq [idx (range num-leaves)]
            (let [path (merkle/build-path leaves idx opts)]
              (is (:ok
                   (merkle/valid-proof?
                    {:leaf-data (nth leaves idx)
                     :index idx
                     :path-bytes path
                     :root root}
                    opts))
                  (str "roundtrip failed num-leaves=" num-leaves " idx=" idx)))))))))
