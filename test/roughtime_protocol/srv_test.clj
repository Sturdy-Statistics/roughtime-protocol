(ns roughtime-protocol.srv-test
  (:require
   [clojure.test            :refer [deftest is testing]]
   [roughtime-protocol.util :as util]
   [roughtime-protocol.srv  :as srv]))

(set! *warn-on-reflection* true)

(defn- check-srv-value
  [b64-pub-key]
  (-> b64-pub-key
      util/b64->bytes
      srv/srv-value
      util/bytes->hex-string))

(def ^:private known-srv-values
  [{:name "cloudflare"
    :public-key-b64 "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
    :srv-hex "0d93616f19641cbf68f8b41a1b659797fc9330b658a5042d6be1021194ee290c"}
   {:name "int08h"
    :public-key-b64 "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="
    :srv-hex "95645ff5c385c24eba48d509528a4a74e0861c0b57f46c25ee5c6a488a23246f"}
   {:name "roughtime.se"
    :public-key-b64 "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="
    :srv-hex "8c4bbf598f43ff13da82bfeb9e0652a4e372ab03c2cae3b6f661ea29c8ebacc2"}])

(deftest srv-test-2
  (testing "check known SRV values"
    (doseq [{:keys [name public-key-b64 srv-hex]} known-srv-values]
      (is (= srv-hex (check-srv-value public-key-b64))
          (str "failed for " name)))))
