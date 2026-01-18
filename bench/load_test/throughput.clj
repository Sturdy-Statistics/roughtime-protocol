(ns load-test.throughput
  (:require
   [clojure.pprint :as pp]
   [clojure.core.async :as a]
   [criterium.core :as crit]

   [roughtime-protocol.sign :as sign]

   [roughtime-protocol.request :as rq]
   [roughtime-protocol.server :as server]))

(set! *warn-on-reflection* true)

(defn- respond-batch
  [request-batch ver cert-map]
  (letfn [(parse [^bytes request-bytes]
            (rq/parse-request request-bytes
                              {:min-size-bytes 1024}))]
   (let [parsed-batch  (mapv parse request-batch)]
     (server/batch-respond--single-version
      ver parsed-batch cert-map))))

(defn- runme-helper
  [total-reqs
   batch-size]
  (assert (= 0 (mod total-reqs batch-size)))
  (let [lt!!     (sign/gen-ed25519-kp)
        lt-pub   (.getPublic lt!!)
        lt-prv!! (.getPrivate lt!!)

        public-key (-> lt-pub sign/public-key->raw-pub32)

        cert-map   (server/mint-new-certificate-map lt-prv!!)

        ver        0x8000000c]

    (letfn [(req [_]
              (rq/make-request
               {:ver [ver] :msg-size 1024 :public-key public-key}))

            (make-reqs [n-batches]
              (let [batch-ch (a/chan 4096)]
                (a/thread
                  (loop [n 0]
                    (if (< n n-batches)
                      (let [request-batch (mapv req (range batch-size))]
                        (a/>!! batch-ch request-batch)
                        (recur (inc n)))
                      (a/close! batch-ch))))
                batch-ch))

            (respond [request-batch] (respond-batch request-batch ver cert-map))]


      (-> (crit/quick-benchmark
           (let [n-batches (quot total-reqs batch-size)
                 ;; start a thread to fill the batch channel
                 batch-ch  (make-reqs n-batches)
                 out-ch    (a/chan n-batches)
                 parallelism 4]

             (a/pipeline-blocking parallelism out-ch (map respond) batch-ch)
             ;; Drain the output channel to ensure all work is completed
             (a/<!! (a/into [] out-ch)))
           {})
          (select-keys [:mean :variance :tail-quantile :lower-q :upper-q])
          (assoc :total-reqs total-reqs
                 :batch-size batch-size)))))

(defn- process-data [res]
 (let [tot (-> res :total-reqs double)]
   (letfn [(xf [k] (int (/ tot (-> (get res k) first))))]
     (merge
      (select-keys res [:total-reqs :batch-size :tail-quantile])
      {:mean (xf :mean)
       :lo (xf :lower-q)
       :hi (xf :upper-q)}))))

(defn- runme
  [total-reqs batch-size]
  (-> (runme-helper total-reqs batch-size) process-data))

(defn run
  "Entry point for load testing"
  [_]

  (let [total-reqs (* 128 128 8)
        f (fn [bs] (runme total-reqs bs))
        batch-sizes [1 4 16 64 128 256 1024 4096]
        data (map f batch-sizes)]
    (pp/print-table [:total-reqs :batch-size :tail-quantile :mean :lo :hi]
                    data)))
