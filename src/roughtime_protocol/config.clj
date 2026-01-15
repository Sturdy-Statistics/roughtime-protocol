(ns roughtime-protocol.config)

(set! *warn-on-reflection* true)

(def fiducial-version 0x8000000c)

(def min-msg-size
  "Minimum size for the RoughTime MESSAGE.  Set to 1012 (= 1024 for the
  packet including the ROUGHTIM header)"
  1012)

(def supported-versions [ ;; initial Google protocol
                         0x00

                         ;; IETF draft series
                         0x80000001 ;; ietf draft ver 1
                         0x80000002 ;; ietf draft ver 2
                         0x80000003 ;; ietf draft ver 3
                         0x80000004 ;; ietf draft ver 4
                         ;; 5 is expired
                         0x80000006 ;; ietf draft ver 6
                         ;; 7 is expired
                         0x80000008 ;; ietf draft ver 8
                         0x80000009 ;; ietf draft ver 9
                         0x8000000a ;; ietf draft ver 10
                         0x8000000b ;; ietf draft ver 11

                         0x8000000c ;; ietf draft vers 12-15

                         ;; v1 not released yet
                         ])

;; Validation per §5.2.5
(when (or (empty? supported-versions)
          (not (apply < supported-versions)))
  (throw (ex-info "VERS must be sorted ascending and non-empty"
                  {:VERS supported-versions})))

;;; define this once for efficiency
(def supported-versions-set
  (set supported-versions))

;;; Note that signature contexts are a function of version

;; VERS google, 0-6, 8-11 (v7 expired due to typo?)
;; RoughTime v1 delegation signature--
;; RoughTime v1 response signature

;; VERS 12-15
;; RoughTime v1 delegation signature
;; RoughTime v1 response signature

;; Per draft: delegation signatures use this exact ASCII context, including NUL.
(def ctx-dele
  (.getBytes "RoughTime v1 delegation signature\0" "US-ASCII"))

(def ctx-dele-google
  (.getBytes "RoughTime v1 delegation signature--\0" "US-ASCII"))

;; Per draft: srep signatures use this exact ASCII context, including NUL.
(def ctx-srep
  (.getBytes "RoughTime v1 response signature\0" "US-ASCII"))

(def ecosystem
  {
   "Cloudflare"
   { ;; https://github.com/cloudflare/roughtime/
    :name "Cloudflare-Roughtime-2"
    :version "IETF-Roughtime"
    :version-no 0x8000000b ;; 0x80000008 also valid
    :supported-versions nil
    :msg-size 1012
    :public-key-type "ed25519",
    :public-key "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
    :addresses [{:protocol "udp"
                 :address "roughtime.cloudflare.com:2003" } ] }

   "Cloudflare-goog"
   { ;; https://github.com/cloudflare/roughtime/
    :name "Cloudflare-Roughtime"
    :version "Google-Roughtime"
    :version-no 0x00
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519",
    :public-key "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
    :addresses [{:protocol "udp"
                 :address "roughtime.cloudflare.com:2003" } ] }

   "int08h"
   { ;; https://github.com/int08h/roughenough
    :name "int08h-Roughtime"
    :version "IETF-Roughtime"
    :version-no 0x8000000c
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="
    :addresses [{:protocol "udp"
                 :address "roughtime.int08h.com:2002"}]}

   "int08h-goog"
   { ;; https://github.com/int08h/roughenough
    :name "int08h-Roughtime"
    :version "IETF-Roughtime"
    :version-no 0x00
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE="
    :addresses [{:protocol "udp"
                 :address "roughtime.int08h.com:2002"}]}

   "roughtime.se"
   { ;; https://roughtime.se
    :name "roughtime.se"
    :version "IETF-Roughtime"
    :version-no 0x8000000c
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="
    :addresses [{:protocol "udp"
                 :address "roughtime.se:2002"}]}

   "TXRyan"
   {
    :name "time.txryan.com"
    :version "Google-Roughtime"
    :version-no 0x00
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA="
    :addresses [ {:protocol "udp"
                  :address "time.txryan.com:2002"}]}

   "SturdyStatistics"
   {
    :name "Sturdy-Statistics"
    :version "IETF-Roughtime"
    :version-no 0x8000000c
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "NqIjwLopQn6yQChtE21Mb97dAbAPe5UOuTa0tOakgD8="
    :addresses [{:protocol "udp"
                 :address "roughtime.sturdystatistics.com:2002"}]}

   "SturdyStatistics-goog"
   {
    :name "Sturdy-Statistics"
    :version "IETF-Roughtime"
    :version-no 0x00
    :supported-versions nil
    :msg-size 1024
    :public-key-type "ed25519"
    :public-key "NqIjwLopQn6yQChtE21Mb97dAbAPe5UOuTa0tOakgD8="
    :addresses [{:protocol "udp"
                 :address "roughtime.sturdystatistics.com:2002"}]}
   })
