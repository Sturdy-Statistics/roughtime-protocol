(ns roughtime-protocol.packet
  (:require
   [roughtime-protocol.util :as util :refer [slice le-buffer]]
   [roughtime-protocol.tag :as tag]
   [roughtime-protocol.tlv :as tlv]))

(set! *warn-on-reflection* true)

(def ^:private ROUGHTIM-MAGIC (tag/str->bytes8 "ROUGHTIM"))

(defn encode-packet
  "Wrap a TLV-encoded Roughtime message into a packet: [magic][msg_len][payload]."
  ^bytes [^bytes msg-bytes]
  (let [msg-len (alength msg-bytes)
        total-len (+ 12 msg-len)
        result (byte-array total-len)
        bb (le-buffer result)]
    (.put bb ^bytes ROUGHTIM-MAGIC)
    (.putInt bb (unchecked-int msg-len))
    (.put bb msg-bytes)
    result))

(defn- validate-packet!
  "Throws if the packet structure is invalid."
  [total-size msg-len magic-bytes min-size-bytes]
  (when-not (util/bytes= ROUGHTIM-MAGIC magic-bytes)
    (throw (ex-info "Invalid Roughtime magic string"
                    {:expected (util/bytes->hex-string ROUGHTIM-MAGIC)
                     :actual   (util/bytes->hex-string magic-bytes)})))

  (when (or (neg? msg-len) (pos? (mod msg-len 4)))
    (throw (ex-info "Invalid message length (must be positive multiple of 4)" {:msg-len msg-len})))

  (let [expected-size (+ 12 msg-len)]
    (when (not= total-size expected-size)
      (throw (ex-info "Packet size mismatch" {:expected expected-size :actual total-size}))))

  (when (and (some? min-size-bytes) (< total-size min-size-bytes))
    (throw (ex-info "Packet smaller than minimum size policy (anti-amplification)"
                    {:actual total-size :min min-size-bytes}))))

(defn decode-packet-
  "Decode a Roughtime packet and perform basic framing validations."
  [^bytes packet & [{:keys [min-size-bytes] :or {min-size-bytes 1024}}]]
  (let [total-size (alength packet)]
    (when (< total-size 12)
      (throw (ex-info "Truncated packet: missing header" {:len total-size})))

    (let [bb          (le-buffer packet)
          magic-bytes (byte-array 8)
          _           (.get bb magic-bytes)
          msg-len     (Integer/toUnsignedLong (.getInt bb))]

      (validate-packet! total-size msg-len magic-bytes min-size-bytes)

      (let [msg-bytes (util/slice packet 12 total-size)]
        {:packet-len    total-size
         :message-len   msg-len
         :message       (tlv/decode-rt-message msg-bytes)
         :message-bytes msg-bytes}))))

(defn- is-packet?
  [^bytes packet]
  (let [total-size (alength packet)]
    (when (< total-size 12)
      (throw (ex-info "Truncated packet: missing header" {:len total-size})))
    (let [bb (le-buffer (slice packet 0 8))
          magic-bytes (byte-array 8)
          _ (.get bb magic-bytes)]
      (util/bytes= ROUGHTIM-MAGIC magic-bytes))))

(defn decode-packet
  "dispatch to `decode-packet-` or to `tlv/decode-rt-message` for compatibility
  with Google version of the protocol."
  [^bytes msg-or-pkt & {:keys [min-size-bytes] :or {min-size-bytes 1024}}]
  (if (is-packet? msg-or-pkt)

    ;; is a packet (IETF draft 1+)
    (decode-packet- msg-or-pkt {:min-size-bytes min-size-bytes})

    ;; is a bare message (Google, IETF draft 0)
    (let [msg-len (alength ^bytes msg-or-pkt)]
      (when (and (some? min-size-bytes) (< msg-len min-size-bytes))
        (throw (ex-info "Packet smaller than minimum size policy (anti-amplification)"
                        {:actual msg-len :min min-size-bytes})))
      {:message-len msg-len
       :message (tlv/decode-rt-message msg-or-pkt)})))
