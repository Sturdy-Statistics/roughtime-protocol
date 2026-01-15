(ns roughtime-protocol.request
  (:require
   [roughtime-protocol.util :as util]
   [roughtime-protocol.endian :as e]
   [roughtime-protocol.tlv :as tlv]
   [roughtime-protocol.srv :as srv]
   [roughtime-protocol.compat :as compat]
   [roughtime-protocol.packet :as packet]
   [roughtime-protocol.config :refer [fiducial-version]]))

(set! *warn-on-reflection* true)

(def REQUEST-TYPE
  "TYPE value for requests."
  (e/long->uint32-le 0))

(defn parse-request
  "Parse and validate a Roughtime request, handling Google and IETF draft variants."
  [^bytes request-bytes ;; packet or message (Google & IETF v0)
   & [{:keys [min-size-bytes]
       :or {min-size-bytes 1024}}]]
  (let [{:keys [message-len message]}
        (packet/decode-packet request-bytes {:min-size-bytes min-size-bytes})

        vrs-bytes (get message "VER")
        nc        (get message "NONC")
        tp        (get message "TYPE")

        {:keys [client-vers chosen-ver]}
        (compat/validate-and-return-vers vrs-bytes)]

    ;; validate message length
    (when (and min-size-bytes (< message-len min-size-bytes))
      (throw (ex-info "Request is smaller than the minimum size policy"
                      {:size message-len :min-size min-size-bytes})))

    ;; run version-specific validations
    (compat/validate-nonce chosen-ver nc)
    (compat/validate-type chosen-ver tp)

    {:nonce nc
     :request-bytes request-bytes
     :version chosen-ver
     :client-vers client-vers
     :message message
     :message-len message-len}))

(defn make-request-msg
  "Constructs a valid TLV request.
   Uses protocol-appropriate nonce lengths and padding tags."
  [{:keys [ver nonce public-key msg-size]
    :or {ver      [fiducial-version]
         msg-size 1024}}]
  (let [chosen-ver (compat/choose-version ver)

        nonce-len  (compat/required-nonce-length chosen-ver)
        nonce      (or nonce
                       (util/gen-nonce {:len nonce-len}))

        _          (when-not (= nonce-len (alength ^bytes nonce))
                     (throw (ex-info "Invalid NONC length for protocol version"
                                     {:version ver
                                      :chosen-ver chosen-ver
                                      :nonce-len (alength ^bytes nonce)
                                      :required-len nonce-len})))

        pad-tag    (compat/pad-tag chosen-ver)

        ;; base message structure
        base-msg (cond-> {"NONC" nonce}

                   ;; VER tag required with 0x80000001
                   (<= 0x80000001 chosen-ver)
                   (assoc "VER" (e/u32-list->bytes ver))

                   ;; TYPE tag required with 0x8000000c
                   (<= 0x8000000c chosen-ver)
                   (assoc "TYPE" REQUEST-TYPE)

                   ;; 0x8000000a added optional SRV tag
                   (and public-key
                        (<= 0x8000000a chosen-ver))
                   (assoc "SRV" (srv/srv-value public-key)))

        ;; make a dummy message to compute padding required
        temp-msg  (tlv/encode-rt-message (assoc base-msg pad-tag (byte-array 0)))

        pad-len   (max 0 (- msg-size (alength ^bytes temp-msg)))]

    (tlv/encode-rt-message (assoc base-msg pad-tag (byte-array pad-len)))))

(defn make-request
  "Build a RoughTime request which may be sent to a server.

   Depending on the version, this is either a full Roughtime **packet**
   (with ROUGHTIM header), or a bare RoughTime **message**.

   Accepts the options

     * ver: nil or Seq[Integer]
         Version numbers of the protocol.  nil for Google protocol.
         Defaults to `config/fiducial-version`.

     * nonce: byte[]
         nonce for the request; 32 bytes for IETF; 64 bytes for Google
         Defaults to `util/gen-nonce` of the required size.

     * msg-size: integer
         Size (in bytes) to pad the request MESSAGE.  Note that the PACKET is
         12 bytes longer than the message.  The spec is somewhat ambiguous about
         whether the limit applies to the MESSAGE or to the PACKET; different
         implementations appear to make different choices.
         Defaults to 1024.

     * public-key: byte[]
         Long-term public key for the server.  If specified, and if the protocol
         version allows, we add a SRV tag to the request corresponding to this
         key.

   Returns request packet as a byte[]."
  ^bytes [opts]
  (let [msg (make-request-msg opts)
        ver (some-> opts :ver first)]
    (if (and ver (or (= 0 ver) (= 0x80000000 ver)))
      ;; google returns a bare message
      msg
      ;; else, return a packet
      (packet/encode-packet msg))))
