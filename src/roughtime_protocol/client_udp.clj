(ns roughtime-protocol.client-udp
  (:require
   [clojure.string :as string])
  (:import
   (java.net DatagramSocket DatagramPacket
             InetSocketAddress
             InetAddress Inet4Address
             SocketTimeoutException)
   (java.util Arrays)))

(set! *warn-on-reflection* true)

(defn- resolve-host
  "Resolve host:port to a concrete InetSocketAddress (prefers IPv4 if available)."
  ^InetSocketAddress [^String host ^long port]
  (let [addrs (InetAddress/getAllByName host)
        ipv4  (some #(when (instance? Inet4Address %) %) addrs)
        pick  (or ipv4 (first addrs))]
    (InetSocketAddress. ^InetAddress pick port)))

(defn- resolve-server [server]
  (let [uri           (->> server
                           :addresses
                           (filter #(= (:protocol %) "udp"))
                           first
                           :address)
        [host port']  (string/split uri #":")
        port          (Long/parseLong port')]
    (resolve-host host port)))

(defn send-udp-once
  "Send req bytes to addr and attempt to receive one reply within timeout-ms.
   Returns {:bytes <byte[]> :from <InetSocketAddress>} or nil on timeout."
  [^InetSocketAddress addr ^bytes req ^long timeout-ms]

  (let [req-len (alength ^bytes req)
        ;; response should be NO LARGER than request.  nonetheless,
        ;; allocate some extra buffer for safety
        rcv-len (max 2048 (* 2 req-len))]

    ;; DatagramSocket()
    ;; Constructs a datagram socket and binds it to any available port
    ;; on the local host machine.
    (with-open [sock (DatagramSocket.)]
      (.setSoTimeout sock (int timeout-ms))

      (try (.setReceiveBufferSize sock rcv-len)
           (catch Exception _))

      ;; SEND (explicit destination on the packet; no need to .connect)
      ;; DatagramPacket(byte[] buf, int length, InetAddress address, int port)
      ;; Constructs a datagram packet for sending packets of length
      ;; length to the specified port number on the specified host.
      (let [send-pkt (DatagramPacket. req req-len
                                      (.getAddress addr) (.getPort addr))]
        (.send sock send-pkt))

      ;; RECV
      ;; DatagramPacket(byte[] buf, int length)
      ;; Constructs a DatagramPacket for receiving packets of length
      (let [buf-size rcv-len
            buf      (byte-array buf-size)
            recv     (DatagramPacket. buf buf-size)]
        (try
          (.receive sock recv)
          (let [n (.getLength recv)
                out (Arrays/copyOf buf n)
                from (InetSocketAddress. (.getAddress recv) (.getPort recv))]
            {:bytes out :from from})
          (catch SocketTimeoutException _ nil))))))

(defn send-udp
  "Send req-bytes to host:port over UDP with retries.
   opts:
     :timeout-ms   per-attempt receive timeout (default 1000)
     :retries      number of *additional* attempts after the first (default 2)
     :verify-src?  if true, drop packets not from the resolved IP:port (default true)
   Returns {:bytes .. :from ..} or throws on failure."
  [server-map ^bytes req-bytes
   {:keys [timeout-ms retries verify-src?]
    :or   {timeout-ms 1000, retries 2, verify-src? true}}]
  (let [^InetSocketAddress addr    (resolve-server server-map)
        ^InetAddress       want-ip (.getAddress addr)
        _want-port (.getPort addr)]
    (loop [attempt 0]
      (if (> attempt retries)
        (throw (ex-info "No UDP response received" {:server server-map
                                                    :attempts (inc retries)
                                                    :timeout-ms timeout-ms}))
        (if-let [{:keys [bytes from]} (send-udp-once addr req-bytes timeout-ms)]
          ;; drop results from unexpected source
          (if (and verify-src?
                   (or (not (.equals want-ip (.getAddress ^InetSocketAddress from)))
                       ;; NB cloudflare redirects to different port based on version
                       false ;; (not= want-port (.getPort from))
                       ))
            (recur (inc attempt))
            {:bytes bytes :from from})
          (recur (inc attempt)))))))
