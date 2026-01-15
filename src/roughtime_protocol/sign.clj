(ns roughtime-protocol.sign
  (:require
   [taoensso.encore :as enc]
   [roughtime-protocol.util :as util])
  (:import
   (java.security KeyPair KeyPairGenerator PrivateKey PublicKey
                  KeyFactory Signature SecureRandom Security)
   (java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec)

   (org.bouncycastle.jce.provider BouncyCastleProvider)
   (org.bouncycastle.crypto.util PrivateKeyFactory PublicKeyFactory)
   (org.bouncycastle.crypto.util PrivateKeyInfoFactory SubjectPublicKeyInfoFactory)
   (org.bouncycastle.crypto.params Ed25519PrivateKeyParameters Ed25519PublicKeyParameters)))

(set! *warn-on-reflection* true)

;;; Provider Registration

;; Register Bouncy Castle globally.
(when-not (Security/getProvider "BC")
  (Security/addProvider (BouncyCastleProvider.)))

;;; Signature (Ed25519)

(def ^:private ^:thread-local ^Signature sig-Ed25519
  "Signature objects are stateful; managed as thread-locals for safety."
  (enc/thread-local (Signature/getInstance "Ed25519" "BC")))

(def ^:private ^:thread-local ^SecureRandom secure-rng
  "SecureRandom objects are stateful and not thread-save; use enc/thread-local"
  (enc/thread-local (SecureRandom.)))

(defn gen-ed25519-kp
  "Generates a new Ed25519 KeyPair using the shared secure RNG."
  ^KeyPair []
  (let [kpg (KeyPairGenerator/getInstance "Ed25519" "BC")]
    ;; Reusing the thread-local SecureRandom from util
    (.initialize kpg 255 ^SecureRandom @secure-rng)
    (.generateKeyPair kpg)))

(defn sign
  "Create a 64-byte Ed25519 signature."
  ^bytes [^bytes ba-content ^PrivateKey signer-key-prv]
  (let [sig ^Signature @sig-Ed25519]
    (.initSign sig signer-key-prv)
    (.update sig ba-content)
    (.sign sig)))

(defn verify
  "Verifies an Ed25519 signature."
  [^bytes ba-content ^PublicKey signer-key-pub ^bytes ba-signature]
  (let [sig ^Signature @sig-Ed25519]
    (.initVerify sig signer-key-pub)
    (.update sig ba-content)
    (.verify sig ba-signature)))

;;; Raw32 / Seed32 formats

(defn raw-pub32->public-key
  "Auditable reconstruction using BC SubjectPublicKeyInfoFactory."
  ^PublicKey [^bytes raw32]
  (when (not= 32 (alength raw32))
    (throw (IllegalArgumentException. "Ed25519 public keys must be 32 bytes")))
  (let [params (Ed25519PublicKeyParameters. raw32 0)
        ;; Generates the standard DER-encoded SPKI structure
        spki-info (SubjectPublicKeyInfoFactory/createSubjectPublicKeyInfo params)
        kf (KeyFactory/getInstance "Ed25519" "BC")]
    (.generatePublic kf (X509EncodedKeySpec. (.getEncoded spki-info)))))

(defn public-key->raw-pub32
  "Extracts the raw 32-byte public key using Bouncy Castle utilities."
  ^bytes [^PublicKey pub]
  ;; This returns the raw 32-byte public key
  (.getEncoded ^Ed25519PublicKeyParameters (PublicKeyFactory/createKey (.getEncoded pub))))

(defn raw-seed32->private-key
  "Auditable reconstruction using BC PrivateKeyInfoFactory."
  ^PrivateKey [^bytes seed32]
  (when (not= 32 (alength seed32))
    (throw (IllegalArgumentException. "Ed25519 seeds must be 32 bytes")))
  (let [params (Ed25519PrivateKeyParameters. seed32 0)
        ;; Generates the standard DER-encoded PKCS#8 structure
        pk-info (PrivateKeyInfoFactory/createPrivateKeyInfo params)
        kf (KeyFactory/getInstance "Ed25519" "BC")]
    (.generatePrivate kf (PKCS8EncodedKeySpec. (.getEncoded pk-info)))))

(defn private-key->raw-seed32
  "Extracts the raw 32-byte seed from a PrivateKey using Bouncy Castle utilities."
  ^bytes [^PrivateKey prv]
  ;; This returns the raw 32-byte seed (not the expanded 64-byte private key)
  (.getEncoded ^Ed25519PrivateKeyParameters (PrivateKeyFactory/createKey (.getEncoded prv))))

;;; Private Key persistence (PKCS#8) format

(defn private-key->pkcs8
  "Returns the given Ed25519 PrivateKey encoded in PKCS#8 format.
   Standard JCA Ed25519 keys use PKCS#8 for their default encoding."
  ^bytes [^PrivateKey sk]
  (.getEncoded sk))

(defn pkcs8->private-key
  "Reconstructs an Ed25519 PrivateKey from a PKCS#8 byte array."
  ^PrivateKey [^bytes pkcs8-bytes]
  (let [kf (KeyFactory/getInstance "Ed25519" "BC")
        spec (PKCS8EncodedKeySpec. pkcs8-bytes)]
    (.generatePrivate kf spec)))

;;; Public Key persistence (X.509 / SPKI) format

(defn public-key->spki
  "Returns the given Ed25519 PublicKey encoded in X.509 / SubjectPublicKeyInfo format."
  ^bytes [^PublicKey pk]
  (.getEncoded pk))

(defn spki->public-key
  "Reconstructs an Ed25519 PublicKey from an SPKI byte array."
  ^PublicKey [^bytes spki-bytes]
  (let [kf (KeyFactory/getInstance "Ed25519" "BC")
        spec (X509EncodedKeySpec. spki-bytes)]
    (.generatePublic kf spec)))

;;; Helpers

(defn sign-with-context
  "Streams context and data into the signature object to avoid intermediate allocation."
  ^bytes [^bytes ctx ^bytes data ^PrivateKey prv]
  (let [sig ^Signature @sig-Ed25519]
    (.initSign sig prv)
    (.update sig ctx)
    (.update sig data)
    (.sign sig)))

(defn verify-with-context
  "Streams context and data into the verification object."
  [^bytes ctx ^bytes data ^PublicKey pub ^bytes signature]
  (let [sig ^Signature @sig-Ed25519]
    (.initVerify sig pub)
    (.update sig ctx)
    (.update sig data)
    (.verify sig signature)))

(defn format-public-key
  [^PublicKey pub]
  (let [raw (-> pub public-key->raw-pub32)]
    {:hex (util/bytes->hex-string raw)
     :b64 (util/bytes->b64 raw)}))
