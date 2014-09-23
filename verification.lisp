(in-package :cl+ssl)

(defconstant +X509-CHECK-FLAG-ALWAYS-CHECK-SUBJECT+ #x01
  "The X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT flag causes the function to consider the subject
DN even if the certificate contains at least one subject alternative name of the right type
(DNS name or email address as appropriate); the default is to ignore the subject DN when at
least one corresponding subject alternative names is present.")
(defconstant +X509-CHECK-FLAG-NO-WILDCARDS+ #x02
  "Disable wildcard matching for dnsName fields and common name. Check_host only")
(defconstant +X509-CHECK-FLAG-NO-PARTIAL-WILDCARDS+ #x04
  "Suppresses support for \"*\" as wildcard pattern in labels that have a prefix or suffix,
such as: \"www*\" or \"*www\". Check_host only")
(defconstant +X509-CHECK-FLAG-MULTI-LABEL-WILDCARDS+ #x08
  "Allows a \"*\" that constitutes the complete label of a DNS name (e.g. \"*.example.com\")
to match more than one label in name. Check_host only")
(defconstant +X509-CHECK-FLAG-SINGLE-LABEL-SUBDOMAINS+ #x10
  "Restricts name values which start with \".\", that would otherwise match any sub-domain
in the peer certificate, to only match direct child sub-domains. Thus, for instance, with
this flag set a name of \".example.com\" would match a peer certificate with a DNS name of
\"www.example.com\", but would not match a peer certificate with a DNS name of \"www.sub.example.com\".
Check_host only")

;; waiting for 1.0.2
(defun add-host-verification (ctx host-name flags)
  (let ((x509-vp))
    (unwind-protect
         (progn
           (setq x509-vp (X509-VERIFY-PARAM-new))
           (cffi:with-foreign-string (name host-name)
             (X509-Verify-param-set1-host x509-vp name 0)
             (X509-verify-param-set-hostflags x509-vp flags)
             (ssl-ctx-set1-param ctx x509-vp)))
      (if x509-vp
          (X509-VERIFY-PARAM-free x509-vp)))))

(cffi:defcallback cb-ssl-verify-host-and-expiration :int ((ok :int) (ctx :pointer))
  (let* (;; (certificate (X509-STORE-CTX-get-current-cert ctx))
        (error-code (print (X509_STORE_CTX-get-error ctx))))
    ok))

(cffi:defcfun ("sk_value" sk-value)
    :pointer
  (stack :pointer)
  (index :int))

(cffi:defcfun ("sk_num" sk-num)
    :int
  (stack :pointer))

(cffi:defcfun ("X509_NAME_get_index_by_NID" x509-name-get-index-by-nid)
    :int
  (name :pointer)
  (nid :int)
  (lastpost :int))

(cffi:defcfun ("X509_NAME_get_entry" x509-name-get-entry)
    :pointer
  (name :pointer)
  (log :int))

(cffi:defcfun ("X509_NAME_ENTRY_get_data" x509-name-entry-get-data)
    :pointer
  (name-entry :pointer))

(cffi:defcfun ("ASN1_STRING_data" asn1-string-data)
    :pointer
  (asn1-string :pointer))

(cffi:defcfun ("ASN1_STRING_length" asn1-string-length)
    :int
  (asn1-string :string))

(cffi:defcfun ("strlen" strlen)
    :int
  (string :string))

(defun sk-general-name-value (names index)
  (sk-value names index))

(defun sk-general-name-num (names)
  (sk-num names))

(cffi:defcstruct asn1_string_st
  (length :int)
  (type :int)
  (data :pointer)
  (flags :long))

(cffi:defcstruct GENERAL_NAME
  (type :int)
  (data :pointer))

(defun verify-hostname% (hostname dns-name)
  (log:info "~A against ~A" hostname dns-name)
  (string= hostname dns-name))

(defun try-get-string-data (asn1-string)
  (cffi:with-foreign-slots ((length data) asn1-string (:struct asn1_string_st))
    (let* ((strlen (strlen data)))
      (when (= strlen length)
        (cffi:foreign-string-to-lisp data)))))

(defun try-match-alt-name (certificate hostname)
  (let ((altnames (x509-get-ext-d2i certificate 85 #|NID_subject_alt_name|# (cffi:null-pointer) (cffi:null-pointer)))
        (matched nil))
    (when (not (cffi:null-pointer-p altnames))
      (let ((altnames-count (sk-general-name-num altnames)))
        (do ((i 0 (1+ i)))
            ((or matched (>= i  altnames-count)))
          (let* ((name (sk-general-name-value altnames i))
                 (dns-name))
            (cffi:with-foreign-slots ((type data) name (:struct general_name))
              (when (= type 2 #|GEN_DNS|#)
                (setq dns-name (try-get-string-data data))
                (when dns-name
                  (setq matched (verify-hostname% hostname dns-name)))))))))
    matched))

(defun get-common-name-index (certificate)
  (x509-name-get-index-by-nid (x509-get-subject-name certificate) 13 #|NID_commonName|# -1))

(defun get-common-name-entry (certificate index)
  (x509-name-get-entry (x509-get-subject-name certificate) index))

(defun try-match-common-name (certificate hostname)
  (log:info "try-match-common-name")
  (let (common-name-index
        common-name-entry
        common-name-asn1
        dns-name)
    (setf common-name-index (get-common-name-index certificate))
    (unless common-name-index
      (return-from try-match-common-name nil))
    (setf common-name-entry (get-common-name-entry certificate common-name-index))
    (unless common-name-entry
      (return-from try-match-common-name nil))
    (setf common-name-asn1 (x509-name-entry-get-data common-name-entry))
    (unless common-name-asn1
      (return-from try-match-common-name nil))
    (setq dns-name (try-get-string-data common-name-asn1))
    (unless dns-name
      (return-from try-match-common-name nil))
    (verify-hostname% hostname dns-name)))


;; from curl
(defun verify-hostname (ssl hostname)
  (let ((certificate (ssl-get-peer-certificate ssl)))
    (or (try-match-alt-name certificate hostname)
        (try-match-common-name certificate hostname))))
