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

(defun remove-trailing-dot (str)
  (if (eql (elt str (1- (length str))) #\.)
      (subseq str 0 (- (length str) 2))
      str))


#|
http://tools.ietf.org/html/rfc6125

   1.  The client SHOULD NOT attempt to match a presented identifier in
       which the wildcard character comprises a label other than the
       left-most label (e.g., do not match bar.*.example.net).

   2.  If the wildcard character is the only character of the left-most
       label in the presented identifier, the client SHOULD NOT compare
       against anything but the left-most label of the reference
       identifier (e.g., *.example.com would match foo.example.com but
       not bar.foo.example.com or example.com).

   3.  The client MAY match a presented identifier in which the wildcard
       character is not the only character of the label (e.g.,
       baz*.example.net and *baz.example.net and b*z.example.net would
       be taken to match baz1.example.net and foobaz.example.net and
       buzz.example.net, respectively).  However, the client SHOULD NOT
       attempt to match a presented identifier where the wildcard
       character is embedded within an A-label or U-label [IDNA-DEFS] of
       an internationalized domain name [IDNA-PROTO].
|#

(defun try-match-using-wildcards (hostname pattern)
  (let ((pattern-w-pos (position #\* pattern))
        (pattern-leftmost-label-end)
        (hostname-leftmost-label-end))
    (unless pattern-w-pos
      (return-from try-match-using-wildcards nil))

    ;; TODO: detect if hostname is IP address

    (setq pattern-leftmost-label-end (position #\. pattern))
    (when (or (null pattern-leftmost-label-end) (null (position #\. pattern :start (1+ pattern-leftmost-label-end)))
              (> pattern-w-pos pattern-leftmost-label-end)
              (string= pattern "xn--" :end1 4))
      (return-from try-match-using-wildcards nil))
    
    (setf hostname-leftmost-label-end (position #\. hostname))
    (when (or (null hostname-leftmost-label-end) (not (string= hostname pattern :start1 hostname-leftmost-label-end
                                                                                  :start2 pattern-leftmost-label-end)))
      
      (return-from try-match-using-wildcards nil))


    (when (< hostname-leftmost-label-end pattern-leftmost-label-end)
      (return-from try-match-using-wildcards nil))

    t))

(defun verify-hostname% (hostname pattern)
  (log:debug "~A against ~A" hostname pattern)
  (setf hostname (remove-trailing-dot hostname)
        pattern (remove-trailing-dot pattern))
  (if (string= hostname pattern)
      t
      (try-match-using-wildcards hostname pattern)))

(defun try-get-string-data (asn1-string)
  (cffi:with-foreign-slots ((length data) asn1-string (:struct asn1_string_st))
    (let* ((strlen (strlen data)))
      (when (= strlen length)
        (cffi:foreign-string-to-lisp data)))))

(defun try-match-alt-name (certificate hostname)
  (let ((altnames (x509-get-ext-d2i certificate 85 #|NID_subject_alt_name|# (cffi:null-pointer) (cffi:null-pointer)))
        (matched nil))
    (if (not (cffi:null-pointer-p altnames))
        (prog1
            (let ((altnames-count (sk-general-name-num altnames)))
              (do ((i 0 (1+ i)))
                  ((or matched (>= i  altnames-count)) matched)
                (let* ((name (sk-general-name-value altnames i))
                       (dns-name))
                  (cffi:with-foreign-slots ((type data) name (:struct general_name))
                    (when (= type 2 #|GEN_DNS|#)
                      (setq dns-name (try-get-string-data data))
                      (when dns-name
                        (setq matched (verify-hostname% hostname dns-name))))))))
          ;; turns out sk_GENERAL_NAME_pop_free is layered #define mess, don't know what to do now
          ;;(sk_GENERAL_NAME_pop_free altnames 1216 #|GENERAL_NAME_free|#) 
          ))))

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